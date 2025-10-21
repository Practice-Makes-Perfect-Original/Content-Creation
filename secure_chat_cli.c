// Allow deprecated winsock names like inet_addr on some setups (we still use modern APIs too)
#define _WINSOCK_DEPRECATED_NO_WARNINGS

// -------- Windows networking & base OS headers (order matters: winsock2 before windows.h) --------
#include <winsock2.h>   // Core Winsock types & calls (SOCKET, send, recv, bind, listen, etc.)
#include <ws2tcpip.h>   // Newer socket helpers (htonl/ntohl prototypes, inet_pton, etc.)
#include <windows.h>    // Windows base APIs (threads, heap, etc.)

// -------- C runtime headers --------
#include <stdio.h>      // I/O (printf, wprintf, fgets, etc.)
#include <stdint.h>     // Fixed-width integer types
#include <stdlib.h>     // General utilities (malloc/free, atoi, etc.)
#include <string.h>     // Memory and string ops (memcpy, memcmp, strlen, etc.)
#include <wchar.h>      // Wide-char utilities (wprintf, fgetws, wcscmp, etc.)
#include <ctype.h>      // Character classification (iswdigit from <wctype.h> via ctype on Windows)

// -------- Windows Cryptography (CNG/NCrypt/Cert) --------
#include <bcrypt.h>     // CNG symmetric crypto, hashing, RNG, AES-GCM primitives
#include <ncrypt.h>     // Key Storage Provider (KSP): RSA public/private operations
#include <wincrypt.h>   // X.509 certificate context & Windows cert store APIs

// MSVC-only linker pragmas (GCC/MinGW simply ignore these; you link with -lws2_32 etc. on the command line)
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")

// ===========================
// ========== utility =========
// ===========================

// CHECK: compact error handling macro -> if expr fails, print a wide error message and jump to 'cleanup' label
#define CHECK(expr, msg) if(!(expr)){ fwprintf(stderr, L"%s\n", L##msg); goto cleanup; }

// NTOK/BOK: convenience predicates for Windows crypto status codes
// - NCrypt returns NTSTATUS-style (>=0 means success), BCrypt returns 0 on success.
#define NTOK(x)  ((x)>=0)
#define BOK(x)   ((x)==0)

// trim_nl: strip trailing newline or carriage return from a wide string (used for menu inputs)
static void trim_nl(wchar_t *s){ if(!s) return; size_t L=wcslen(s); if(L && (s[L-1]==L'\n' || s[L-1]==L'\r')) s[L-1]=0; }

// wide_to_utf8: convert user-entered IP (wide) to UTF-8 narrow char buffer for Winsock APIs
static void wide_to_utf8(const wchar_t *w, char *out, size_t outsz){
    WideCharToMultiByte(CP_UTF8,0,w,-1,out,(int)outsz,NULL,NULL);
}

// parse_int_or_default: read an integer from a wide string if present; otherwise return provided default
static int parse_int_or_default(const wchar_t *w, int defv){
    if(!w || !*w) return defv;
    int any = 0; for(const wchar_t *p=w; *p; ++p){ if(iswdigit(*p)){ any=1; break; } } // detect any digit
    if(!any) return defv;
    return _wtoi(w); // Windows wide-char to int
}

// ===========================
// ======= framing layer ======
// ===========================
// We define a simple, explicit on-the-wire framing so the receiver can parse messages off the TCP stream.
//
// Frames (ASCII 4-byte magic + big-endian sizes):
//   CERT: "CERT" [u32 len] [DER certificate bytes]
//   EKY!: "EKY!" [u32 len] [RSA-OAEP ciphertext of 44-byte payload: 32-byte AES key + 12-byte nonceBase]
//   DAT!: "DAT!" [u32 counter] [u32 ctLen] [ciphertext] [u32 tagLen] [auth tag]
//
// The counter is used to derive a unique GCM nonce per message (nonceBase || counter).

static const char F_CERT[4] = {'C','E','R','T'};   // Server → Client: sends certificate (DER)
static const char F_EKY[4]  = {'E','K','Y','!'};   // Client → Server: sends RSA-wrapped session material
static const char F_DAT[4]  = {'D','A','T','!'};   // Either direction: encrypted chat payload

// send_all: robustly send 'len' bytes even if send() writes only partially; returns FALSE on error/close
static BOOL send_all(SOCKET s, const void *buf, int len) {
    const char *p = (const char*)buf; int n = 0;
    while (n < len) {
        int w = send(s, p + n, len - n, 0);
        if (w <= 0) return FALSE;  // 0 or negative indicates socket error or closed
        n += w;
    }
    return TRUE;
}

// recv_all: robustly receive 'len' bytes; blocks until all arrive or connection drops; FALSE on failure
static BOOL recv_all(SOCKET s, void *buf, int len) {
    char *p = (char*)buf; int n = 0;
    while (n < len) {
        int r = recv(s, p + n, len - n, 0);
        if (r <= 0) return FALSE;  // peer closed or error
        n += r;
    }
    return TRUE;
}

// =====================================
// == hashing: SHA-256 cert thumbprint ==
// =====================================
// We compute the SHA-256 digest of the server certificate (DER) for TOFU display.
static BOOL sha256(const BYTE *data, DWORD len, BYTE out[32]) {
    BCRYPT_ALG_HANDLE hAlg = NULL;     // algorithm provider handle
    BCRYPT_HASH_HANDLE hHash = NULL;   // hash object handle
    DWORD hashLen=0, objLen=0; PBYTE obj = NULL; // buffer for hash object as required by CNG

    // Open SHA-256 provider
    if (!BOK(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) goto cleanup;
    // Query hash object buffer size
    if (!BOK(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&objLen, sizeof(objLen), &hashLen, 0))) goto cleanup;
    obj = (PBYTE)HeapAlloc(GetProcessHeap(), 0, objLen); // allocate hash object
    if (!obj) goto cleanup;
    // Create a hash object bound to the provider and our object buffer
    if (!BOK(BCryptCreateHash(hAlg, &hHash, obj, objLen, NULL, 0, 0))) goto cleanup;
    // Hash the input bytes
    if (!BOK(BCryptHashData(hHash, (PUCHAR)data, len, 0))) goto cleanup;
    // Finalize and write 32-byte digest to 'out'
    if (!BOK(BCryptFinishHash(hHash, out, 32, 0))) goto cleanup;

    // tidy up on success
    HeapFree(GetProcessHeap(), 0, obj); BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg,0);
    return TRUE;

cleanup:
    // tidy up on failure
    if (obj) HeapFree(GetProcessHeap(), 0, obj);
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return FALSE;
}

// Pretty print 32-byte thumbprint as hex pairs separated by colons
static void print_thumbprint(const BYTE t[32]) {
    wprintf(L"\nServer cert SHA-256: ");
    for (int i=0;i<32;i++) wprintf(L"%02X%s", t[i], i==31?L"\n":L":");
}

// ==================================
// == AES-256-GCM symmetric wrapper ==
// ==================================
// Holds AES algorithm handle, key, 12-byte IV base (nonce base), and housekeeping buffers.
typedef struct {
    BCRYPT_ALG_HANDLE hAlg;  // AES provider handle
    BCRYPT_KEY_HANDLE hKey;  // derived AES key handle
    BYTE ivBase[12];         // 96-bit nonce base; last 4 bytes will be replaced with counter per message
    DWORD tagLen;            // GCM auth tag length (16 bytes = 128-bit tag)
    DWORD cbKeyObj;          // size of the CNG key object buffer
    PUCHAR keyObj;           // allocated key object buffer
} AESGCM_CTX;

// aesgcm_init: open AES provider, set GCM mode, generate a symmetric key from raw 32-byte key, store nonce base
static BOOL aesgcm_init(AESGCM_CTX *ctx, const BYTE key[32], const BYTE nonceBase12[12]) {
    ZeroMemory(ctx, sizeof(*ctx));
    if (!BOK(BCryptOpenAlgorithmProvider(&ctx->hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) return FALSE;
    // Switch chaining mode to GCM (authenticated encryption)
    if (!BOK(BCryptSetProperty(ctx->hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, (ULONG)wcslen(BCRYPT_CHAIN_MODE_GCM)*sizeof(WCHAR), 0))) return FALSE;
    DWORD cb=0;
    // Query how big the key object buffer must be and allocate it
    if (!BOK(BCryptGetProperty(ctx->hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&ctx->cbKeyObj, sizeof(ctx->cbKeyObj), &cb, 0))) return FALSE;
    ctx->keyObj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, ctx->cbKeyObj);
    if (!ctx->keyObj) return FALSE;
    // Generate a CNG key handle from raw 32-byte key material
    if (!BOK(BCryptGenerateSymmetricKey(ctx->hAlg, &ctx->hKey, ctx->keyObj, ctx->cbKeyObj, (PUCHAR)key, 32, 0))) return FALSE;

    ctx->tagLen = 16; // standard 128-bit auth tag for GCM
    memcpy(ctx->ivBase, nonceBase12, 12); // copy base nonce (first 8 random bytes + last 4 reserved for counter)
    return TRUE;
}

// aesgcm_free: release all CNG resources associated with this context
static void aesgcm_free(AESGCM_CTX *ctx) {
    if (ctx->hKey) BCryptDestroyKey(ctx->hKey);
    if (ctx->keyObj) HeapFree(GetProcessHeap(), 0, ctx->keyObj);
    if (ctx->hAlg) BCryptCloseAlgorithmProvider(ctx->hAlg, 0);
    ZeroMemory(ctx, sizeof(*ctx));
}

// make_iv: derive per-message 12-byte nonce by copying base and writing the 32-bit counter into the last 4 bytes
static void make_iv(const BYTE base[12], uint32_t counter, BYTE iv[12]) {
    memcpy(iv, base, 12);
    iv[8]  = (BYTE)(counter & 0xFF);
    iv[9]  = (BYTE)((counter>>8) & 0xFF);
    iv[10] = (BYTE)((counter>>16)& 0xFF);
    iv[11] = (BYTE)((counter>>24)& 0xFF);
}

// aesgcm_encrypt: AEAD-encrypt plaintext with IV(counter) and output ciphertext + tag
static BOOL aesgcm_encrypt(AESGCM_CTX *ctx, uint32_t counter, const BYTE *pt, DWORD cbPt,
                           BYTE **outCt, DWORD *cbCt, BYTE **outTag, DWORD *cbTag)
{
    *outCt=NULL; *cbCt=0; *outTag=NULL; *cbTag=0;
    BYTE iv[12]; make_iv(ctx->ivBase, counter, iv); // derive unique nonce per message
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ainfo; BCRYPT_INIT_AUTH_MODE_INFO(ainfo);
    ainfo.pbNonce = (PUCHAR)iv; ainfo.cbNonce = 12;
    ainfo.pbTag = NULL; ainfo.cbTag = ctx->tagLen; // request tag allocation

    DWORD cbOut=0;
    // First call to get ciphertext size
    if (!BOK(BCryptEncrypt(ctx->hKey, (PUCHAR)pt, cbPt, &ainfo, NULL, 0, NULL, 0, &cbOut, 0))) return FALSE;
    BYTE *ct = (BYTE*)HeapAlloc(GetProcessHeap(), 0, cbOut);
    if (!ct) return FALSE;
    BYTE *tag = (BYTE*)HeapAlloc(GetProcessHeap(), 0, ctx->tagLen);
    if (!tag){ HeapFree(GetProcessHeap(),0,ct); return FALSE; }
    ainfo.pbTag = tag; // second call will write the authentication tag here

    // Second call performs the encryption and fills ct + tag
    if (!BOK(BCryptEncrypt(ctx->hKey, (PUCHAR)pt, cbPt, &ainfo, NULL, 0, ct, cbOut, &cbOut, 0))) {
        HeapFree(GetProcessHeap(),0,ct); HeapFree(GetProcessHeap(),0,tag); return FALSE;
    }
    *outCt=ct; *cbCt=cbOut; *outTag=tag; *cbTag=ctx->tagLen;
    return TRUE;
}

// aesgcm_decrypt: AEAD-decrypt ciphertext with IV(counter); tag must match or decryption fails
static BOOL aesgcm_decrypt(AESGCM_CTX *ctx, uint32_t counter, const BYTE *ct, DWORD cbCt,
                           const BYTE *tag, DWORD cbTag, BYTE **outPt, DWORD *cbPt)
{
    *outPt=NULL; *cbPt=0;
    if (cbTag != ctx->tagLen) return FALSE; // enforce expected tag length
    BYTE iv[12]; make_iv(ctx->ivBase, counter, iv);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ainfo; BCRYPT_INIT_AUTH_MODE_INFO(ainfo);
    ainfo.pbNonce=(PUCHAR)iv; ainfo.cbNonce=12; ainfo.pbTag=(PUCHAR)tag; ainfo.cbTag=cbTag;

    DWORD cbOut=0;
    // Query plaintext size first
    if (!BOK(BCryptDecrypt(ctx->hKey, (PUCHAR)ct, cbCt, &ainfo, NULL, 0, NULL, 0, &cbOut, 0))) return FALSE;
    BYTE *pt=(BYTE*)HeapAlloc(GetProcessHeap(),0,cbOut);
    if (!pt) return FALSE;
    // Actual decrypt; fails if tag invalid (integrity/authentication failure)
    if (!BOK(BCryptDecrypt(ctx->hKey, (PUCHAR)ct, cbCt, &ainfo, NULL, 0, pt, cbOut, &cbOut, 0))) {
        HeapFree(GetProcessHeap(),0,pt); return FALSE;
    }
    *outPt=pt; *cbPt=cbOut; return TRUE;
}

// ===============================================
// == RSA key & self-signed certificate (server) ==
// ===============================================
// ensure_self_signed_cert:
//   - Opens CurrentUser\MY store
//   - Searches for CN=SecureChat Demo
//   - If found, returns its PCCERT_CONTEXT and the bound NCrypt private key handle
//   - If missing, creates a persisted RSA-2048 key, self-signs a cert, stores it, and returns them
static BOOL ensure_self_signed_cert(NCRYPT_KEY_HANDLE *phKey, PCCERT_CONTEXT *ppCert) {
    *phKey=0; *ppCert=NULL; // initialize outputs
    HCERTSTORE hMy = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
    if (!hMy) return FALSE;

    // Build the X.500 subject name "CN=SecureChat Demo"
    CERT_NAME_BLOB subject = {0};
    DWORD cbName=0;
    CertStrToNameW(X509_ASN_ENCODING, L"CN=SecureChat Demo", CERT_X500_NAME_STR, NULL, NULL, &cbName, NULL);
    BYTE *name = (BYTE*)LocalAlloc(0, cbName);
    if(!name){ CertCloseStore(hMy,0); return FALSE; }
    CertStrToNameW(X509_ASN_ENCODING, L"CN=SecureChat Demo", CERT_X500_NAME_STR, NULL, name, &cbName, NULL);
    subject.pbData = name; subject.cbData = cbName;

    // Try to find existing cert in the store with that subject
    PCCERT_CONTEXT p = CertFindCertificateInStore(hMy, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_NAME, &subject, NULL);
    if (p) {
        // If it has a linked NCrypt private key, return both
        NCRYPT_KEY_HANDLE hKey=0; DWORD cb=sizeof(hKey);
        if (CertGetCertificateContextProperty(p, CERT_NCRYPT_KEY_HANDLE_PROP_ID, &hKey, &cb)) {
            *ppCert = p; *phKey = hKey; LocalFree(name); CertCloseStore(hMy,0); return TRUE;
        }
        // Otherwise, free and proceed to create a new one
        CertFreeCertificateContext(p);
    }

    // Create a new RSA-2048 key in the Microsoft Key Storage Provider (persisted with name "SecureChatKey")
    NCRYPT_PROV_HANDLE hProv=0; NCRYPT_KEY_HANDLE hKey=0;
    if (!NTOK(NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0))) { LocalFree(name); CertCloseStore(hMy,0); return FALSE; }
    if (!NTOK(NCryptCreatePersistedKey(hProv, &hKey, NCRYPT_RSA_ALGORITHM, L"SecureChatKey", 0, NCRYPT_OVERWRITE_KEY_FLAG))) goto fail;
    DWORD bits=2048;
    if (!NTOK(NCryptSetProperty(hKey, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, sizeof(bits), 0))) goto fail;
    if (!NTOK(NCryptFinalizeKey(hKey, 0))) goto fail;

    // Describe how the cert links to the key/container
    CRYPT_KEY_PROV_INFO kpi = {0};
    kpi.pwszContainerName = L"SecureChatKey";
    kpi.pwszProvName = MS_KEY_STORAGE_PROVIDER;

    // Self-sign a certificate with that key (no extended extensions here; minimal demo)
    CERT_EXTENSIONS exts = {0};
    PCCERT_CONTEXT cert = CertCreateSelfSignCertificate((HCRYPTPROV_OR_NCRYPT_KEY_HANDLE)hKey, &subject, 0, &kpi, NULL, NULL, NULL, &exts);
    if (!cert) goto fail;

    // Add/replace into CurrentUser\MY store
    CertAddCertificateContextToStore(hMy, cert, CERT_STORE_ADD_REPLACE_EXISTING, &cert);
    *phKey = hKey; *ppCert = cert;  // return key+cert to caller
    LocalFree(name); CertCloseStore(hMy,0); NCryptFreeObject(hProv);
    return TRUE;

fail:
    // Cleanup on failure
    if (hKey) NCryptFreeObject(hKey);
    if (hProv) NCryptFreeObject(hProv);
    LocalFree(name); CertCloseStore(hMy,0);
    return FALSE;
}

// cert_to_der: copy the encoded DER blob from the certificate context into a heap buffer for sending
static BOOL cert_to_der(PCCERT_CONTEXT cert, BYTE **pp, DWORD *pcb) {
    *pp=NULL; *pcb=0;
    BYTE *p=(BYTE*)HeapAlloc(GetProcessHeap(),0,cert->cbCertEncoded);
    if(!p) return FALSE;
    memcpy(p, cert->pbCertEncoded, cert->cbCertEncoded);
    *pp=p; *pcb=cert->cbCertEncoded; return TRUE;
}

// cert_to_ncrypt_pubkey: turn the cert’s SubjectPublicKeyInfo into an NCrypt public key handle for NCryptEncrypt
static BOOL cert_to_ncrypt_pubkey(PCCERT_CONTEXT cert, NCRYPT_KEY_HANDLE *phKey) {
    *phKey = 0; BCRYPT_KEY_HANDLE hPubB=0; NCRYPT_PROV_HANDLE hProv=0; NCRYPT_KEY_HANDLE hKey=0;
    // Import SPKI to a BCrypt (CNG) public key first
    if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, &cert->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &hPubB)) return FALSE;
    // Export to a BCRYPT_RSAPUBLIC_BLOB
    DWORD cb=0; BCryptExportKey(hPubB, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &cb, 0);
    PUCHAR blob = (PUCHAR)HeapAlloc(GetProcessHeap(),0,cb);
    if (!blob){ BCryptDestroyKey(hPubB); return FALSE; }
    if (!BOK(BCryptExportKey(hPubB, 0, BCRYPT_RSAPUBLIC_BLOB, blob, cb, &cb, 0))) { HeapFree(GetProcessHeap(),0,blob); BCryptDestroyKey(hPubB); return FALSE; }

    // Import that blob into NCrypt provider so we can use NCryptEncrypt (RSA-OAEP)
    if (!NTOK(NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0))) { HeapFree(GetProcessHeap(),0,blob); BCryptDestroyKey(hPubB); return FALSE; }
    if (!NTOK(NCryptImportKey(hProv, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, &hKey, blob, cb, 0))) { NCryptFreeObject(hProv); HeapFree(GetProcessHeap(),0,blob); BCryptDestroyKey(hPubB); return FALSE; }

    HeapFree(GetProcessHeap(),0,blob); BCryptDestroyKey(hPubB); NCryptFreeObject(hProv);
    *phKey = hKey; return TRUE;
}

// ========================================
// == RSA-OAEP(SHA-256) encrypt / decrypt ==
// ========================================
// rsa_oaep_encrypt: wrap arbitrary bytes (44-byte key+nonce in our handshake) using server's RSA public key
static BOOL rsa_oaep_encrypt(NCRYPT_KEY_HANDLE hPub, const BYTE *in, DWORD cbIn, BYTE **out, DWORD *cbOut) {
    *out=NULL; *cbOut=0;
    DWORD cb=0;
    // Set up OAEP with SHA-256 (more modern than SHA-1)
    BCRYPT_OAEP_PADDING_INFO pi; ZeroMemory(&pi,sizeof(pi)); pi.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    // First size query
    SECURITY_STATUS ss = NCryptEncrypt(hPub,(PBYTE)in,cbIn,NULL,NULL,0,&cb,NCRYPT_PAD_OAEP_FLAG);
    if (!NTOK(ss)) return FALSE;
    BYTE *buf = (BYTE*)HeapAlloc(GetProcessHeap(),0,cb); if(!buf) return FALSE;
    // Real encryption into allocated buffer
    ss = NCryptEncrypt(hPub,(PBYTE)in,cbIn,&pi,buf,cb,&cb,NCRYPT_PAD_OAEP_FLAG);
    if (!NTOK(ss)) { HeapFree(GetProcessHeap(),0,buf); return FALSE; }
    *out=buf; *cbOut=cb; return TRUE;
}

// rsa_oaep_decrypt: unwrap data using the server's private key (obtained from cert store)
static BOOL rsa_oaep_decrypt(NCRYPT_KEY_HANDLE hPriv, const BYTE *in, DWORD cbIn, BYTE **out, DWORD *cbOut) {
    *out=NULL; *cbOut=0;
    DWORD cb=0;
    BCRYPT_OAEP_PADDING_INFO pi; ZeroMemory(&pi,sizeof(pi)); pi.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    // Size query
    SECURITY_STATUS ss = NCryptDecrypt(hPriv,(PBYTE)in,cbIn,&pi,NULL,0,&cb,NCRYPT_PAD_OAEP_FLAG);
    if (!NTOK(ss)) return FALSE;
    BYTE *buf=(BYTE*)HeapAlloc(GetProcessHeap(),0,cb); if(!buf) return FALSE;
    // Real decrypt
    ss = NCryptDecrypt(hPriv,(PBYTE)in,cbIn,&pi,buf,cb,&cb,NCRYPT_PAD_OAEP_FLAG);
    if (!NTOK(ss)) { HeapFree(GetProcessHeap(),0,buf); return FALSE; }
    *out=buf; *cbOut=cb; return TRUE;
}

// ===============================
// == handshake (server side)  ==
// ===============================
// Sequence:
//  1) Ensure we have a self-signed cert + private key
//  2) Send CERT frame with DER
//  3) Receive EKY! frame, RSA-decrypt it → {AES-256 key | 12B nonce base}
//  4) Initialize AES-GCM context with that material
static BOOL server_handshake(SOCKET s, AESGCM_CTX *outCtx) {
    BOOL ok=FALSE;
    NCRYPT_KEY_HANDLE hKey=0; PCCERT_CONTEXT cert=NULL;
    BYTE *der=NULL; DWORD cbDer=0;

    CHECK(ensure_self_signed_cert(&hKey,&cert), "Server: failed to ensure self-signed cert");
    CHECK(cert_to_der(cert,&der,&cbDer), "Server: cert der export failed");

    // Send CERT frame (magic + len + bytes)
    CHECK(send_all(s, F_CERT, 4), "send CERT magic failed");
    uint32_t n = htonl(cbDer);
    CHECK(send_all(s, &n, 4), "send CERT len failed");
    CHECK(send_all(s, der, cbDer), "send CERT der failed");

    // Expect EKY! next
    char magic[4];
    CHECK(recv_all(s, magic, 4), "recv EKY magic failed");
    CHECK(memcmp(magic, F_EKY, 4)==0, "expected EKY!");

    // Read RSA ciphertext length + body
    uint32_t ekLenN=0; CHECK(recv_all(s, &ekLenN, 4), "recv EKY len failed");
    uint32_t ekLen = ntohl(ekLenN);
    BYTE *ekBuf=(BYTE*)HeapAlloc(GetProcessHeap(),0,ekLen); CHECK(ekBuf,"oom ek");
    CHECK(recv_all(s, ekBuf, ekLen), "recv EKY body failed");

    // RSA-OAEP decrypt → should be exactly 44 bytes (32 key + 12 nonce base)
    BYTE *plain=NULL; DWORD cbPlain=0;
    CHECK(rsa_oaep_decrypt(hKey, ekBuf, ekLen, &plain, &cbPlain), "RSA decrypt failed");
    CHECK(cbPlain==44, "handshake payload must be 44 bytes (32 key + 12 ivBase)");

    // Initialize AES-GCM with key and IV base
    CHECK(aesgcm_init(outCtx, plain, plain+32), "AES-GCM init failed");
    ok=TRUE;

cleanup:
    // Free any temporaries and handles; caller uses outCtx if ok==TRUE
    if (der) HeapFree(GetProcessHeap(),0,der);
    if (cert) CertFreeCertificateContext(cert);
    if (hKey) NCryptFreeObject(hKey);
    return ok;
}

// ===============================
// == handshake (client side)  ==
// ===============================
// Sequence:
//  1) Receive CERT frame; parse DER to PCCERT_CONTEXT
//  2) Compute SHA-256 thumbprint; ask user to type 'trust' (TOFU)
//  3) Extract public key as NCrypt handle
//  4) Generate random AES key + 12B nonce base; RSA-OAEP encrypt; send EKY!
//  5) Initialize AES-GCM with same key/nonce base
static BOOL client_handshake(SOCKET s, AESGCM_CTX *outCtx) {
    BOOL ok=FALSE;
    // Receive CERT magic
    char magic[4];
    CHECK(recv_all(s, magic, 4), "recv CERT magic failed");
    CHECK(memcmp(magic, F_CERT, 4)==0, "expected CERT");

    // Read DER length + body
    uint32_t derLenN=0; CHECK(recv_all(s, &derLenN, 4), "recv CERT len failed");
    uint32_t derLen = ntohl(derLenN);
    BYTE *der=(BYTE*)HeapAlloc(GetProcessHeap(),0,derLen); CHECK(der,"oom der");
    CHECK(recv_all(s, der, derLen), "recv CERT body failed");

    // Parse the certificate
    PCCERT_CONTEXT cert = CertCreateCertificateContext(X509_ASN_ENCODING, der, derLen);
    CHECK(cert, "Cert parse failed");

    // Show thumbprint and ask user to trust this key (Trust On First Use)
    BYTE fp[32]; CHECK(sha256(cert->pbCertEncoded, cert->cbCertEncoded, fp), "SHA256 fail");
    print_thumbprint(fp);
    wprintf(L"Type 'trust' to accept this server key (TOFU): ");
    wchar_t buf[64]={0}; if (!fgetws(buf, 64, stdin)) goto cleanup;
    trim_nl(buf);
    if (wcsncmp(buf, L"trust", 5) != 0) { fwprintf(stderr, L"Aborted by user.\n"); goto cleanup; }

    // Extract RSA public key for NCryptEncrypt
    NCRYPT_KEY_HANDLE hPub=0; CHECK(cert_to_ncrypt_pubkey(cert, &hPub), "pubkey import fail");

    // Generate session secrets: 32-byte AES key + 12-byte IV base (system RNG)
    BYTE key[32], ivBase[12];
    if (!BOK(BCryptGenRandom(NULL, key, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) goto cleanup;
    if (!BOK(BCryptGenRandom(NULL, ivBase, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG))) goto cleanup;

    // Build 44-byte payload and RSA-OAEP encrypt with server pubkey
    BYTE payload[44]; memcpy(payload, key,32); memcpy(payload+32, ivBase,12);
    BYTE *ek=NULL; DWORD cbEk=0; CHECK(rsa_oaep_encrypt(hPub, payload, 44, &ek, &cbEk), "RSA encrypt fail");

    // Send EKY! (magic + len + ciphertext)
    CHECK(send_all(s, F_EKY, 4), "send EKY magic fail");
    uint32_t n = htonl(cbEk);
    CHECK(send_all(s, &n, 4), "send EKY len fail");
    CHECK(send_all(s, ek, cbEk), "send EKY body fail");

    // Initialize AES-GCM locally with the same key/ivBase
    CHECK(aesgcm_init(outCtx, key, ivBase), "AES-GCM init fail");
    ok=TRUE;

cleanup:
    // Note: temporary DER, EKY buffers freed by caller or earlier; outCtx valid if ok
    return ok;
}

// ======================================
// == secure send/recv for DAT! frames ==
// ======================================
// send_secure: GCM-encrypt message using current counter → send framed (DAT! + counter + ct + tag) and bump counter
static BOOL send_secure(AESGCM_CTX *ctx, SOCKET s, uint32_t *pCounter, const BYTE *msg, DWORD cbMsg) {
    BYTE *ct=NULL,*tag=NULL; DWORD cbCt=0, cbTag=0;
    if (!aesgcm_encrypt(ctx, (*pCounter), msg, cbMsg, &ct, &cbCt, &tag, &cbTag)) return FALSE;

    // Frame header + sizes are big-endian (network order)
    if (!send_all(s, F_DAT, 4)) return FALSE;
    uint32_t counterN = htonl(*pCounter), ctN=htonl(cbCt), tagN=htonl(cbTag);
    if (!send_all(s, &counterN, 4)) return FALSE;
    if (!send_all(s, &ctN, 4)) return FALSE;
    if (!send_all(s, ct, cbCt)) return FALSE;
    if (!send_all(s, &tagN, 4)) return FALSE;
    if (!send_all(s, tag, cbTag)) return FALSE;

    // Free temp buffers and increment message counter for next IV
    HeapFree(GetProcessHeap(),0,ct); HeapFree(GetProcessHeap(),0,tag);
    (*pCounter)++;
    return TRUE;
}

// recv_secure: parse DAT! frame, GCM-decrypt using provided counter, and return plaintext buffer to caller
static BOOL recv_secure(AESGCM_CTX *ctx, SOCKET s, BYTE **out, DWORD *cbOut) {
    *out=NULL; *cbOut=0;
    char magic[4]; if (!recv_all(s, magic, 4)) return FALSE;
    if (memcmp(magic, F_DAT, 4)!=0) return FALSE;

    // Receive counter and ciphertext sizes
    uint32_t counterN=0, ctN=0, tagN=0;
    if (!recv_all(s, &counterN, 4)) return FALSE;
    if (!recv_all(s, &ctN, 4)) return FALSE;
    uint32_t counter = ntohl(counterN), cbCt = ntohl(ctN);

    // Receive ciphertext body
    BYTE *ct=(BYTE*)HeapAlloc(GetProcessHeap(),0,cbCt); if(!ct) return FALSE;
    if (!recv_all(s, ct, cbCt)) { HeapFree(GetProcessHeap(),0,ct); return FALSE; }

    // Receive tag length and tag body
    if (!recv_all(s, &tagN, 4)) { HeapFree(GetProcessHeap(),0,ct); return FALSE; }
    uint32_t cbTag = ntohl(tagN);
    BYTE *tag=(BYTE*)HeapAlloc(GetProcessHeap(),0,cbTag); if(!tag){ HeapFree(GetProcessHeap(),0,ct); return FALSE; }
    if (!recv_all(s, tag, cbTag)) { HeapFree(GetProcessHeap(),0,ct); HeapFree(GetProcessHeap(),0,tag); return FALSE; }

    // Attempt authenticated decryption (fails if tag invalid or tampered data)
    BYTE *pt=NULL; DWORD cbPt=0;
    BOOL ok = aesgcm_decrypt(ctx, counter, ct, cbCt, tag, cbTag, &pt, &cbPt);
    HeapFree(GetProcessHeap(),0,ct); HeapFree(GetProcessHeap(),0,tag);
    if (!ok) return FALSE;

    *out=pt; *cbOut=cbPt; return TRUE; // caller owns 'pt' and frees it
}

// =====================
// == networking (TCP) ==
// =====================
// start_winsock: initialize Winsock 2.2 (must be called once before socket operations)
static BOOL start_winsock(void){ WSADATA w; return (WSAStartup(MAKEWORD(2,2), &w)==0); }

// listen_on: create/bind/listen a TCP socket on given port (IPv4, INADDR_ANY)
static SOCKET listen_on(uint16_t port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s==INVALID_SOCKET) return INVALID_SOCKET;
    struct sockaddr_in a; ZeroMemory(&a,sizeof(a));
    a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_ANY); a.sin_port=htons(port);
    int opt=1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    if (bind(s,(struct sockaddr*)&a,sizeof(a))!=0) { closesocket(s); return INVALID_SOCKET; }
    if (listen(s,1)!=0) { closesocket(s); return INVALID_SOCKET; } // simple demo: backlog 1
    return s;
}

// connect_to: create a TCP socket and connect to given ip:port (IPv4)
static SOCKET connect_to(const char *ip, uint16_t port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s==INVALID_SOCKET) return INVALID_SOCKET;
    struct sockaddr_in a; ZeroMemory(&a,sizeof(a));
    a.sin_family=AF_INET; a.sin_port=htons(port); a.sin_addr.s_addr=inet_addr(ip); // localhost "127.0.0.1" ok
    if (connect(s,(struct sockaddr*)&a,sizeof(a))!=0) { closesocket(s); return INVALID_SOCKET; }
    return s;
}

// =====================
// == Reader thread   ==
// =====================
// Background thread that continuously receives secure messages and prints them.
// Keeps main thread free for user input & sending.
typedef struct {
    SOCKET s;
    AESGCM_CTX *ctx;
} ReaderArgs;

static DWORD WINAPI ReaderThread(LPVOID lpParam){
    ReaderArgs *args = (ReaderArgs*)lpParam;
    SOCKET s = args->s;
    AESGCM_CTX *ctx = args->ctx;
    HeapFree(GetProcessHeap(), 0, args); // free our args early; thread keeps local copies

    for(;;){
        BYTE *pt=NULL; DWORD cb=0;
        if (!recv_secure(ctx, s, &pt, &cb)) { wprintf(L"\n[peer closed or auth failed]\n"); break; }
        wprintf(L"\nPeer: %.*hs\n", cb, pt); // print received message as narrow string
        HeapFree(GetProcessHeap(),0,pt);
    }
    return 0;
}

// ==========================
// == server main routine ==
// ==========================
// Steps:
//  - Initialize Winsock
//  - Listen and accept one client
//  - Perform server_handshake (establish AES-GCM session)
//  - Spawn reader thread; main thread reads stdin and sends securely
//  - Clean shutdown on '/quit' or error
static int run_server(uint16_t port) {
    if (!start_winsock()) { fwprintf(stderr,L"Winsock init failed\n"); return 1; }
    SOCKET ls = listen_on(port);
    if (ls==INVALID_SOCKET){ fwprintf(stderr,L"Listen failed on %hu\n", port); return 1; }
    wprintf(L"\n[Server] Listening on %hu ...\n", port);

    struct sockaddr_in ca; int calen=sizeof(ca);
    SOCKET cs = accept(ls,(struct sockaddr*)&ca,&calen);
    if (cs==INVALID_SOCKET){ fwprintf(stderr,L"Accept failed\n"); closesocket(ls); return 1; }

    AESGCM_CTX gcm; ZeroMemory(&gcm,sizeof(gcm));
    if (!server_handshake(cs, &gcm)) { fwprintf(stderr,L"Handshake failed\n"); closesocket(cs); closesocket(ls); return 1; }
    wprintf(L"[Server] Handshake OK. Type messages, '/quit' to exit.\n");

    uint32_t counter=1; // per-direction message counter for nonce derivation
    ReaderArgs *ra = (ReaderArgs*)HeapAlloc(GetProcessHeap(),0,sizeof(ReaderArgs));
    ra->s = cs; ra->ctx = &gcm;
    HANDLE hReader = CreateThread(NULL,0,ReaderThread,(LPVOID)ra,0,NULL);

    char line[2048];
    for(;;){
        if (!fgets(line, sizeof(line), stdin)) break;       // read a line from console
        size_t L = strlen(line);
        if (L && (line[L-1]=='\n')) line[L-1]=0, L--;       // strip trailing newline
        if (strcmp(line,"/quit")==0) break;                  // user exit command
        if (!send_secure(&gcm, cs, &counter, (BYTE*)line, (DWORD)L)) { wprintf(L"[send failed]\n"); break; }
    }
    // Graceful close
    shutdown(cs, SD_BOTH); closesocket(cs); closesocket(ls);
    WaitForSingleObject(hReader, 2000); CloseHandle(hReader);
    aesgcm_free(&gcm);
    WSACleanup(); return 0;
}

// ==========================
// == client main routine ==
// ==========================
// Steps:
//  - Initialize Winsock
//  - Connect to server ip:port
//  - Perform client_handshake (validate cert via TOFU, send key material)
//  - Spawn reader thread; main thread sends user input securely
//  - Clean shutdown on '/quit' or error
static int run_client(const char *ip, uint16_t port) {
    if (!start_winsock()) { fwprintf(stderr,L"Winsock init failed\n"); return 1; }
    SOCKET s = connect_to(ip, port);
    if (s==INVALID_SOCKET){ fwprintf(stderr,L"Connect failed\n"); return 1; }

    AESGCM_CTX gcm; ZeroMemory(&gcm,sizeof(gcm));
    if (!client_handshake(s, &gcm)) { fwprintf(stderr,L"Handshake failed\n"); closesocket(s); return 1; }
    wprintf(L"[Client] Handshake OK. Type messages, '/quit' to exit.\n");

    uint32_t counter=1; // per-direction message counter
    ReaderArgs *ra = (ReaderArgs*)HeapAlloc(GetProcessHeap(),0,sizeof(ReaderArgs));
    ra->s = s; ra->ctx = &gcm;
    HANDLE hReader = CreateThread(NULL,0,ReaderThread,(LPVOID)ra,0,NULL);

    char line[2048];
    for(;;){
        if (!fgets(line, sizeof(line), stdin)) break;
        size_t L = strlen(line);
        if (L && (line[L-1]=='\n')) line[L-1]=0, L--;
        if (strcmp(line,"/quit")==0) break;
        if (!send_secure(&gcm, s, &counter, (BYTE*)line, (DWORD)L)) { wprintf(L"[send failed]\n"); break; }
    }
    // Graceful close
    shutdown(s, SD_BOTH); closesocket(s);
    WaitForSingleObject(hReader, 2000); CloseHandle(hReader);
    aesgcm_free(&gcm);
    WSACleanup(); return 0;
}

// ======================
// == interactive menu ==
// ======================
// Simple menu-driven UX so you don't need CLI flags; good for grading demos.
static void menu_banner(void){
    wprintf(L"=============================\n");
    wprintf(L"  SecureChat (Windows, CNG)  \n");
    wprintf(L"=============================\n");
    wprintf(L"1) Start Server\n");
    wprintf(L"2) Start Client\n");
    wprintf(L"3) Quit\n");
}

// wmain: Unicode entry point; loops menu and dispatches to server/client flows
int wmain(void){
    for(;;){
        menu_banner();
        wprintf(L"\nSelect an option (1-3): ");
        wchar_t choice[16]={0};
        if (!fgetws(choice, 16, stdin)) return 0;
        trim_nl(choice);

        if (wcscmp(choice, L"1")==0){
            wprintf(L"Enter port [default 4444]: ");
            wchar_t wport[32]={0}; fgetws(wport, 32, stdin); trim_nl(wport);
            int port = parse_int_or_default(wport, 4444);
            return run_server((uint16_t)port);
        }
        else if (wcscmp(choice, L"2")==0){
            wprintf(L"Enter server IP [default 127.0.0.1]: ");
            wchar_t wip[128]={0}; fgetws(wip, 128, stdin); trim_nl(wip);
            if (wcslen(wip)==0) wcscpy(wip, L"127.0.0.1"); // default to localhost if blank

            wprintf(L"Enter port [default 4444]: ");
            wchar_t wport[32]={0}; fgetws(wport, 32, stdin); trim_nl(wport);
            int port = parse_int_or_default(wport, 4444);

            char ipA[128]={0}; wide_to_utf8(wip, ipA, sizeof(ipA)); // convert to UTF-8 for Winsock
            return run_client(ipA, (uint16_t)port);
        }
        else if (wcscmp(choice, L"3")==0){
            wprintf(L"Goodbye.\n");
            return 0;
        }
        else{
            wprintf(L"Invalid choice. Try again.\n\n");
        }
    }
}
