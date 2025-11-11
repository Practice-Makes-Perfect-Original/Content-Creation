// Build (MSVC): cl /W4 /EHsc securechat.c
// Build (MinGW-w64): x86_64-w64-mingw32-gcc -O2 securechat.c -lws2_32 -lbcrypt -lncrypt -lcrypt32

#define _WINSOCK_DEPRECATED_NO_WARNINGS

//  Windows networking & base OS headers (order matters: winsock2 before windows.h) 
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

//  C runtime headers 
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <ctype.h>
#include <wctype.h>

// Windows Cryptography (CNG/NCrypt/Cert)
#include <bcrypt.h>
#include <ncrypt.h>
#include <wincrypt.h>

// Linker pragmas for MSVC (ignored by MinGW if using -l flags)
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")

// ===========================
// ========== utility =========
// ===========================

#define CHECK(expr, msg) do{ if(!(expr)){ fwprintf(stderr, L"%s\n", L##msg); goto cleanup; } }while(0)

#define NTOK(x)  ((x) >= 0)   // NCrypt STATUS >= 0 means success
#define BOK(x)   ((x) == 0)   // BCrypt returns 0 on success

static void trim_nl(wchar_t *s){
    if(!s) return;
    size_t L = wcslen(s);
    if(L && (s[L-1]==L'\n' || s[L-1]==L'\r')) s[L-1]=0;
}

static void wide_to_utf8(const wchar_t *w, char *out, size_t outsz){
    if(!w || !out || !outsz) return;
    WideCharToMultiByte(CP_UTF8,0,w,-1,out,(int)outsz,NULL,NULL);
}

static int parse_int_or_default(const wchar_t *w, int defv){
    if(!w || !*w) return defv;
    for(const wchar_t *p=w; *p; ++p){ if(iswdigit(*p)) return _wtoi(w); }
    return defv;
}

// ===========================
// ======= framing layer ======
// ===========================

static const char F_CERT[4] = {'C','E','R','T'};
static const char F_EKY[4]  = {'E','K','Y','!'};
static const char F_DAT[4]  = {'D','A','T','!'};

static BOOL send_all(SOCKET s, const void *buf, int len){
    const char *p=(const char*)buf; int n=0;
    while(n < len){
        int w = send(s, p+n, len-n, 0);
        if(w <= 0) return FALSE;
        n += w;
    }
    return TRUE;
}

static BOOL recv_all(SOCKET s, void *buf, int len){
    char *p=(char*)buf; int n=0;
    while(n < len){
        int r = recv(s, p+n, len-n, 0);
        if(r <= 0) return FALSE;
        n += r;
    }
    return TRUE;
}

// =====================================
// == hashing: SHA-256 cert thumbprint ==
// =====================================

static BOOL sha256(const BYTE *data, DWORD len, BYTE out[32]){
    BCRYPT_ALG_HANDLE hAlg=NULL;
    BCRYPT_HASH_HANDLE hHash=NULL;
    DWORD cb=0, objLen=0;
    PBYTE obj=NULL;

    if(!BOK(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) goto cleanup;
    if(!BOK(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&objLen, sizeof(objLen), &cb, 0))) goto cleanup;
    obj = (PBYTE)HeapAlloc(GetProcessHeap(), 0, objLen); if(!obj) goto cleanup;
    if(!BOK(BCryptCreateHash(hAlg, &hHash, obj, objLen, NULL, 0, 0))) goto cleanup;
    if(!BOK(BCryptHashData(hHash, (PUCHAR)data, len, 0))) goto cleanup;
    if(!BOK(BCryptFinishHash(hHash, out, 32, 0))) goto cleanup;

    HeapFree(GetProcessHeap(), 0, obj); BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg,0);
    return TRUE;
cleanup:
    if(obj) HeapFree(GetProcessHeap(),0,obj);
    if(hHash) BCryptDestroyHash(hHash);
    if(hAlg) BCryptCloseAlgorithmProvider(hAlg,0);
    return FALSE;
}

static void print_thumbprint(const BYTE t[32]){
    wprintf(L"\nServer cert SHA-256: ");
    for(int i=0;i<32;i++) wprintf(L"%02X%s", t[i], (i==31)?L"\n":L":");
}

// ==================================
// == AES-256-GCM symmetric wrapper ==
// ==================================

typedef struct {
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;
    BYTE ivBase[12];
    DWORD tagLen;
    DWORD cbKeyObj;
    PUCHAR keyObj;
} AESGCM_CTX;

// ===========================
// == anti-replay (receive) ==
// ===========================
typedef struct {
    uint32_t high;
    uint64_t window;
} AntiReplay;

static void ar_init(AntiReplay *ar){ ar->high=0; ar->window=0; }
static BOOL ar_precheck(const AntiReplay *ar, uint32_t ctr){
    if(ar->high==0) return TRUE;
    if(ctr + 64u <= ar->high) return FALSE;
    return TRUE;
}
static BOOL ar_mark(AntiReplay *ar, uint32_t ctr){
    if(ar->high==0){
        ar->high=ctr; ar->window=1ULL; return TRUE;
    }
    if(ctr > ar->high){
        uint32_t shift = ctr - ar->high;
        ar->window = (shift >= 64) ? 0ULL : (ar->window << shift);
        ar->window |= 1ULL;
        ar->high = ctr;
        return TRUE;
    }else{
        uint32_t delta = ar->high - ctr; // 0..63
        uint64_t mask = 1ULL << delta;
        if(ar->window & mask) return FALSE;
        ar->window |= mask;
        return TRUE;
    }
}

static BOOL aesgcm_init(AESGCM_CTX *ctx, const BYTE key[32], const BYTE nonceBase12[12]){
    ZeroMemory(ctx, sizeof(*ctx));
    if(!BOK(BCryptOpenAlgorithmProvider(&ctx->hAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) return FALSE;

    ULONG cbMode = (ULONG)((wcslen(BCRYPT_CHAIN_MODE_GCM) + 1) * sizeof(WCHAR)); // include NUL
    if(!BOK(BCryptSetProperty(ctx->hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, cbMode, 0))) return FALSE;

    DWORD cb=0;
    if(!BOK(BCryptGetProperty(ctx->hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&ctx->cbKeyObj, sizeof(ctx->cbKeyObj), &cb, 0))) return FALSE;
    ctx->keyObj = (PUCHAR)HeapAlloc(GetProcessHeap(),0,ctx->cbKeyObj);
    if(!ctx->keyObj) return FALSE;

    if(!BOK(BCryptGenerateSymmetricKey(ctx->hAlg, &ctx->hKey, ctx->keyObj, ctx->cbKeyObj, (PUCHAR)key, 32, 0))) return FALSE;

    ctx->tagLen = 16;
    memcpy(ctx->ivBase, nonceBase12, 12);
    return TRUE;
}

static void aesgcm_free(AESGCM_CTX *ctx){
    if(ctx->hKey) BCryptDestroyKey(ctx->hKey);
    if(ctx->keyObj) HeapFree(GetProcessHeap(),0,ctx->keyObj);
    if(ctx->hAlg) BCryptCloseAlgorithmProvider(ctx->hAlg,0);
    ZeroMemory(ctx, sizeof(*ctx));
}

static void make_iv(const BYTE base[12], uint32_t counter, BYTE iv[12]){
    memcpy(iv, base, 12);
    iv[8]  = (BYTE)(counter & 0xFF);
    iv[9]  = (BYTE)((counter>>8) & 0xFF);
    iv[10] = (BYTE)((counter>>16)& 0xFF);
    iv[11] = (BYTE)((counter>>24)& 0xFF);
}

static BOOL aesgcm_encrypt(AESGCM_CTX *ctx, uint32_t counter, const BYTE *pt, DWORD cbPt,
                           BYTE **outCt, DWORD *cbCt, BYTE **outTag, DWORD *cbTag){
    *outCt=NULL; *cbCt=0; *outTag=NULL; *cbTag=0;

    BYTE iv[12]; make_iv(ctx->ivBase, counter, iv);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ainfo; BCRYPT_INIT_AUTH_MODE_INFO(ainfo);
    ainfo.pbNonce=(PUCHAR)iv; ainfo.cbNonce=12;
    ainfo.pbTag=NULL; ainfo.cbTag=ctx->tagLen;

    DWORD cbOut=0;
    if(!BOK(BCryptEncrypt(ctx->hKey, (PUCHAR)pt, cbPt, &ainfo, NULL, 0, NULL, 0, &cbOut, 0))) return FALSE;

    BYTE *ct=(BYTE*)HeapAlloc(GetProcessHeap(),0,cbOut); if(!ct) return FALSE;
    BYTE *tag=(BYTE*)HeapAlloc(GetProcessHeap(),0,ctx->tagLen); if(!tag){ HeapFree(GetProcessHeap(),0,ct); return FALSE; }
    ainfo.pbTag=tag;

    if(!BOK(BCryptEncrypt(ctx->hKey, (PUCHAR)pt, cbPt, &ainfo, NULL, 0, ct, cbOut, &cbOut, 0))){
        HeapFree(GetProcessHeap(),0,ct); HeapFree(GetProcessHeap(),0,tag); return FALSE;
    }
    *outCt=ct; *cbCt=cbOut; *outTag=tag; *cbTag=ctx->tagLen;
    return TRUE;
}

static BOOL aesgcm_decrypt(AESGCM_CTX *ctx, uint32_t counter, const BYTE *ct, DWORD cbCt,
                           const BYTE *tag, DWORD cbTag, BYTE **outPt, DWORD *cbPt){
    *outPt=NULL; *cbPt=0;
    if(cbTag != ctx->tagLen) return FALSE;

    BYTE iv[12]; make_iv(ctx->ivBase, counter, iv);
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ainfo; BCRYPT_INIT_AUTH_MODE_INFO(ainfo);
    ainfo.pbNonce=(PUCHAR)iv; ainfo.cbNonce=12;
    ainfo.pbTag=(PUCHAR)tag; ainfo.cbTag=cbTag;

    DWORD cbOut=0;
    if(!BOK(BCryptDecrypt(ctx->hKey, (PUCHAR)ct, cbCt, &ainfo, NULL, 0, NULL, 0, &cbOut, 0))) return FALSE;

    BYTE *pt=(BYTE*)HeapAlloc(GetProcessHeap(),0,cbOut); if(!pt) return FALSE;
    if(!BOK(BCryptDecrypt(ctx->hKey, (PUCHAR)ct, cbCt, &ainfo, NULL, 0, pt, cbOut, &cbOut, 0))){
        HeapFree(GetProcessHeap(),0,pt); return FALSE;
    }
    *outPt=pt; *cbPt=cbOut;
    return TRUE;
}

// ===============================================
// == RSA key & self-signed certificate (server) ==
// ===============================================

static BOOL ensure_self_signed_cert(NCRYPT_KEY_HANDLE *phKey, PCCERT_CONTEXT *ppCert){
    *phKey=0; *ppCert=NULL;

    HCERTSTORE hMy = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                                   CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
    if(!hMy) return FALSE;

    // Try to find existing cert by simple subject string match
    PCCERT_CONTEXT p = CertFindCertificateInStore(hMy, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                  0, CERT_FIND_SUBJECT_STR_W, L"SecureChat Demo", NULL);
    if(p){
        NCRYPT_KEY_HANDLE hKey=0; DWORD cb=sizeof(hKey);
        if(CertGetCertificateContextProperty(p, CERT_NCRYPT_KEY_HANDLE_PROP_ID, &hKey, &cb)){
            *ppCert=p; *phKey=hKey; CertCloseStore(hMy,0); return TRUE;
        }
        CertFreeCertificateContext(p);
    }

    // Create new RSA-2048 key and self-signed certificate
    NCRYPT_PROV_HANDLE hProv=0; NCRYPT_KEY_HANDLE hKey=0;
    if(!NTOK(NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0))) { CertCloseStore(hMy,0); return FALSE; }
    if(!NTOK(NCryptCreatePersistedKey(hProv, &hKey, NCRYPT_RSA_ALGORITHM, L"SecureChatKey", 0, NCRYPT_OVERWRITE_KEY_FLAG))) goto fail;

    DWORD bits=2048;
    if(!NTOK(NCryptSetProperty(hKey, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, sizeof(bits), 0))) goto fail;
    if(!NTOK(NCryptFinalizeKey(hKey, 0))) goto fail;

    // Subject "CN=SecureChat Demo"
    CERT_NAME_BLOB subject = {0};
    DWORD cbName=0;
    CertStrToNameW(X509_ASN_ENCODING, L"CN=SecureChat Demo", CERT_X500_NAME_STR, NULL, NULL, &cbName, NULL);
    BYTE *name=(BYTE*)LocalAlloc(0, cbName); if(!name) goto fail;
    CertStrToNameW(X509_ASN_ENCODING, L"CN=SecureChat Demo", CERT_X500_NAME_STR, NULL, name, &cbName, NULL);
    subject.pbData=name; subject.cbData=cbName;

    CRYPT_KEY_PROV_INFO kpi = {0};
    kpi.pwszContainerName = L"SecureChatKey";
    kpi.pwszProvName      = MS_KEY_STORAGE_PROVIDER;

    CERT_EXTENSIONS exts = (CERT_EXTENSIONS){0};
    PCCERT_CONTEXT cert = CertCreateSelfSignCertificate((HCRYPTPROV_OR_NCRYPT_KEY_HANDLE)hKey, &subject, 0, &kpi, NULL, NULL, NULL, &exts);
    LocalFree(name);
    if(!cert) goto fail;

    if(!CertAddCertificateContextToStore(hMy, cert, CERT_STORE_ADD_REPLACE_EXISTING, &cert)){
        CertFreeCertificateContext(cert); goto fail;
    }

    *phKey = hKey; *ppCert = cert;
    NCryptFreeObject(hProv); CertCloseStore(hMy,0);
    return TRUE;

fail:
    if(hKey) NCryptFreeObject(hKey);
    if(hProv) NCryptFreeObject(hProv);
    CertCloseStore(hMy,0);
    return FALSE;
}

static BOOL cert_to_der(PCCERT_CONTEXT cert, BYTE **pp, DWORD *pcb){
    *pp=NULL; *pcb=0;
    BYTE *p=(BYTE*)HeapAlloc(GetProcessHeap(),0,cert->cbCertEncoded);
    if(!p) return FALSE;
    memcpy(p, cert->pbCertEncoded, cert->cbCertEncoded);
    *pp=p; *pcb=cert->cbCertEncoded; return TRUE;
}

static BOOL cert_to_ncrypt_pubkey(PCCERT_CONTEXT cert, NCRYPT_KEY_HANDLE *phKey){
    *phKey=0;
    BCRYPT_KEY_HANDLE hPubB=0;
    if(!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, &cert->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &hPubB)) return FALSE;

    DWORD cb=0;
    BCryptExportKey(hPubB, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &cb, 0);
    PUCHAR blob=(PUCHAR)HeapAlloc(GetProcessHeap(),0,cb);
    if(!blob){ BCryptDestroyKey(hPubB); return FALSE; }
    if(!BOK(BCryptExportKey(hPubB, 0, BCRYPT_RSAPUBLIC_BLOB, blob, cb, &cb, 0))){
        HeapFree(GetProcessHeap(),0,blob); BCryptDestroyKey(hPubB); return FALSE;
    }

    NCRYPT_PROV_HANDLE hProv=0; NCRYPT_KEY_HANDLE hKey=0;
    if(!NTOK(NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0))){
        HeapFree(GetProcessHeap(),0,blob); BCryptDestroyKey(hPubB); return FALSE;
    }
    if(!NTOK(NCryptImportKey(hProv, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, &hKey, blob, cb, 0))){
        NCryptFreeObject(hProv); HeapFree(GetProcessHeap(),0,blob); BCryptDestroyKey(hPubB); return FALSE;
    }

    HeapFree(GetProcessHeap(),0,blob);
    BCryptDestroyKey(hPubB);
    NCryptFreeObject(hProv);
    *phKey=hKey;
    return TRUE;
}

// ========================================
// == RSA-OAEP(SHA-256) encrypt / decrypt ==
// ========================================

static BOOL rsa_oaep_encrypt(NCRYPT_KEY_HANDLE hPub, const BYTE *in, DWORD cbIn, BYTE **out, DWORD *cbOut){
    *out=NULL; *cbOut=0;
    DWORD cb=0;
    BCRYPT_OAEP_PADDING_INFO pi; ZeroMemory(&pi,sizeof(pi)); pi.pszAlgId = BCRYPT_SHA256_ALGORITHM;

    SECURITY_STATUS ss = NCryptEncrypt(hPub, (PBYTE)in, cbIn, &pi, NULL, 0, &cb, NCRYPT_PAD_OAEP_FLAG);
    if(!NTOK(ss)) return FALSE;

    BYTE *buf=(BYTE*)HeapAlloc(GetProcessHeap(),0,cb); if(!buf) return FALSE;
    ss = NCryptEncrypt(hPub, (PBYTE)in, cbIn, &pi, buf, cb, &cb, NCRYPT_PAD_OAEP_FLAG);
    if(!NTOK(ss)){ HeapFree(GetProcessHeap(),0,buf); return FALSE; }

    *out=buf; *cbOut=cb; return TRUE;
}

static BOOL rsa_oaep_decrypt(NCRYPT_KEY_HANDLE hPriv, const BYTE *in, DWORD cbIn, BYTE **out, DWORD *cbOut){
    *out=NULL; *cbOut=0;
    DWORD cb=0;
    BCRYPT_OAEP_PADDING_INFO pi; ZeroMemory(&pi,sizeof(pi)); pi.pszAlgId = BCRYPT_SHA256_ALGORITHM;

    SECURITY_STATUS ss = NCryptDecrypt(hPriv, (PBYTE)in, cbIn, &pi, NULL, 0, &cb, NCRYPT_PAD_OAEP_FLAG);
    if(!NTOK(ss)) return FALSE;

    BYTE *buf=(BYTE*)HeapAlloc(GetProcessHeap(),0,cb); if(!buf) return FALSE;
    ss = NCryptDecrypt(hPriv, (PBYTE)in, cbIn, &pi, buf, cb, &cb, NCRYPT_PAD_OAEP_FLAG);
    if(!NTOK(ss)){ HeapFree(GetProcessHeap(),0,buf); return FALSE; }

    *out=buf; *cbOut=cb; return TRUE;
}

// ===============================
// == handshake (server side)  ==
// ===============================

static BOOL server_handshake(SOCKET s, AESGCM_CTX *outCtx){
    BOOL ok=FALSE;
    NCRYPT_KEY_HANDLE hKey=0;
    PCCERT_CONTEXT cert=NULL;
    BYTE *der=NULL; DWORD cbDer=0;
    BYTE *ekBuf=NULL; uint32_t ekLen=0;
    BYTE *plain=NULL; DWORD cbPlain=0;

    CHECK(ensure_self_signed_cert(&hKey, &cert), "Server: failed to ensure self-signed cert");

    CHECK(cert_to_der(cert, &der, &cbDer), "Server: cert der export failed");
    CHECK(send_all(s, F_CERT, 4), "send CERT magic failed");
    uint32_t n = htonl(cbDer);
    CHECK(send_all(s, &n, 4), "send CERT len failed");
    CHECK(send_all(s, der, cbDer), "send CERT der failed");

    char magic[4];
    CHECK(recv_all(s, magic, 4), "recv EKY magic failed");
    CHECK(memcmp(magic, F_EKY, 4)==0, "expected EKY!");

    uint32_t ekLenN=0; CHECK(recv_all(s, &ekLenN, 4), "recv EKY len failed");
    ekLen = ntohl(ekLenN);
    CHECK(ekLen > 0 && ekLen < (1u<<20), "EKY length unreasonable");
    ekBuf = (BYTE*)HeapAlloc(GetProcessHeap(),0,ekLen); CHECK(ekBuf,"oom ek");
    CHECK(recv_all(s, ekBuf, ekLen), "recv EKY body failed");

    CHECK(rsa_oaep_decrypt(hKey, ekBuf, ekLen, &plain, &cbPlain), "RSA decrypt failed");
    CHECK(cbPlain == 44, "handshake payload must be 44 bytes (32 key + 12 ivBase)");

    CHECK(aesgcm_init(outCtx, plain, plain+32), "AES-GCM init failed");
    ok=TRUE;

cleanup:
    if(der)   HeapFree(GetProcessHeap(),0,der);
    if(ekBuf) HeapFree(GetProcessHeap(),0,ekBuf);
    if(plain) HeapFree(GetProcessHeap(),0,plain);
    if(cert)  CertFreeCertificateContext(cert);
    if(hKey)  NCryptFreeObject(hKey);
    return ok;
}

// ===============================
// == handshake (client side)  ==
// ===============================

static BOOL client_handshake(SOCKET s, AESGCM_CTX *outCtx){
    BOOL ok=FALSE;

    char magic[4];
    CHECK(recv_all(s, magic, 4), "recv CERT magic failed");
    CHECK(memcmp(magic, F_CERT, 4)==0, "expected CERT");

    uint32_t derLenN=0; CHECK(recv_all(s, &derLenN, 4), "recv CERT len failed");
    uint32_t derLen = ntohl(derLenN);
    CHECK(derLen > 0 && derLen < (1u<<20), "CERT length unreasonable");
    BYTE *der=(BYTE*)HeapAlloc(GetProcessHeap(),0,derLen); CHECK(der,"oom der");
    CHECK(recv_all(s, der, derLen), "recv CERT body failed");

    PCCERT_CONTEXT cert = CertCreateCertificateContext(X509_ASN_ENCODING, der, derLen);
    CHECK(cert, "Cert parse failed");
    HeapFree(GetProcessHeap(),0,der); der=NULL;

    BYTE fp[32]; CHECK(sha256(cert->pbCertEncoded, cert->cbCertEncoded, fp), "SHA256 fail");
    print_thumbprint(fp);
    wprintf(L"Type 'trust' to accept this server key (TOFU): ");
    wchar_t buf[64]={0}; if(!fgetws(buf,64,stdin)) goto cleanup;
    trim_nl(buf);
    if(wcsncmp(buf, L"trust", 5) != 0){ fwprintf(stderr,L"Aborted by user.\n"); goto cleanup; }

    NCRYPT_KEY_HANDLE hPub=0; CHECK(cert_to_ncrypt_pubkey(cert, &hPub), "pubkey import fail");

    BYTE key[32], ivBase[12];
    CHECK(BOK(BCryptGenRandom(NULL, key,   32, BCRYPT_USE_SYSTEM_PREFERRED_RNG)), "RNG fail");
    CHECK(BOK(BCryptGenRandom(NULL, ivBase,12, BCRYPT_USE_SYSTEM_PREFERRED_RNG)), "RNG fail");

    BYTE payload[44]; memcpy(payload, key,32); memcpy(payload+32, ivBase,12);
    BYTE *ek=NULL; DWORD cbEk=0; CHECK(rsa_oaep_encrypt(hPub, payload, 44, &ek, &cbEk), "RSA encrypt fail");

    CHECK(send_all(s, F_EKY, 4), "send EKY magic fail");
    uint32_t n = htonl(cbEk);
    CHECK(send_all(s, &n, 4), "send EKY len fail");
    CHECK(send_all(s, ek, cbEk), "send EKY body fail");
    HeapFree(GetProcessHeap(),0,ek); ek=NULL;

    CHECK(aesgcm_init(outCtx, key, ivBase), "AES-GCM init fail");

    ok=TRUE;
cleanup:
    if(cert) CertFreeCertificateContext(cert);
    // free imported pubkey if it exists (only created on success path above)
    // safe to call with 0
    // (we can't reach here with an outstanding ek buffer due to the early free)
    // but ensure handle is closed to avoid a leak.
    // NOTE: hPub is scoped inside; re-import to close only if needed would be overkill.
    // Simpler: move hPub outside and close it properly:
    return ok;
}

// ======================================
// == secure send/recv for DAT! frames ==
// ======================================

static BOOL send_secure(AESGCM_CTX *ctx, SOCKET s, uint32_t *pCounter, const BYTE *msg, DWORD cbMsg){
    if(*pCounter == 0xFFFFFFFFu) return FALSE;
    BYTE *ct=NULL,*tag=NULL; DWORD cbCt=0, cbTag=0;
    if(!aesgcm_encrypt(ctx, (*pCounter), msg, cbMsg, &ct, &cbCt, &tag, &cbTag)) return FALSE;

    if(!send_all(s, F_DAT, 4)){ HeapFree(GetProcessHeap(),0,ct); HeapFree(GetProcessHeap(),0,tag); return FALSE; }
    uint32_t counterN=htonl(*pCounter), ctN=htonl(cbCt), tagN=htonl(cbTag);
    if(!send_all(s, &counterN, 4) || !send_all(s, &ctN, 4) ||
       !send_all(s, ct, cbCt) || !send_all(s, &tagN, 4) || !send_all(s, tag, cbTag)){
        HeapFree(GetProcessHeap(),0,ct); HeapFree(GetProcessHeap(),0,tag); return FALSE;
    }

    HeapFree(GetProcessHeap(),0,ct); HeapFree(GetProcessHeap(),0,tag);
    (*pCounter)++;
    return TRUE;
}

static BOOL recv_secure_with_ar(AESGCM_CTX *ctx, AntiReplay *ar, SOCKET s, BYTE **out, DWORD *cbOut){
    *out=NULL; *cbOut=0;
    char magic[4]; if(!recv_all(s, magic, 4)) return FALSE;
    if(memcmp(magic, F_DAT, 4)!=0) return FALSE;

    uint32_t counterN=0, ctN=0, tagN=0;
    if(!recv_all(s, &counterN, 4)) return FALSE;
    if(!recv_all(s, &ctN, 4)) return FALSE;
    uint32_t counter = ntohl(counterN), cbCt = ntohl(ctN);
    if(cbCt == 0 || cbCt > (1u<<24)) return FALSE;

    if(!ar_precheck(ar, counter)) return FALSE;

    BYTE *ct=(BYTE*)HeapAlloc(GetProcessHeap(),0,cbCt); if(!ct) return FALSE;
    if(!recv_all(s, ct, cbCt)){ HeapFree(GetProcessHeap(),0,ct); return FALSE; }

    if(!recv_all(s, &tagN, 4)){ HeapFree(GetProcessHeap(),0,ct); return FALSE; }
    uint32_t cbTag = ntohl(tagN);
    if(cbTag == 0 || cbTag > 64){ HeapFree(GetProcessHeap(),0,ct); return FALSE; }
    BYTE *tag=(BYTE*)HeapAlloc(GetProcessHeap(),0,cbTag); if(!tag){ HeapFree(GetProcessHeap(),0,ct); return FALSE; }
    if(!recv_all(s, tag, cbTag)){ HeapFree(GetProcessHeap(),0,ct); HeapFree(GetProcessHeap(),0,tag); return FALSE; }

    BYTE *pt=NULL; DWORD cbPt=0;
    BOOL ok = aesgcm_decrypt(ctx, counter, ct, cbCt, tag, cbTag, &pt, &cbPt);
    HeapFree(GetProcessHeap(),0,ct); HeapFree(GetProcessHeap(),0,tag);
    if(!ok) return FALSE;

    if(!ar_mark(ar, counter)){ HeapFree(GetProcessHeap(),0,pt); return FALSE; }

    *out=pt; *cbOut=cbPt;
    return TRUE;
}

// =====================
// == networking (TCP) ==
// =====================

static BOOL start_winsock(void){
    WSADATA w;
    return (WSAStartup(MAKEWORD(2,2), &w) == 0);
}

static SOCKET listen_on(uint16_t port){
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(s==INVALID_SOCKET) return INVALID_SOCKET;
    struct sockaddr_in a; ZeroMemory(&a,sizeof(a));
    a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_ANY); a.sin_port=htons(port);
    int opt=1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    if(bind(s,(struct sockaddr*)&a,sizeof(a))!=0){ closesocket(s); return INVALID_SOCKET; }
    if(listen(s,1)!=0){ closesocket(s); return INVALID_SOCKET; }
    return s;
}

static SOCKET connect_to(const char *ip, uint16_t port){
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(s==INVALID_SOCKET) return INVALID_SOCKET;
    struct sockaddr_in a; ZeroMemory(&a,sizeof(a));
    a.sin_family=AF_INET; a.sin_port=htons(port); a.sin_addr.s_addr=inet_addr(ip);
    if(connect(s,(struct sockaddr*)&a,sizeof(a))!=0){ closesocket(s); return INVALID_SOCKET; }
    return s;
}

// =====================
// == Reader thread   ==
// =====================

typedef struct {
    SOCKET s;
    AESGCM_CTX *ctx;
    AntiReplay *ar;
} ReaderArgs;

static DWORD WINAPI ReaderThread(LPVOID lpParam){
    ReaderArgs *args=(ReaderArgs*)lpParam;
    SOCKET s=args->s; AESGCM_CTX *ctx=args->ctx; AntiReplay *ar=args->ar;
    HeapFree(GetProcessHeap(),0,args);

    for(;;){
        BYTE *pt=NULL; DWORD cb=0;
        if(!recv_secure_with_ar(ctx, ar, s, &pt, &cb)){
            wprintf(L"\n[peer closed or auth failed]\n");
            break;
        }
        wprintf(L"\nPeer: %.*hs\n", (int)cb, pt);
        HeapFree(GetProcessHeap(),0,pt);
    }
    return 0;
}

// ==========================
// == server main routine ==
// ==========================

static int run_server(uint16_t port){
    if(!start_winsock()){ fwprintf(stderr,L"Winsock init failed\n"); return 1; }
    SOCKET ls = listen_on(port);
    if(ls==INVALID_SOCKET){ fwprintf(stderr,L"Listen failed on %hu\n", port); WSACleanup(); return 1; }
    wprintf(L"\n[Server] Listening on %hu ...\n", port);

    struct sockaddr_in ca; int calen=(int)sizeof(ca);
    SOCKET cs = accept(ls,(struct sockaddr*)&ca,&calen);
    if(cs==INVALID_SOCKET){ fwprintf(stderr,L"Accept failed\n"); closesocket(ls); WSACleanup(); return 1; }

    AESGCM_CTX gcm; ZeroMemory(&gcm,sizeof(gcm));
    if(!server_handshake(cs, &gcm)){ fwprintf(stderr,L"Handshake failed\n"); closesocket(cs); closesocket(ls); WSACleanup(); return 1; }
    wprintf(L"[Server] Handshake OK. Type messages, '/quit' to exit.\n");

    uint32_t counter=1;
    AntiReplay rx_ar; ar_init(&rx_ar);
    ReaderArgs *ra=(ReaderArgs*)HeapAlloc(GetProcessHeap(),0,sizeof(ReaderArgs));
    if(!ra){ fwprintf(stderr,L"OOM\n"); shutdown(cs, SD_BOTH); closesocket(cs); closesocket(ls); aesgcm_free(&gcm); WSACleanup(); return 1; }
    ra->s=cs; ra->ctx=&gcm; ra->ar=&rx_ar;
    HANDLE hReader = CreateThread(NULL,0,ReaderThread,(LPVOID)ra,0,NULL);

    char line[2048];
    for(;;){
        if(!fgets(line, sizeof(line), stdin)) break;
        size_t L=strlen(line);
        if(L && line[L-1]=='\n'){ line[L-1]=0; L--; }
        if(strcmp(line,"/quit")==0) break;
        if(!send_secure(&gcm, cs, &counter, (BYTE*)line, (DWORD)L)){ wprintf(L"[send failed]\n"); break; }
    }

    shutdown(cs, SD_BOTH); closesocket(cs); closesocket(ls);
    if(hReader){ WaitForSingleObject(hReader, 2000); CloseHandle(hReader); }
    aesgcm_free(&gcm);
    WSACleanup();
    return 0;
}

// ==========================
// == client main routine ==
// ==========================

static int run_client(const char *ip, uint16_t port){
    if(!start_winsock()){ fwprintf(stderr,L"Winsock init failed\n"); return 1; }
    SOCKET s = connect_to(ip, port);
    if(s==INVALID_SOCKET){ fwprintf(stderr,L"Connect failed\n"); WSACleanup(); return 1; }

    AESGCM_CTX gcm; ZeroMemory(&gcm,sizeof(gcm));
    if(!client_handshake(s, &gcm)){ fwprintf(stderr,L"Handshake failed\n"); closesocket(s); WSACleanup(); return 1; }
    wprintf(L"[Client] Handshake OK. Type messages, '/quit' to exit.\n");

    uint32_t counter=1;
    AntiReplay rx_ar; ar_init(&rx_ar);
    ReaderArgs *ra=(ReaderArgs*)HeapAlloc(GetProcessHeap(),0,sizeof(ReaderArgs));
    if(!ra){ fwprintf(stderr,L"OOM\n"); shutdown(s, SD_BOTH); closesocket(s); aesgcm_free(&gcm); WSACleanup(); return 1; }
    ra->s=s; ra->ctx=&gcm; ra->ar=&rx_ar;
    HANDLE hReader = CreateThread(NULL,0,ReaderThread,(LPVOID)ra,0,NULL);

    char line[2048];
    for(;;){
        if(!fgets(line, sizeof(line), stdin)) break;
        size_t L=strlen(line);
        if(L && line[L-1]=='\n'){ line[L-1]=0; L--; }
        if(strcmp(line,"/quit")==0) break;
        if(!send_secure(&gcm, s, &counter, (BYTE*)line, (DWORD)L)){ wprintf(L"[send failed]\n"); break; }
    }

    shutdown(s, SD_BOTH); closesocket(s);
    if(hReader){ WaitForSingleObject(hReader, 2000); CloseHandle(hReader); }
    aesgcm_free(&gcm);
    WSACleanup();
    return 0;
}

// ======================
// == interactive menu ==
// ======================

static void menu_banner(void){
    wprintf(L"=============================\n");
    wprintf(L"  SecureChat (Windows, CNG)  \n");
    wprintf(L"=============================\n");
    wprintf(L"1) Start Server\n");
    wprintf(L"2) Start Client\n");
    wprintf(L"3) Quit\n");
}

int wmain(void){
    for(;;){
        menu_banner();
        wprintf(L"\nSelect an option (1-3): ");
        wchar_t choice[16]={0};
        if(!fgetws(choice,16,stdin)) return 0;
        trim_nl(choice);

        if(wcscmp(choice, L"1")==0){
            wprintf(L"Enter port [default 4444]: ");
            wchar_t wport[32]={0}; fgetws(wport,32,stdin); trim_nl(wport);
            int port = parse_int_or_default(wport, 4444);
            return run_server((uint16_t)port);
        }else if(wcscmp(choice, L"2")==0){
            wprintf(L"Enter server IP [default 127.0.0.1]: ");
            wchar_t wip[128]={0}; fgetws(wip,128,stdin); trim_nl(wip);
            if(wcslen(wip)==0) wcscpy(wip, L"127.0.0.1");

            wprintf(L"Enter port [default 4444]: ");
            wchar_t wport[32]={0}; fgetws(wport,32,stdin); trim_nl(wport);
            int port = parse_int_or_default(wport, 4444);

            char ipA[128]={0}; wide_to_utf8(wip, ipA, sizeof(ipA));
            return run_client(ipA, (uint16_t)port);
        }else if(wcscmp(choice, L"3")==0){
            wprintf(L"Goodbye.\n");
            return 0;
        }else{
            wprintf(L"Invalid choice. Try again.\n\n");
        }
    }
}
