#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 4444
#define BUFFER_SIZE 1024

// GUI Global Variables
HWND hwnd, hChatBox, hMessageBox, hSendButton, hIPBox, hConnectButton, hWaitButton;
SOCKET global_socket;
SSL *global_ssl;
SSL_CTX *ctx;
int isServer = 0;

// Function Declarations
LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
DWORD WINAPI ServerThread(LPVOID param);
DWORD WINAPI ClientThread(LPVOID param);
void SendMessageGUI();
SSL_CTX *initialize_ssl_context(int isServer);
void generate_self_signed_cert(const char *cert_file, const char *key_file);
void cleanup_files();

// Function to Generate Self-Signed Certificate
void generate_self_signed_cert(const char *cert_file, const char *key_file) {
    EVP_PKEY *pkey = EVP_PKEY_new();
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, e, NULL);
    EVP_PKEY_assign_RSA(pkey, rsa);

    X509 *x509 = X509_new();
    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
    X509_set_pubkey(x509, pkey);

    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"Secure Chat", -1, -1, 0);
    X509_set_issuer_name(x509, name);
    X509_sign(x509, pkey, EVP_sha256());

    FILE *cert_fp = fopen(cert_file, "wb");
    PEM_write_X509(cert_fp, x509);
    fclose(cert_fp);

    FILE *key_fp = fopen(key_file, "wb");
    PEM_write_PrivateKey(key_fp, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(key_fp);

    EVP_PKEY_free(pkey);
    RSA_free(rsa);
    BN_free(e);
    X509_free(x509);
}

// Initialize SSL Context
SSL_CTX *initialize_ssl_context(int isServer) {
    SSL_CTX *ctx = SSL_CTX_new(isServer ? TLS_server_method() : TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    generate_self_signed_cert("temp_server.crt", "temp_server.key");

    if (isServer) {
        if (SSL_CTX_use_certificate_file(ctx, "temp_server.crt", SSL_FILETYPE_PEM) <= 0 ||
            SSL_CTX_use_PrivateKey_file(ctx, "temp_server.key", SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
            }
    }
    return ctx;
}

// Server Function
DWORD WINAPI ServerThread(LPVOID param) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    SOCKET server_fd, client_socket;
    struct sockaddr_in server_addr, client_addr;
    int addr_size = sizeof(client_addr);

    ctx = initialize_ssl_context(1);
    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(server_fd, 1);

    client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addr_size);
    global_socket = client_socket;

    global_ssl = SSL_new(ctx);
    SSL_set_fd(global_ssl, client_socket);
    SSL_accept(global_ssl);

    char buffer[BUFFER_SIZE];
    int bytes_read;
    while ((bytes_read = SSL_read(global_ssl, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        SendMessage(hChatBox, WM_SETTEXT, 0, (LPARAM)buffer);
    }

    SSL_shutdown(global_ssl);
    SSL_free(global_ssl);
    closesocket(client_socket);
    return 0;
}

// Client Function
DWORD WINAPI ClientThread(LPVOID param) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    char *ip = (char *)param;
    SOCKET client_socket;
    struct sockaddr_in server_addr;

    ctx = initialize_ssl_context(0);
    client_socket = socket(AF_INET, SOCK_STREAM, 0);

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, ip, &server_addr.sin_addr);

    connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));
    global_socket = client_socket;

    global_ssl = SSL_new(ctx);
    SSL_set_fd(global_ssl, client_socket);
    SSL_connect(global_ssl);

    char buffer[BUFFER_SIZE];
    int bytes_read;
    while ((bytes_read = SSL_read(global_ssl, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        SendMessage(hChatBox, WM_SETTEXT, 0, (LPARAM)buffer);
    }

    SSL_shutdown(global_ssl);
    SSL_free(global_ssl);
    closesocket(client_socket);
    return 0;
}

// Sends a Message
void SendMessageGUI() {
    char buffer[BUFFER_SIZE];
    GetWindowText(hMessageBox, buffer, BUFFER_SIZE);
    SSL_write(global_ssl, buffer, strlen(buffer));
}

// Main Windows GUI Loop
LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_COMMAND:
            if ((HWND)lParam == hSendButton) {
                SendMessageGUI();
            }
            if ((HWND)lParam == hConnectButton) {
                char ip[INET_ADDRSTRLEN];
                GetWindowText(hIPBox, ip, INET_ADDRSTRLEN);
                CreateThread(NULL, 0, ClientThread, ip, 0, NULL);
            }
            if ((HWND)lParam == hWaitButton) {
                isServer = 1;
                CreateThread(NULL, 0, ServerThread, NULL, 0, NULL);
            }
            break;
        case WM_DESTROY:
            cleanup_files();
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

// Entry Point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "SecureChat";

    RegisterClass(&wc);
    hwnd = CreateWindow("SecureChat", "Secure Chat", WS_OVERLAPPEDWINDOW, 100, 100, 400, 400, NULL, NULL, hInstance, NULL);

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}

// Function to Delete Temporary Certs
void cleanup_files() {
    remove("temp_server.crt");
    remove("temp_server.key");
}
