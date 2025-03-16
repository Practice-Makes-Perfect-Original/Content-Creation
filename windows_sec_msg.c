#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <pthread.h>

#define SECURITY_WIN32
#include <security.h>
#include <sspi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")

#define PORT 4444
#define BUFFER_SIZE 1024
#define SCHANNEL_CRED_VERSION 4
#define SP_PROT_TLS1_2 0x00000800
#define UNISP_NAME "Microsoft Unified Security Protocol Provider"

// Manually define SCHANNEL_CRED (MinGW-W64 does not provide it)
typedef struct _SCHANNEL_CRED {
    DWORD dwVersion;
    DWORD cCreds;
    PVOID *paCred;
    HCERTSTORE hRootStore;
    DWORD cMappers;
    PVOID *aphMappers;
    DWORD cSupportedAlgs;
    ALG_ID *palSupportedAlgs;
    DWORD grbitEnabledProtocols;
    DWORD dwMinimumCipherStrength;
    DWORD dwMaximumCipherStrength;
    DWORD dwSessionLifespan;
    DWORD dwFlags;
    DWORD dwCredFormat;
} SCHANNEL_CRED;

// GUI Elements
HWND hwnd, hChatBox, hMessageBox, hSendButton, hIPBox, hConnectButton, hWaitButton;
SOCKET global_socket;
CredHandle hCred;
CtxtHandle hCtxt;
int isServer = 0;

// Function Declarations
LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
DWORD WINAPI ServerThread(LPVOID param);
DWORD WINAPI ClientThread(LPVOID param);
void SendMessageGUI();
SECURITY_STATUS InitTLS(SOCKET sock, int isServer);
void CleanupTLS();

// Initialize TLS (Schannel)
SECURITY_STATUS InitTLS(SOCKET sock, int isServer) {
    SCHANNEL_CRED schCred;
    memset(&schCred, 0, sizeof(schCred));
    schCred.dwVersion = SCHANNEL_CRED_VERSION;
    schCred.grbitEnabledProtocols = SP_PROT_TLS1_2;

    return AcquireCredentialsHandle(
        NULL, UNISP_NAME, isServer ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND,
        NULL, &schCred, NULL, NULL, &hCred, NULL);
}

// GUI Layout
void CreateChatUI(HWND hwnd) {
    CreateWindow("STATIC", "IP Address:", WS_VISIBLE | WS_CHILD, 10, 10, 100, 20, hwnd, NULL, NULL, NULL);
    hIPBox = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER, 120, 10, 200, 20, hwnd, NULL, NULL, NULL);

    CreateWindow("STATIC", "Chat:", WS_VISIBLE | WS_CHILD, 10, 40, 100, 20, hwnd, NULL, NULL, NULL);
    hChatBox = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | ES_READONLY | WS_VSCROLL, 
                            10, 60, 380, 200, hwnd, NULL, NULL, NULL);

    CreateWindow("STATIC", "Message:", WS_VISIBLE | WS_CHILD, 10, 270, 100, 20, hwnd, NULL, NULL, NULL);
    hMessageBox = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER, 120, 270, 200, 20, hwnd, NULL, NULL, NULL);

    hSendButton = CreateWindow("BUTTON", "Send", WS_VISIBLE | WS_CHILD, 330, 270, 60, 20, hwnd, (HMENU)1, NULL, NULL);
    hConnectButton = CreateWindow("BUTTON", "Connect", WS_VISIBLE | WS_CHILD, 10, 300, 80, 30, hwnd, (HMENU)2, NULL, NULL);
    hWaitButton = CreateWindow("BUTTON", "Wait", WS_VISIBLE | WS_CHILD, 100, 300, 80, 30, hwnd, (HMENU)3, NULL, NULL);
}

// Main GUI Handler
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
        case WM_CREATE:
            CreateChatUI(hwnd);
            break;
        case WM_DESTROY:
            CleanupTLS();
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

// Server Function
DWORD WINAPI ServerThread(LPVOID param) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    SOCKET server_fd, client_socket;
    struct sockaddr_in server_addr, client_addr;
    int addr_size = sizeof(client_addr);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(server_fd, 1);

    client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addr_size);
    global_socket = client_socket;

    char buffer[BUFFER_SIZE];
    while (recv(global_socket, buffer, sizeof(buffer) - 1, 0) > 0) {
        strcat(buffer, "\r\n");
        SendMessage(hChatBox, EM_REPLACESEL, 0, (LPARAM)buffer);
    }

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

    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, ip, &server_addr.sin_addr);
    connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));
    global_socket = client_socket;

    char buffer[BUFFER_SIZE];
    while (recv(global_socket, buffer, sizeof(buffer) - 1, 0) > 0) {
        strcat(buffer, "\r\n");
        SendMessage(hChatBox, EM_REPLACESEL, 0, (LPARAM)buffer);
    }

    closesocket(client_socket);
    return 0;
}

// Sends a Message
void SendMessageGUI() {
    char buffer[BUFFER_SIZE];
    GetWindowText(hMessageBox, buffer, BUFFER_SIZE);
    send(global_socket, buffer, strlen(buffer), 0);
    strcat(buffer, " (You)\r\n");
    SendMessage(hChatBox, EM_REPLACESEL, 0, (LPARAM)buffer);
    SetWindowText(hMessageBox, "");
}

// Entry Point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "SecureChat";

    RegisterClass(&wc);
    hwnd = CreateWindow("SecureChat", "Secure Chat", WS_OVERLAPPEDWINDOW, 100, 100, 420, 380, NULL, NULL, hInstance, NULL);
    
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}

void CleanupTLS() {
    FreeCredentialsHandle(&hCred);
    DeleteSecurityContext(&hCtxt);
    WSACleanup();
}
