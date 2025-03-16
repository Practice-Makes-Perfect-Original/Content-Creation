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

// manually define SCHANNEL_CRED because mingw doesnt provide it
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

// Gui Elements
HWND hwnd, hChatBox, hMessageBox, hSendButton, hIPBox, hConnectButton, hWaitButton, hPortBox;
HBRUSH hbrBkgnd;
SOCKET global_socket;
CredHandle hCred;
CtxtHandle hCtxt;
int isServer = 0;

// Function declarations
LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
DWORD WINAPI ServerThread(LPVOID param);
DWORD WINAPI ClientThread(LPVOID param);
void SendMessageGUI();
SECURITY_STATUS InitTLS(SOCKET sock, int isServer);
void CleanupTLS();

// Initialize tls (Schannel)
SECURITY_STATUS InitTLS(SOCKET sock, int isServer) {
    SCHANNEL_CRED schCred;
    memset(&schCred, 0, sizeof(schCred));
    schCred.dwVersion = SCHANNEL_CRED_VERSION;
    schCred.grbitEnabledProtocols = SP_PROT_TLS1_2;

    return AcquireCredentialsHandle(
        NULL, UNISP_NAME, isServer ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND,
        NULL, &schCred, NULL, NULL, &hCred, NULL);
}

// gui Layout
void CreateChatUI(HWND hwnd) {
    CreateWindow("STATIC", "IP Address:", WS_VISIBLE | WS_CHILD, 10, 10, 100, 20, hwnd, NULL, NULL, NULL);
    hIPBox = CreateWindow("EDIT", "127.0.0.1", WS_VISIBLE | WS_CHILD | WS_BORDER, 120, 10, 200, 20, hwnd, NULL, NULL, NULL);

    CreateWindow("STATIC", "Port:", WS_VISIBLE | WS_CHILD, 10, 40, 100, 20, hwnd, NULL, NULL, NULL);
    hPortBox = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER, 120, 40, 200, 20, hwnd, NULL, NULL, NULL);

    CreateWindow("STATIC", "Chat:", WS_VISIBLE | WS_CHILD, 10, 70, 100, 20, hwnd, NULL, NULL, NULL);
    hChatBox = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | ES_READONLY | WS_VSCROLL, 
                            10, 90, 380, 200, hwnd, NULL, NULL, NULL);

    CreateWindow("STATIC", "Message:", WS_VISIBLE | WS_CHILD, 10, 300, 100, 20, hwnd, NULL, NULL, NULL);
    hMessageBox = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER, 120, 300, 200, 20, hwnd, NULL, NULL, NULL);

    hSendButton = CreateWindow("BUTTON", "Send", WS_VISIBLE | WS_CHILD, 330, 300, 60, 20, hwnd, (HMENU)1, NULL, NULL);
    hConnectButton = CreateWindow("BUTTON", "Connect", WS_VISIBLE | WS_CHILD, 10, 330, 80, 30, hwnd, (HMENU)2, NULL, NULL);
    hWaitButton = CreateWindow("BUTTON", "Wait", WS_VISIBLE | WS_CHILD, 100, 330, 80, 30, hwnd, (HMENU)3, NULL, NULL);
}



// Main gui handler
LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE:
            hbrBkgnd = CreateSolidBrush(RGB(30, 30, 30)); // Dark gray background
            CreateChatUI(hwnd);
            break;

        case WM_CTLCOLORSTATIC: // Change text color for static labels
        case WM_CTLCOLOREDIT:   // Change text color for edit boxes
        case WM_CTLCOLORBTN:    // Change button colors
        {
            HDC hdcStatic = (HDC)wParam;
            SetTextColor(hdcStatic, RGB(255, 255, 255)); // White text
            SetBkColor(hdcStatic, RGB(30, 30, 30)); // Dark background
            return (LRESULT)hbrBkgnd;
        }

        case WM_ERASEBKGND:
            FillRect((HDC)wParam, &((RECT){0, 0, 600, 500}), hbrBkgnd);
            return 1;

        case WM_DESTROY:
            DeleteObject(hbrBkgnd);
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}




//server function

DWORD WINAPI ServerThread(LPVOID param) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    SOCKET server_fd, client_socket;
    struct sockaddr_in server_addr, client_addr;
    int addr_size = sizeof(client_addr);
    int port;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == INVALID_SOCKET) {
        MessageBox(NULL, "Server socket creation failed!", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    srand(time(NULL)); // Generate a random port
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    do {
        port = rand() % 1000 + 4000; // Random port between 4000-5000
        server_addr.sin_port = htons(port);
    } while (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR);

    // **Show chosen port in GUI**
    char port_msg[50];
    sprintf(port_msg, "%d", port);
    SetWindowText(hPortBox, port_msg); // Update the port field in the GUI

    // copy the port number to clipboard**
    OpenClipboard(NULL);
    EmptyClipboard();
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, strlen(port_msg) + 1);
    memcpy(GlobalLock(hMem), port_msg, strlen(port_msg) + 1);
    GlobalUnlock(hMem);
    SetClipboardData(CF_TEXT, hMem);
    CloseClipboard();

    MessageBox(NULL, "Port copied to clipboard!", "Info", MB_OK | MB_ICONINFORMATION);

    if (listen(server_fd, SOMAXCONN) == SOCKET_ERROR) {
        MessageBox(NULL, "Listen failed!", "Error", MB_OK | MB_ICONERROR);
        closesocket(server_fd);
        return 1;
    }

    client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addr_size);
    if (client_socket == INVALID_SOCKET) {
        MessageBox(NULL, "Client connection failed!", "Error", MB_OK | MB_ICONERROR);
        closesocket(server_fd);
        return 1;
    }

    global_socket = client_socket; // Store globally

    char buffer[BUFFER_SIZE];
    int bytes_read;

    while ((bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes_read] = '\0';

        SendMessage(hChatBox, EM_SETSEL, -1, -1);
        SendMessage(hChatBox, EM_REPLACESEL, 0, (LPARAM)buffer);
        SendMessage(hChatBox, EM_REPLACESEL, 0, (LPARAM)"\r\n");

        send(client_socket, buffer, strlen(buffer), 0);
    }

    closesocket(client_socket);
    closesocket(server_fd);
    return 0;
}






//client function
DWORD WINAPI ClientThread(LPVOID param) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    char ip[INET_ADDRSTRLEN];
    char port_str[6];

    // get IP and port from user input**
    GetWindowText(hIPBox, ip, INET_ADDRSTRLEN);
    GetWindowText(hPortBox, port_str, 6); // Get port from the input field
    int port = atoi(port_str); // Convert to integer

    if (port <= 0) {
        MessageBox(NULL, "Invalid port!", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    SOCKET client_socket;
    struct sockaddr_in server_addr;

    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == INVALID_SOCKET) {
        MessageBox(NULL, "Client socket creation failed!", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        MessageBox(NULL, "Invalid IP address!", "Error", MB_OK | MB_ICONERROR);
        closesocket(client_socket);
        return 1;
    }

    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        MessageBox(NULL, "Failed to connect to server!", "Error", MB_OK | MB_ICONERROR);
        closesocket(client_socket);
        return 1;
    }

    global_socket = client_socket; // Store globally

    char buffer[BUFFER_SIZE];
    int bytes_read;

    while ((bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes_read] = '\0';

        SendMessage(hChatBox, EM_SETSEL, -1, -1);
        SendMessage(hChatBox, EM_REPLACESEL, 0, (LPARAM)buffer);
        SendMessage(hChatBox, EM_REPLACESEL, 0, (LPARAM)"\r\n");
    }

    closesocket(client_socket);
    return 0;
}




void SendMessageGUI() {
    char buffer[BUFFER_SIZE];
    GetWindowText(hMessageBox, buffer, BUFFER_SIZE);

    // Check if message is empty
    if (strlen(buffer) == 0) {
        return; // Don't send empty messages
    }

    // Check if socket is valid
    if (global_socket == INVALID_SOCKET) {
        MessageBox(NULL, "Not connected to a server!", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Send the message
    int sent = send(global_socket, buffer, strlen(buffer), 0);
    if (sent == SOCKET_ERROR) {
        MessageBox(NULL, "Failed to send message!", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Append "You" to show it was sent by this user
    strcat(buffer, " (You)\r\n");

    // Safely update chat box**
    SendMessage(hChatBox, EM_SETSEL, -1, -1);  // Move cursor to end
    SendMessage(hChatBox, EM_REPLACESEL, 0, (LPARAM)buffer);

    SetWindowText(hMessageBox, ""); // Clear input field after sending
}

// Entry Point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "SecureChat";

    RegisterClass(&wc);
    hwnd = CreateWindow("SecureChat", "Secure Chat", WS_OVERLAPPEDWINDOW, 100, 100, 420, 400, NULL, NULL, hInstance, NULL);
    
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
