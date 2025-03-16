#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#define PORT 4444
#define BUFFER_SIZE 1024

typedef struct {
    int socket;
    SSL *ssl;
} chat_t;

SSL_CTX *server_ctx, *client_ctx;

void cleanup_files();
void generate_self_signed_cert(const char *cert_file, const char *key_file);
SSL_CTX *initialize_server_ssl();
SSL_CTX *initialize_client_ssl();
void *receive_messages(void *arg);
void *send_messages(void *arg);
void start_server();
void start_client(const char *ip);

void generate_self_signed_cert(const char *cert_file, const char *key_file) {
    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    EVP_PKEY *pkey = EVP_PKEY_new();
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

    X509_free(x509);
    EVP_PKEY_free(pkey);
}

SSL_CTX *initialize_server_ssl() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    generate_self_signed_cert("temp_chat.crt", "temp_chat.key");

    if (SSL_CTX_use_certificate_file(ctx, "temp_chat.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "temp_chat.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
        }

        return ctx;
}

SSL_CTX *initialize_client_ssl() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void *receive_messages(void *arg) {
    chat_t *chat = (chat_t *)arg;
    char buffer[BUFFER_SIZE];
    int bytes_read;

    while ((bytes_read = SSL_read(chat->ssl, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        printf("\n[Received]: %s\n> ", buffer);
        fflush(stdout);
    }

    printf("\nConnection closed.\n");
    SSL_shutdown(chat->ssl);
    SSL_free(chat->ssl);
    close(chat->socket);
    cleanup_files();
    exit(0);
}

void *send_messages(void *arg) {
    chat_t *chat = (chat_t *)arg;
    char buffer[BUFFER_SIZE];

    while (1) {
        printf("> ");
        fgets(buffer, BUFFER_SIZE, stdin);
        buffer[strcspn(buffer, "\n")] = 0;

        if (strlen(buffer) > 0) {
            SSL_write(chat->ssl, buffer, strlen(buffer));
        }
    }
}

void start_server() {
    int server_fd, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_size = sizeof(client_addr);
    pthread_t tid_recv, tid_send;

    server_ctx = initialize_server_ssl();
    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(server_fd, 1);

    printf("Waiting for a chat connection on port %d...\n", PORT);
    client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addr_size);

    SSL *ssl = SSL_new(server_ctx);
    SSL_set_fd(ssl, client_socket);
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(client_socket);
        SSL_free(ssl);
        return;
    }

    chat_t chat = {client_socket, ssl};
    pthread_create(&tid_recv, NULL, receive_messages, &chat);
    pthread_create(&tid_send, NULL, send_messages, &chat);

    pthread_join(tid_recv, NULL);
    pthread_join(tid_send, NULL);
}

void start_client(const char *ip) {
    int client_socket;
    struct sockaddr_in server_addr;
    pthread_t tid_recv, tid_send;

    client_ctx = initialize_client_ssl();
    client_socket = socket(AF_INET, SOCK_STREAM, 0);

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, ip, &server_addr.sin_addr);

    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        return;
    }

    SSL *ssl = SSL_new(client_ctx);
    SSL_set_fd(ssl, client_socket);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(client_socket);
        SSL_free(ssl);
        return;
    }

    chat_t chat = {client_socket, ssl};
    pthread_create(&tid_recv, NULL, receive_messages, &chat);
    pthread_create(&tid_send, NULL, send_messages, &chat);

    pthread_join(tid_recv, NULL);
    pthread_join(tid_send, NULL);
}

void cleanup_files() {
    remove("temp_chat.crt");
    remove("temp_chat.key");
}

int main() {
    int choice;
    char ip[INET_ADDRSTRLEN];

    printf("1. Initiate chat\n2. Wait for chat\nSelect: ");
    scanf("%d", &choice);
    getchar();

    SSL_library_init();

    if (choice == 1) {
        printf("Enter IP to connect: ");
        scanf("%s", ip);
        start_client(ip);
    } else if (choice == 2) {
        start_server();
    } else {
        printf("Invalid choice.\n");
    }

    return 0;
}
