#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <arpa/inet.h>
#include <unistd.h>


void InitOpenSSL() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void CleanupOpenSSL() {
    EVP_cleanup();
}

SSL_CTX* CreateClientContext() {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);

    if (!ctx) {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void ConfigureClientContext(SSL_CTX* ctx) {
	const char* cert_path = "../cert/server.crt";
    
	if (!SSL_CTX_load_verify_locations(ctx, cert_path, nullptr)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int add_custom_ext_cb(SSL *ssl, unsigned int ext_type, unsigned int context,
                      const unsigned char **out, size_t *outlen, X509 *x,
                      size_t chainidx, int *al, void *add_arg) {
    const char *extension_data = static_cast<const char*>(add_arg);
    *out = (unsigned char *)extension_data;
    *outlen = strlen(extension_data);
    return 1;  // Success
}

int parse_custom_ext_cb(SSL *ssl, unsigned int ext_type, unsigned int context,
                        const unsigned char *in, size_t inlen, X509 *x,
                        size_t chainidx, int *al, void *parse_arg) {
    std::cout << "Received custom extension data: "
          << std::string(reinterpret_cast<const char*>(in), inlen) 
          << std::endl;
    return 1;  // Success
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <port> <extension_type> <extension_data>" << std::endl;
        return EXIT_FAILURE;
    }

    const char* server_ip = argv[1];
    int port = std::stoi(argv[2]);
	int extension_type = std::stoi(argv[3]);
    const char* extension_data = argv[4];
    
    SSL_CTX* ctx;

    InitOpenSSL();
    ctx = CreateClientContext();

    SSL_CTX_add_custom_ext(ctx, extension_type, SSL_EXT_CLIENT_HELLO,
                            add_custom_ext_cb, NULL, (void*)extension_data,
                            parse_custom_ext_cb, NULL);


    ConfigureClientContext(ctx);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip, &addr.sin_addr);

    if (connect(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to connect");
        exit(EXIT_FAILURE);
    }

    SSL* ssl = SSL_new(ctx);

    SSL_set_fd(ssl, server_fd);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        std::string request = "GET /tls/ HTTP/1.1\r\nHost: " + std::string(server_ip) + "\r\nConnection: close\r\n\r\n";
        SSL_write(ssl, request.c_str(), request.size());

        char reply[1024];
        int bytes = SSL_read(ssl, reply, sizeof(reply));
        std::cout << "Bytes: " << bytes << std::endl;

        if (bytes < 0) {
            int error = SSL_get_error(ssl, bytes);
            switch (error) {
                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_WRITE:
                    std::cerr << "SSL_read wants to be called again" << std::endl;
                    break;
                case SSL_ERROR_SYSCALL:
                    std::cerr << "SSL_read syscall error: " << strerror(errno) << std::endl;
                    break;
                case SSL_ERROR_ZERO_RETURN:
                    std::cerr << "SSL connection was closed" << std::endl;
                    break;
                default:
                    std::cerr << "SSL_read failed with error code: " << error << std::endl;
                    ERR_print_errors_fp(stderr);
            }  
        } 

        if (bytes == 0) {
            std::cerr << "SSL connection closed by the server" << std::endl;
        }

        if (bytes > 0) {
            reply[bytes] = 0;
            std::cout << "Received: " << reply << std::endl;
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(server_fd);
    SSL_CTX_free(ctx);
    CleanupOpenSSL();
}
