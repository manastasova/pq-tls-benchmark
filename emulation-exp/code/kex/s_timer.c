/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <s2n.h>

#define CLI_AUTH_REQ
#define SERV_VERIF_DISABLE

#define UNUSED(x) (void)(x)

#define NS_IN_MS 1000000.0
#define MS_IN_S 1000
#define SOCKERR -1

const char* host = "10.0.0.1";

int do_tls_handshake(struct s2n_connection *conn)
{
    int sockfd = -1;
    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "Error: Could not create socket\n");
        return SOCKERR;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, '\0', sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(4433);

    if(inet_pton(AF_INET, host, &serv_addr.sin_addr) < 1) {
        fprintf(stderr, "Error: inet_pton failed\n");
        return SOCKERR;
    }

    if(connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
       fprintf(stderr, "Error: connect failed with %s\n", strerror(errno));
       return SOCKERR;
    }

    struct linger no_linger = {.l_onoff = 1, .l_linger = 0};
    if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, (char*)&no_linger, sizeof(no_linger)) < 0) {
        fprintf(stderr, "Error: setting LINGER=0 sockopt failed with %s\n", strerror(errno));
        close(sockfd);
        return SOCKERR;
    }

     int state = 1;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &state, sizeof(state)) < 0) {
        fprintf(stderr, "Error: setting TCP_NODELAY sockopt failed with %s\n", strerror(errno));
        close(sockfd);
        return SOCKERR;
    }

    if (setsockopt(sockfd, IPPROTO_TCP, TCP_QUICKACK, &state, sizeof(state)) < 0) {
        fprintf(stderr, "Error: setting TCP_QUICKACK sockopt failed with %s\n", strerror(errno));
        close(sockfd);
        return SOCKERR;
    }

    if (s2n_connection_set_fd(conn, sockfd) != S2N_SUCCESS) {
        fprintf(stderr, "Error: failed to set fd on connection. %s: %s\n",
                s2n_strerror(s2n_errno, NULL), s2n_strerror_debug(s2n_errno, NULL));
        close(sockfd);
        return SOCKERR;
    }

    s2n_blocked_status blocked;
    while (s2n_negotiate(conn, &blocked) != S2N_SUCCESS) {
        if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
            fprintf(stderr, "Error: failed to negotiate. %s: %s\n",
            s2n_strerror(s2n_errno, NULL), s2n_strerror_debug(s2n_errno, NULL));
            close(sockfd);
            return SOCKERR;
        }

    }

    // Unset TCP_QUICKACK after the handshake completes
    state = 0;
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_QUICKACK, &state, sizeof(state)) < 0) {
        fprintf(stderr, "Error: unsetting TCP_QUICKACK sockopt failed with %s\n", strerror(errno));
        close(sockfd);
        return SOCKERR;
    }

    return sockfd;
}

int request_body(struct s2n_connection *conn, uint32_t n_bytes) {
    char req[1024];
    for (size_t i = 0; i < sizeof(req); i++) {
        req[i] = '\0';
    }
    const char *fmt = "GET /?q=%u HTTP/1.1\r\n\r\n";
    sprintf(req, fmt, n_bytes);
    s2n_blocked_status blocked;
    size_t bytes_written = s2n_send(conn, req, strlen(req), &blocked);
    return bytes_written == strlen(req) ? S2N_SUCCESS : S2N_FAILURE;
}

int read_body(struct s2n_connection *conn, int n_bytes) {
    int total_recieved = -1;
    int content_length = -1;
    int recieved;
    uint8_t buffer[65536];
    s2n_blocked_status unused;
    while ((recieved = s2n_recv(conn, buffer, sizeof(buffer), &unused)) > 0) {
        if (s2n_error_get_type(s2n_errno) == S2N_ERR_T_BLOCKED) {
            continue;
        }
        if (recieved < 0) {
            fprintf(stderr, "Error reading HTTP response: %s. %s\n", s2n_strerror(s2n_errno, NULL), s2n_strerror_debug(s2n_errno, NULL));
            return errno;
        }
        buffer[recieved] = 0;
        if (total_recieved < 0) {
            if (content_length < 0) {
                const char *content_len_header = "Content-Length: ";
                char *substr = strstr((char*) buffer, content_len_header);
                if (!substr) {
                    continue;
                }
                content_length = strtol(substr + strlen(content_len_header), NULL, 10);
            } else if (strstr((char*) buffer, "\r\n") == (char*) buffer) {
                total_recieved = 0;
            }
        } else {
            total_recieved += recieved;
        }
        if (total_recieved == content_length) {
            break;
        }
    }

    return n_bytes == total_recieved ? S2N_SUCCESS : S2N_FAILURE;
}

uint8_t verify_host(const char *host_name, size_t host_name_len, void *data) {
    UNUSED(host_name);
    UNUSED(host_name_len);
    UNUSED(data);
    return 1;
}

char *load_file_to_cstring(const char *path)
{
    FILE *pem_file = fopen(path, "rb");
    if (!pem_file) {
        fprintf(stderr, "Failed to open file %s: '%s'\n", path, strerror(errno));
        return NULL;
    }

    /* Make sure we can fit the pem into the output buffer */
    if (fseek(pem_file, 0, SEEK_END) < 0) {
        fprintf(stderr, "Failed calling fseek: '%s'\n", strerror(errno));
        fclose(pem_file);
        return NULL;
    }

    const ssize_t pem_file_size = ftell(pem_file);
    if (pem_file_size < 0) {
        fprintf(stderr, "Failed calling ftell: '%s'\n", strerror(errno));
        fclose(pem_file);
        return NULL;
    }

    rewind(pem_file);

    char *pem_out = malloc(pem_file_size + 1);
    if (pem_out == NULL) {
        fprintf(stderr, "Failed allocating memory\n");
        fclose(pem_file);
        return NULL;
    }

    if (fread(pem_out, sizeof(char), pem_file_size, pem_file) < (size_t) pem_file_size) {
        fprintf(stderr, "Failed reading file: '%s'\n", strerror(errno));
        free(pem_out);
        fclose(pem_file);
        return NULL;
    }

    pem_out[pem_file_size] = '\0';
    fclose(pem_file);

    return pem_out;
}

int main(int argc, char* argv[])
{
    int ret = -1;
    if(argc != 4)
    {
        fprintf(stderr, "Usage: %s <security_policy> <measurements> <n_bytes>\n", argv[0]);
        return 1;
    }

    const char* security_policy = argv[1];
    const size_t measurements = strtol(argv[2], 0, 10);
    const uint32_t n_bytes = strtol(argv[3], 0, 10);

    s2n_init();

    struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
    if (conn == NULL) {
        fprintf(stderr, "Error: failed to allocate new connection\n");
        goto s2n_err;
    }

    struct s2n_config *config = s2n_config_new();
    if (config == NULL) {
        fprintf(stderr, "Error: failed to allocate new config\n");
        goto s2n_err;
    }

    if (s2n_config_wipe_trust_store(config)) {
        fprintf(stderr, "Error: failed to wipe trust store on config\n");
        goto s2n_err;
    }

    const char* trust_store_dir = NULL;
    const char* trust_store_path = "../certs/CA.crt";
    //  const char* trust_store_path = "../certs/new_certs/ca_rsa4096_cert.pem";
    if (s2n_config_set_verification_ca_location(config, trust_store_dir, trust_store_path)) {
        fprintf(stderr, "Error: failed to set trust store on config\n");
        goto s2n_err;
    }

    if (s2n_config_set_cipher_preferences(config, security_policy)) {
        fprintf(stderr, "Error: failed to set security policy on config\n");
        goto s2n_err;
    }
    
    #ifdef CLI_AUTH_REQ
    s2n_config_set_client_auth_type(config, S2N_CERT_AUTH_REQUIRED);

    // set client certificates as needed (X in {2, 18,22}KB)
    const char *client_cert_path = "../certs/client-cas_3KB.pem";
    const char *client_key_path = "../certs/client-key.pem";

    // Load the file into a string
    char *client_cert = load_file_to_cstring(client_cert_path);
    char *client_key  = load_file_to_cstring(client_key_path);

    struct s2n_cert_chain_and_key *chain_and_key = s2n_cert_chain_and_key_new();
    s2n_cert_chain_and_key_load_pem(chain_and_key, client_cert, client_key);
    s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key);

    #else
    s2n_config_set_client_auth_type(config, S2N_CERT_AUTH_NONE);
    #endif

    #ifdef SERV_VERIF_DISABLE
    if (s2n_config_disable_x509_verification(config) != S2N_SUCCESS) {
        fprintf(stderr, "Error: s2n_config_disable_x509_verification %s\n", strerror(errno));
        exit(1);
    }
    #endif
    s2n_config_set_verify_host_callback(config, verify_host, NULL);

    

    if (s2n_connection_set_config(conn, config)) {
        fprintf(stderr, "Error: failed to set config on connection\n");
        goto s2n_err;
    }

    const int warmup_conns = 3;
    struct timespec start, finish;
    for (int i = -1 * warmup_conns; i < (int) measurements; i++) {
        //usleep(((rand() % 10) + 1) * 1000);    // sleep between 1 and 10ms
        clock_gettime(CLOCK_MONOTONIC_RAW, &start);
        int sockfd = do_tls_handshake(conn);
        if (sockfd == SOCKERR) {
            /* Retry since at high packet loss rates,
             * the connect() syscall fails sometimes.
             * Non-retryable errors are caught by manual
             * inspection of logs, which has sufficed
             * for our purposes */
            continue;
        }
        size_t recv_buf_size = 1024 * 100;
        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &recv_buf_size, sizeof(recv_buf_size)) < 0) {
        perror("Failed to set receive buffer size");
        close(sockfd);
        exit(1);
        }

        if (n_bytes > 0) {
            if (request_body(conn, n_bytes) != S2N_SUCCESS) {
                fprintf(stderr, "Error: error requesting %u bytes: %s\n", n_bytes, strerror(errno));
                goto err;
            }
            if (read_body(conn, n_bytes) != S2N_SUCCESS) {
                fprintf(stderr, "Error: error reading body: %s\n", strerror(errno));
                goto err;
            }
        }
        
        
        struct tcp_info info;
        size_t info_len;
        if (getsockopt(sockfd, SOL_TCP, TCP_INFO, &info, (socklen_t*) &info_len) < 0) {
            fprintf(stderr, "Error: cannot get TCP info with error %s\n", strerror(errno));
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &finish);

        s2n_blocked_status unused;
        if(s2n_shutdown(conn, &unused) != S2N_SUCCESS || s2n_connection_wipe(conn) != S2N_SUCCESS) {
            close(sockfd);
            goto s2n_err;
        }
        
        if (close(sockfd)) {
            fprintf(stderr, "Error: socket shutdown failed with error %s\n", strerror(errno));
            goto err;
        }

        // no output on warmup run
        if (i < 0) {
            continue;
        }

        const double handshake_time_ms = ((finish.tv_sec - start.tv_sec) * MS_IN_S) + ((finish.tv_nsec - start.tv_nsec) / NS_IN_MS);

        printf("%f,%u,%u,%u\n",
                handshake_time_ms,
                info.tcpi_retransmits,
                info.tcpi_retrans,
                info.tcpi_total_retrans
        );
    }

    ret = 0;
    goto end;

s2n_err:
    fprintf(stderr, "Error: Unrecoverable s2n error. %s: %s\n",
            s2n_strerror(s2n_errno, NULL), s2n_strerror_debug(s2n_errno, NULL));
err:
    ret = 1;
end:
    if (conn) {
        s2n_connection_free(conn);
    }
    if (config) {
        s2n_config_free(config);
    }
    s2n_cleanup();
    return ret;
}
