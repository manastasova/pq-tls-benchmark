/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
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

#define NS_IN_MS 1000000.0
#define MS_IN_S 1000
#define SOCKERR -1
#define TCP_ACK_TIMEOUT_MS 5000
#define TCP_ACK_POLL_INTERVAL_US 100

const char* host = "10.0.0.1";
const int port = 4433;

int do_tls_handshake(struct s2n_connection *conn)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Error: Could not create socket\n");
        return SOCKERR;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, '\0', sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &serv_addr.sin_addr) < 1) {
        fprintf(stderr, "Error: inet_pton failed\n");
        close(sockfd);
        return SOCKERR;
    }

    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        fprintf(stderr, "Error: connect failed with %s\n", strerror(errno));
        close(sockfd);
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

    /* Wait for all sent data (including client cert) to be acknowledged by peer */
    struct timespec poll_start, poll_current;
    clock_gettime(CLOCK_MONOTONIC_RAW, &poll_start);
    
    struct tcp_info tcp_info;
    socklen_t tcp_info_len = sizeof(tcp_info);
    int total_wait_ms = 0;
    
    while (1) {
        if (getsockopt(sockfd, IPPROTO_TCP, TCP_INFO, &tcp_info, &tcp_info_len) < 0) {
            fprintf(stderr, "Warning: cannot get TCP info during ACK polling: %s\n", strerror(errno));
            break;
        }
        
        /* Check if all data has been acknowledged */
        if (tcp_info.tcpi_unacked == 0) {
            break;
        }
        
        /* Check for timeout */
        clock_gettime(CLOCK_MONOTONIC_RAW, &poll_current);
        total_wait_ms = ((poll_current.tv_sec - poll_start.tv_sec) * MS_IN_S) + 
                        ((poll_current.tv_nsec - poll_start.tv_nsec) / NS_IN_MS);
        
        if (total_wait_ms > TCP_ACK_TIMEOUT_MS) {
            fprintf(stderr, "Warning: TCP ACK timeout after %d ms (unacked=%u)\n", 
                    total_wait_ms, tcp_info.tcpi_unacked);
            break;
        }
        
        /* Sleep briefly before polling again */
        usleep(TCP_ACK_POLL_INTERVAL_US);
    }

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
    memset(req, '\0', sizeof(req));
    snprintf(req, sizeof(req), "GET /?q=%u HTTP/1.1\r\n\r\n", n_bytes);
    
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
            fprintf(stderr, "Error reading HTTP response: %s. %s\n", 
                    s2n_strerror(s2n_errno, NULL), s2n_strerror_debug(s2n_errno, NULL));
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

char *load_file_to_cstring(const char *path)
{
    FILE *file = fopen(path, "rb");
    if (!file) {
        fprintf(stderr, "Failed to open file %s: '%s'\n", path, strerror(errno));
        return NULL;
    }

    if (fseek(file, 0, SEEK_END) < 0) {
        fprintf(stderr, "Failed calling fseek: '%s'\n", strerror(errno));
        fclose(file);
        return NULL;
    }

    const ssize_t file_size = ftell(file);
    if (file_size < 0) {
        fprintf(stderr, "Failed calling ftell: '%s'\n", strerror(errno));
        fclose(file);
        return NULL;
    }

    rewind(file);

    char *content = malloc(file_size + 1);
    if (!content) {
        fprintf(stderr, "Failed allocating memory\n");
        fclose(file);
        return NULL;
    }

    if (fread(content, sizeof(char), file_size, file) < (size_t) file_size) {
        fprintf(stderr, "Failed reading file: '%s'\n", strerror(errno));
        free(content);
        fclose(file);
        return NULL;
    }

    content[file_size] = '\0';
    fclose(file);

    return content;
}

int main(int argc, char* argv[])
{
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <security_policy> <measurements> <n_bytes>\n", argv[0]);
        return 1;
    }

    const char* security_policy = argv[1];
    const size_t measurements = strtol(argv[2], NULL, 10);
    const uint32_t n_bytes = strtol(argv[3], NULL, 10);

    if (s2n_init() != S2N_SUCCESS) {
        fprintf(stderr, "Error: s2n_init failed\n");
        return 1;
    }

    struct s2n_config *config = s2n_config_new();
    if (!config) {
        fprintf(stderr, "Error: failed to allocate new config\n");
        goto error;
    }

    if (s2n_config_wipe_trust_store(config) != S2N_SUCCESS) {
        fprintf(stderr, "Error: failed to wipe trust store on config\n");
        goto error;
    }

    const char* trust_store_path = "/home/ubuntu/pq-tls-benchmark/emulation-exp/code/mldsa_certs/root_ca_cert.pem";
    if (s2n_config_set_verification_ca_location(config, trust_store_path, NULL) != S2N_SUCCESS) {
        fprintf(stderr, "Error: failed to set trust store on config\n");
        goto error;
    }

    if (s2n_config_set_cipher_preferences(config, security_policy) != S2N_SUCCESS) {
        fprintf(stderr, "Error: failed to set security policy on config\n");
        goto error;
    }

    const char *client_cert_path = "/home/ubuntu/pq-tls-benchmark/emulation-exp/code/mldsa_certs/client_certificate_chain.pem";
    const char *client_key_path = "/home/ubuntu/pq-tls-benchmark/emulation-exp/code/mldsa_certs/client_key.pem";

    char *client_cert = load_file_to_cstring(client_cert_path);
    char *client_key = load_file_to_cstring(client_key_path);
    if (!client_cert || !client_key) {
        fprintf(stderr, "Error: failed to load client certificate or key\n");
        goto error;
    }

    struct s2n_cert_chain_and_key *chain_and_key = s2n_cert_chain_and_key_new();
    if (!chain_and_key) {
        fprintf(stderr, "Error: failed to allocate cert chain and key\n");
        free(client_cert);
        free(client_key);
        goto error;
    }

    if (s2n_cert_chain_and_key_load_pem(chain_and_key, client_cert, client_key) != S2N_SUCCESS) {
        fprintf(stderr, "Error: failed to load cert chain and key\n");
        free(client_cert);
        free(client_key);
        goto error;
    }

    if (s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key) != S2N_SUCCESS) {
        fprintf(stderr, "Error: failed to add cert chain to config\n");
        free(client_cert);
        free(client_key);
        goto error;
    }

    free(client_cert);
    free(client_key);

    struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
    if (!conn) {
        fprintf(stderr, "Error: failed to allocate new connection\n");
        goto error;
    }

    if (s2n_connection_set_config(conn, config) != S2N_SUCCESS) {
        fprintf(stderr, "Error: failed to set config on connection\n");
        goto error;
    }

    const int warmup_conns = 3;
    struct timespec start, finish;
    
    for (int i = -warmup_conns; i < (int) measurements; i++) {
        if (s2n_set_server_name(conn, "localhost") != S2N_SUCCESS) {
            fprintf(stderr, "Error: failed to set server name on connection\n");
            goto error;
        }

        clock_gettime(CLOCK_MONOTONIC_RAW, &start);
        int sockfd = do_tls_handshake(conn);
        if (sockfd == SOCKERR) {
            continue;
        }

        size_t recv_buf_size = 1024 * 1000;
        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &recv_buf_size, sizeof(recv_buf_size)) < 0) {
            perror("Failed to set receive buffer size");
            close(sockfd);
            goto error;
        }

        if (n_bytes > 0) {
            if (request_body(conn, n_bytes) != S2N_SUCCESS) {
                fprintf(stderr, "Error: error requesting %u bytes: %s\n", n_bytes, strerror(errno));
                close(sockfd);
                goto error;
            }
            if (read_body(conn, n_bytes) != S2N_SUCCESS) {
                fprintf(stderr, "Error: error reading body: %s\n", strerror(errno));
                close(sockfd);
                goto error;
            }
        }

        struct tcp_info info;
        socklen_t info_len = sizeof(info);
        if (getsockopt(sockfd, SOL_TCP, TCP_INFO, &info, &info_len) < 0) {
            fprintf(stderr, "Error: cannot get TCP info with error %s\n", strerror(errno));
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &finish);

        s2n_blocked_status unused;
        if (s2n_shutdown(conn, &unused) != S2N_SUCCESS || s2n_connection_wipe(conn) != S2N_SUCCESS) {
            close(sockfd);
            goto error;
        }

        if (close(sockfd) != 0) {
            fprintf(stderr, "Error: socket shutdown failed with error %s\n", strerror(errno));
            goto error;
        }

        if (i < 0) {
            continue;
        }

        const double handshake_time_ms = ((finish.tv_sec - start.tv_sec) * MS_IN_S) + 
                                         ((finish.tv_nsec - start.tv_nsec) / NS_IN_MS);

        printf("%f,%u,%u,%u\n",
                handshake_time_ms,
                info.tcpi_retransmits,
                info.tcpi_retrans,
                info.tcpi_total_retrans);
    }

    s2n_connection_free(conn);
    s2n_config_free(config);
    s2n_cleanup();
    return 0;

error:
    fprintf(stderr, "Error: Unrecoverable s2n error. %s: %s\n",
            s2n_strerror(s2n_errno, NULL), s2n_strerror_debug(s2n_errno, NULL));
    if (conn) {
        s2n_connection_free(conn);
    }
    if (config) {
        s2n_config_free(config);
    }
    s2n_cleanup();
    return 1;
}
