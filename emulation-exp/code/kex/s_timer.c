/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <s2n.h>

#include <time.h>

#define NS_IN_MS 1000000.0
#define MS_IN_S 1000

const char* host = "10.0.0.1";

int do_tls_handshake(struct s2n_connection *conn)
{
    int sockfd = -1;
    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "Error: Could not create socket\n");
        return -1;
    } 

    struct sockaddr_in serv_addr; 
    memset(&serv_addr, '\0', sizeof(serv_addr)); 

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(4433); 

    if(inet_pton(AF_INET, host, &serv_addr.sin_addr) <= 0) {
        fprintf(stderr, "Error: inet_pton failed\n");
        return -1;
    } 

    if(connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
       fprintf(stderr, "Error: connect failed\n");
       return -1;
    } 

    struct linger no_linger = {.l_onoff = 1, .l_linger = 0};
    if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, (char*)&no_linger, sizeof(no_linger)) < 0) {
        fprintf(stderr, "Error: setting LINGER=0 sockopt failed");
        return -1;
    }

    s2n_blocked_status blocked = S2N_BLOCKED;
    if (s2n_negotiate(conn, &blocked) != S2N_SUCCESS) {
        fprintf(stderr, "Error: %s. %s\n", s2n_strerror(s2n_errno, NULL), s2n_strerror_debug(s2n_errno, NULL));
        return -1;
    }

    return 0;
}

int main(int argc, char* argv[])
{
    int ret = -1;
    SSL_CTX* ssl_ctx = 0;
    if(argc != 3)
    {
        fprintf(stderr, "Wrong number of arguments.\n");
        goto end;
    }
    const char* kex_alg = argv[1];
    const size_t measurements_to_make = strtol(argv[2], 0, 10);
    size_t measurements = 0;

    const char* ciphersuites = "TLS_AES_256_GCM_SHA384";
    const SSL_METHOD* ssl_meth = TLS_client_method();
    SSL* ssl = NULL;

    struct timespec start, finish;
    double* handshake_times_ms = malloc(measurements_to_make * sizeof(*handshake_times_ms));

    ssl_ctx = SSL_CTX_new(ssl_meth);
    if (!ssl_ctx)
    {
        goto ossl_error;
    }

    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_quiet_shutdown(ssl_ctx, 1);

    ret = SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
    if (ret != 1)
    {
        goto ossl_error;
    }

    ret = SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
    if (ret != 1)
    {
        goto ossl_error;
    }

    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_COMPRESSION);

    ret = SSL_CTX_set_ciphersuites(ssl_ctx, ciphersuites);
    if (ret != 1)
    {
        goto ossl_error;
    }
    ret = SSL_CTX_set1_groups_list(ssl_ctx, kex_alg);
    if (ret != 1)
    {
        goto ossl_error;
    }

    ret = SSL_CTX_load_verify_locations(ssl_ctx, "../tmp/nginx/conf/CA.crt", 0);
    if(ret != 1)
    {
        goto ossl_error;
    }
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    struct *s2n_config = s2n_config_new();
    // TODO: point this at the trust store?
    s2n_config_set_cipher_preferences("PQ-TLS-1-3-2023-06-01");

    while(measurements < measurements_to_make)
    {
        clock_gettime(CLOCK_MONOTONIC_RAW, &start);
        ssl = do_tls_handshake(ssl_ctx);
        clock_gettime(CLOCK_MONOTONIC_RAW, &finish);
        if (!ssl)
        {
            /* Retry since at high packet loss rates,
             * the connect() syscall fails sometimes.
             * Non-retryable errors are caught by manual
             * inspection of logs, which has sufficed
             * for our purposes */
            continue;
        }

        SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        ret = BIO_closesocket(SSL_get_fd(ssl));
        if(ret == -1)
        {
            goto ossl_error;
        }

        SSL_free(ssl);

        handshake_times_ms[measurements] = ((finish.tv_sec - start.tv_sec) * MS_IN_S) + ((finish.tv_nsec - start.tv_nsec) / NS_IN_MS);
        measurements++;
    }

    for(size_t i = 0; i < measurements - 1; i++)
    {
        printf("%f,", handshake_times_ms[i]);
    }
    printf("%f", handshake_times_ms[measurements - 1]);

    ret = 0;
    goto end;

ossl_error:
    fprintf(stderr, "Unrecoverable OpenSSL error.\n");
    ERR_print_errors_fp(stderr);
end:
    SSL_CTX_free(ssl_ctx);
    return ret;
}
