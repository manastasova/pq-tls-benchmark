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
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include <s2n.h>

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

    if(inet_pton(AF_INET, host, &serv_addr.sin_addr) < 1) {
        fprintf(stderr, "Error: inet_pton failed\n");
        return -1;
    } 

    if(connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
       fprintf(stderr, "Error: connect failed with %s\n", strerror(errno));
       return errno;
    } 

    struct linger no_linger = {.l_onoff = 1, .l_linger = 0};
    if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, (char*)&no_linger, sizeof(no_linger)) < 0) {
        fprintf(stderr, "Error: setting LINGER=0 sockopt failed with %s\n", strerror(errno));
        return errno;
    }

    if (s2n_connection_set_fd(conn, sockfd) != S2N_SUCCESS) {
        fprintf(stderr, "Error: failed to set fd on connection. %s: %s\n",
                s2n_strerror(s2n_errno, NULL), s2n_strerror_debug(s2n_errno, NULL));
        return -1;
    }

    s2n_blocked_status unused;
    if (s2n_negotiate(conn, &unused) != S2N_SUCCESS) {
        fprintf(stderr, "Error: failed to negotiate. %s: %s\n",
                s2n_strerror(s2n_errno, NULL), s2n_strerror_debug(s2n_errno, NULL));
        return -1;
    }

    return sockfd;
}

int main(int argc, char* argv[])
{
    int ret = -1;
    if(argc != 3)
    {
        fprintf(stderr, "Usage: %s <kex_alg> <measurement_count>\n", argv[0]);
        return 1;
    }
    /*const char* kex_alg = argv[1];*/
    const size_t measurements_to_make = strtol(argv[2], 0, 10);
    size_t measurements = 0;

    struct timespec start, finish;
    double* handshake_times_ms = malloc(measurements_to_make * sizeof(*handshake_times_ms));

    /*
    ssl_ctx = SSL_CTX_new(ssl_meth);
    if (!ssl_ctx)
    {
        goto s2n_err;
    }

    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_quiet_shutdown(ssl_ctx, 1);

    ret = SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
    if (ret != 1)
    {
        goto s2n_err;
    }

    ret = SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
    if (ret != 1)
    {
        goto s2n_err;
    }

    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_COMPRESSION);

    ret = SSL_CTX_set_ciphersuites(ssl_ctx, ciphersuites);
    if (ret != 1)
    {
        goto s2n_err;
    }
    ret = SSL_CTX_set1_groups_list(ssl_ctx, kex_alg);
    if (ret != 1)
    {
        goto s2n_err;
    }

    ret = SSL_CTX_load_verify_locations(ssl_ctx, "../tmp/nginx/conf/CA.crt", 0);
    if(ret != 1)
    {
        goto s2n_err;
    }
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
    */

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
    // TODO: configure !!
    /*const char* ciphersuites = "TLS_AES_256_GCM_SHA384";*/
    if (s2n_connection_set_config(conn, config)) {
        fprintf(stderr, "Error: failed to set config on connection\n");
        goto s2n_err;
    }


    // TODO: point this at the trust store?

    while(measurements < measurements_to_make)
    {
        clock_gettime(CLOCK_MONOTONIC_RAW, &start);
        // TODO: pull socket creation up here?
        int sockfd = do_tls_handshake(conn);
        clock_gettime(CLOCK_MONOTONIC_RAW, &finish);
        if (sockfd < 0) {
            /* Retry since at high packet loss rates,
             * the connect() syscall fails sometimes.
             * Non-retryable errors are caught by manual
             * inspection of logs, which has sufficed
             * for our purposes */
            // TODO: need to scope down the retry condition to specific socket errors
            //continue;
            goto err;
        }

        s2n_blocked_status unused;
        if(s2n_shutdown(conn, &unused) != S2N_SUCCESS || s2n_connection_wipe(conn) != S2N_SUCCESS) {
            goto s2n_err;
        }

        if (shutdown(sockfd, SHUT_RDWR)) {
            fprintf(stderr, "Error: socket shutdown failed with error %s\n", strerror(errno));
            goto err;
        }

        handshake_times_ms[measurements] = ((finish.tv_sec - start.tv_sec) * MS_IN_S) + ((finish.tv_nsec - start.tv_nsec) / NS_IN_MS);
        measurements++;
    }

    for(size_t i = 0; i < measurements - 1; i++)
    {
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
