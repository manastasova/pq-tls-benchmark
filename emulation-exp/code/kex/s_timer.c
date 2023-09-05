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

    // TODO [childw] remove this option from socket after |s2n_negotiate| returns?
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

    s2n_blocked_status unused;
    if (s2n_negotiate(conn, &unused) != S2N_SUCCESS) {
        fprintf(stderr, "Error: failed to negotiate. %s: %s\n",
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

    return sockfd;
}

unsigned char verify_host(const char *host_name, size_t host_name_len, void *data) {
    UNUSED(host_name);
    UNUSED(host_name_len);
    UNUSED(data);
    return 1;
}

int main(int argc, char* argv[])
{
    int ret = -1;
    if(argc != 3)
    {
        fprintf(stderr, "Usage: %s <security_policy> <measurements>\n", argv[0]);
        return 1;
    }

    const char* security_policy = argv[1];
    const size_t measurements = strtol(argv[2], 0, 10);

    struct timespec start, finish;
    double *handshake_times_ms = malloc(measurements * sizeof(double));
    if (handshake_times_ms == NULL) {
        fprintf(stderr, "Error: failed to allocate handshake time array\n");
        goto err;
    }

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
    if (s2n_config_set_verification_ca_location(config, trust_store_dir, trust_store_path)) {
        fprintf(stderr, "Error: failed to set trust store on config\n");
        goto s2n_err;
    }

    if (s2n_config_set_cipher_preferences(config, security_policy)) {
        fprintf(stderr, "Error: failed to set security policy on config\n");
        goto s2n_err;
    }

    if (s2n_config_set_verify_host_callback(config, verify_host, NULL)) {
        fprintf(stderr, "Error: failed to set verify host callback on config\n");
        goto s2n_err;
    }

    if (s2n_connection_set_config(conn, config)) {
        fprintf(stderr, "Error: failed to set config on connection\n");
        goto s2n_err;
    }

    const int warmup_conns = 3;
    for (int i = -1 * warmup_conns; i < (int) measurements; i++) {
        //usleep(((rand() % 10) + 1) * 1000);    // sleep between 1 and 10ms
        if (i >= 0) {
            handshake_times_ms[i] = 0;  // TODO need to account for this in analysis script?
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &start);
        int sockfd = do_tls_handshake(conn);
        clock_gettime(CLOCK_MONOTONIC_RAW, &finish);
        if (sockfd == SOCKERR) {
            /* Retry since at high packet loss rates,
             * the connect() syscall fails sometimes.
             * Non-retryable errors are caught by manual
             * inspection of logs, which has sufficed
             * for our purposes */
            continue;
        }

        s2n_blocked_status unused;
        if(s2n_shutdown(conn, &unused) != S2N_SUCCESS || s2n_connection_wipe(conn) != S2N_SUCCESS) {
            close(sockfd);
            goto s2n_err;
        }

        if (close(sockfd)) {
            fprintf(stderr, "Error: socket shutdown failed with error %s\n", strerror(errno));
            goto err;
        }

        if (i < 0) {
            continue;
        }

        handshake_times_ms[i] = ((finish.tv_sec - start.tv_sec) * MS_IN_S) + ((finish.tv_nsec - start.tv_nsec) / NS_IN_MS);
    }

    for(size_t i = 0; i < measurements; i++) {
        printf(i < measurements-1 ? "%f," : "%f", handshake_times_ms[i]);
    }

    ret = 0;
    goto end;

s2n_err:
    fprintf(stderr, "Error: Unrecoverable s2n error. %s: %s\n",
            s2n_strerror(s2n_errno, NULL), s2n_strerror_debug(s2n_errno, NULL));
err:
    ret = 1;
end:
    if (handshake_times_ms) {
        free(handshake_times_ms);
    }
    if (conn) {
        s2n_connection_free(conn);
    }
    if (config) {
        s2n_config_free(config);
    }
    s2n_cleanup();
    return ret;
}
