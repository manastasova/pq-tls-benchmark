/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "api/s2n.h"
#include "common.h"
#include "crypto/s2n_libcrypto.h"
#include "error/s2n_errno.h"

#define MAX_CERTIFICATES 50

void usage()
{
    fprintf(stderr, "s2nd - simplified s2n-tls server for benchmarking\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "usage: s2nd [options] host port\n");
    fprintf(stderr, " host: hostname or IP address to listen on\n");
    fprintf(stderr, " port: port to listen on\n");
    fprintf(stderr, "\n Options:\n\n");
    fprintf(stderr, "  -c [version_string]\n");
    fprintf(stderr, "  --ciphers [version_string]\n");
    fprintf(stderr, "    Set the cipher preference version string.\n");
    fprintf(stderr, "  --cert\n");
    fprintf(stderr, "    Path to a PEM encoded certificate [chain]. Option can be repeated.\n");
    fprintf(stderr, "  --key\n");
    fprintf(stderr, "    Path to a PEM encoded private key that matches cert. Option can be repeated.\n");
    fprintf(stderr, "  -m\n");
    fprintf(stderr, "  --mutualAuth\n");
    fprintf(stderr, "    Request a Client Certificate.\n");
    fprintf(stderr, "  --prefer-throughput\n");
    fprintf(stderr, "    Prefer throughput by raising maximum outgoing record size to 16k\n");
    fprintf(stderr, "  -s\n");
    fprintf(stderr, "  --self-service-blinding\n");
    fprintf(stderr, "    Don't introduce 10-30 second delays on TLS Handshake errors.\n");
    fprintf(stderr, "  -t,--ca-file [file path]\n");
    fprintf(stderr, "    Location of trust store CA file (PEM format).\n");
    fprintf(stderr, "  -T,--no-session-ticket\n");
    fprintf(stderr, "    Disable session ticket for resumption.\n");
    fprintf(stderr, "  -C,--corked-io\n");
    fprintf(stderr, "    Turn on corked io\n");
    fprintf(stderr, "  -b --https-bench <bytes>\n");
    fprintf(stderr, "    Send number of bytes in https server mode to test throughput.\n");
    fprintf(stderr, "  -h,--help\n");
    fprintf(stderr, "    Display this message and quit.\n");
    exit(1);
}

int handle_connection(int fd, struct s2n_config *config, struct conn_settings settings)
{
    struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
    if (!conn) {
        print_s2n_error("Error getting new s2n connection");
        S2N_ERROR_PRESERVE_ERRNO();
    }

    GUARD_EXIT(s2n_setup_server_connection(conn, fd, config, settings), "Error setting up connection");

    if (negotiate(conn, fd) != S2N_SUCCESS) {
        if (settings.mutual_auth) {
            if (!s2n_connection_client_cert_used(conn)) {
                print_s2n_error("Error: Mutual Auth was required, but not negotiated");
            }
        }
        S2N_ERROR_PRESERVE_ERRNO();
    }

    GUARD_EXIT(s2n_connection_free_handshake(conn), "Error freeing handshake memory after negotiation");

    if (settings.https_server) {
        https(conn, settings.https_bench);
    } else {
        bool stop_echo = false;
        echo(conn, fd, &stop_echo);
    }

    GUARD_RETURN(wait_for_shutdown(conn, fd), "Error closing connection");

    GUARD_RETURN(s2n_connection_wipe(conn), "Error wiping connection");

    GUARD_RETURN(s2n_connection_free(conn), "Error freeing connection");

    return 0;
}

int main(int argc, char *const *argv)
{
    struct addrinfo hints, *ai = NULL;
    int r = 0, sockfd = 0;

    /* required args */
    const char *host = NULL;
    const char *port = NULL;

    const char *cipher_prefs = "default";

    /* Certificates provided by the user */
    int num_user_certificates = 0;
    int num_user_private_keys = 0;
    const char *certificates[MAX_CERTIFICATES] = { 0 };
    const char *private_keys[MAX_CERTIFICATES] = { 0 };

    struct conn_settings conn_settings = { 0 };
    long int bytes = 0;
    conn_settings.session_ticket = 1;
    conn_settings.session_cache = 1;

    struct option long_options[] = {
        { "ciphers", required_argument, NULL, 'c' },
        { "help", no_argument, NULL, 'h' },
        { "key", required_argument, NULL, 'k' },
        { "mutualAuth", no_argument, NULL, 'm' },
        { "prefer-throughput", no_argument, NULL, 'p' },
        { "cert", required_argument, NULL, 'r' },
        { "self-service-blinding", no_argument, NULL, 's' },
        { "ca-file", required_argument, 0, 't' },
        { "no-session-ticket", no_argument, 0, 'T' },
        { "corked-io", no_argument, 0, 'C' },
        { "https-bench", required_argument, 0, 'b' },
        { 0 },
    };

    while (1) {
        int option_index = 0;
        int c = getopt_long(argc, argv, "c:hmpst:TCb:", long_options, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 'C':
                conn_settings.use_corked_io = 1;
                break;
            case 'c':
                cipher_prefs = optarg;
                break;
            case 'h':
                usage();
                break;
            case 'k':
                if (num_user_private_keys == MAX_CERTIFICATES) {
                    fprintf(stderr, "Cannot support more than %d certificates!\n", MAX_CERTIFICATES);
                    exit(1);
                }
                private_keys[num_user_private_keys] = load_file_to_cstring(optarg);
                num_user_private_keys++;
                break;
            case 'm':
                conn_settings.mutual_auth = 1;
                break;
            case 'p':
                conn_settings.prefer_throughput = 1;
                break;
            case 'r':
                if (num_user_certificates == MAX_CERTIFICATES) {
                    fprintf(stderr, "Cannot support more than %d certificates!\n", MAX_CERTIFICATES);
                    exit(1);
                }
                certificates[num_user_certificates] = load_file_to_cstring(optarg);
                num_user_certificates++;
                break;
            case 's':
                conn_settings.self_service_blinding = 1;
                break;
            case 't':
                conn_settings.ca_file = optarg;
                break;
            case 'T':
                conn_settings.session_ticket = 0;
                break;
            case 'b':
                bytes = strtoul(optarg, NULL, 10);
                GUARD_EXIT(bytes, "https-bench bytes needs to be some positive long value.");
                conn_settings.https_bench = bytes;
                conn_settings.https_server = 1;
                break;
            case '?':
            default:
                usage();
                break;
        }
    }

    if (optind < argc) {
        host = argv[optind++];
    }

    if (optind < argc) {
        port = argv[optind++];
    }

    if (!host || !port) {
        usage();
    }

    if (setvbuf(stdin, NULL, _IONBF, 0) < 0) {
        fprintf(stderr, "Error disabling buffering for stdin\n");
        exit(1);
    }

    if (setvbuf(stdout, NULL, _IONBF, 0) < 0) {
        fprintf(stderr, "Error disabling buffering for stdout\n");
        exit(1);
    }

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        fprintf(stderr, "Error disabling SIGPIPE\n");
        exit(1);
    }

    if ((r = getaddrinfo(host, port, &hints, &ai)) < 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(r));
        exit(1);
    }

    if ((sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) == -1) {
        fprintf(stderr, "socket error: %s\n", strerror(errno));
        exit(1);
    }

    r = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &r, sizeof(int)) < 0) {
        fprintf(stderr, "setsockopt error: %s\n", strerror(errno));
        exit(1);
    }

    if (bind(sockfd, ai->ai_addr, ai->ai_addrlen) < 0) {
        fprintf(stderr, "bind error: %s\n", strerror(errno));
        exit(1);
    }

    if (listen(sockfd, 1) == -1) {
        fprintf(stderr, "listen error: %s\n", strerror(errno));
        exit(1);
    }

    GUARD_EXIT(s2n_init(), "Error running s2n_init()");
    printf("libcrypto: %s\n", s2n_libcrypto_get_version_name());

    printf("Listening on %s:%s\n", host, port);

    struct s2n_config *config = s2n_config_new();
    if (!config) {
        print_s2n_error("Error getting new s2n config");
        exit(1);
    }

    if (num_user_certificates != num_user_private_keys) {
        fprintf(stderr, "Mismatched certificate(%d) and private key(%d) count!\n", num_user_certificates, num_user_private_keys);
        exit(1);
    }

    if (num_user_certificates == 0) {
        fprintf(stderr, "No certificates provided!\n");
        exit(1);
    }

    for (int i = 0; i < num_user_certificates; i++) {
        struct s2n_cert_chain_and_key *chain_and_key = s2n_cert_chain_and_key_new();
        GUARD_EXIT(s2n_cert_chain_and_key_load_pem(chain_and_key, certificates[i], private_keys[i]), "Error getting certificate/key");
        GUARD_EXIT(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key), "Error setting certificate/key");
    }

    s2n_set_common_server_config(0, config, conn_settings, cipher_prefs, NULL);

    int fd = 0;
    while ((fd = accept(sockfd, ai->ai_addr, &ai->ai_addrlen)) > 0) {
        int rc = handle_connection(fd, config, conn_settings);
        close(fd);
        if (rc < 0) {
            exit(rc);
        }
    }

    GUARD_EXIT(s2n_cleanup(), "Error running s2n_cleanup()");

    return 0;
}
