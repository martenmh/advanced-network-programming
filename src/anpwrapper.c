/*
 * Copyright [2020] [Animesh Trivedi]
 *
 * This code is part of the Advanced Network Programming (ANP) course
 * at VU Amsterdam.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *        http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

//XXX: _GNU_SOURCE must be defined before including dlfcn to get RTLD_NEXT symbols
#define _GNU_SOURCE

#include "anpwrapper.h"
#include "init.h"
#include "ip.h"
#include "linklist.h"
#include "systems_headers.h"
#include <dlfcn.h>

LIST_HEAD(sockets);
uint32_t sockets_size = 0;

static int (*__start_main)(int (*main)(int, char **, char **), int argc, \
                           char **ubp_av, void (*init)(void), void (*fini)(void), \
                           void (*rtld_fini)(void), void (*stack_end));

static ssize_t (*_send)(int fd, const void *buf, size_t n, int flags) = NULL;

static ssize_t (*_recv)(int fd, void *buf, size_t n, int flags) = NULL;

static int (*_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;

static int (*_socket)(int domain, int type, int protocol) = NULL;

static int (*_close)(int sockfd) = NULL;

static int is_socket_supported(int domain, int type, int protocol) {
    if (domain != AF_INET) {
        return 0;
    }
    if (!(type & SOCK_STREAM)) {
        return 0;
    }
    if (protocol != 0 && protocol != IPPROTO_TCP) {
        return 0;
    }
    printf("\nSupported socket domain %d type %d and protocol %d \n", domain, type, protocol);
    return 1;
}

struct anp_socket_entry *get_socket(int sockfd) {
    struct list_head *item;
    struct anp_socket_entry *entry;
    list_for_each(item, &sockets) {
        entry = list_entry(item, struct anp_socket_entry, list);
        if (entry->sockfd == sockfd) {
            return entry;
        }
    }
    return NULL;
}

bool is_anp_socket(int sockfd) { // used to chose between the default and ANP paths
    return get_socket(sockfd) != NULL;
}

// TODO: ANP milestone 3 -- implement the socket, and connect calls
int socket(int domain, int type, int protocol) {
    if (is_socket_supported(domain, type, protocol)) {
        struct anp_socket_entry *entry = calloc(1, sizeof(struct anp_socket_entry));
        list_init(&entry->list);
        entry->sockfd = MIN_SOCKFD + sockets_size;
        sockets_size++;
        list_add_tail(&entry->list, &sockets);

        // initialize mutex locks
        pthread_mutex_init(&entry->tcp_state_mut, NULL);
        pthread_mutex_init(&entry->tcp_state.sig_mut, NULL);

        printf("New socket count is: %d\n", sockets_size);
        entry->tcp_state.state = CLOSED; // socket is always initiated in the CLOSED state
        return entry->sockfd;
    }
    // if this is not what anpnetstack support, let it go, let it go!
    printf("\nUnsupported socket. domain: %d, type: %d, protocol %d.", domain, type, protocol);
    return _socket(domain, type, protocol);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (addr->sa_family != AF_INET) {
        printf("\nDropping connection: Unsupported sa_family!!!\n");
        return -1;
    }

    // check whether the current file descriptor is an ANP socket, if it is not then use the default OS path
    bool is_anp_sockfd = is_anp_socket(sockfd);

    if (is_anp_sockfd) {
        printf("Establishing connection......\n");
        struct anp_socket_entry *sock_entry = get_socket(sockfd);
        pthread_mutex_lock(&sock_entry->tcp_state_mut); // acquire the lock on thread

        if (sock_entry->tcp_state.state != CLOSED) {
            printf("\nDropping connection: Expected CLOSED socket for connect!!!\n");
            return -1;
        }

        // SYN PACKET
        struct subuff *syn_sub = alloc_tcp_sub();
        if (!syn_sub) {
            printf("\nError: allocation of the TCP tx_sub failed!!!\n");
            return -1;
        }

        struct tcphdr *syn_hdr = (struct tcphdr *) sub_push(syn_sub, TCP_HDR_LEN); // MIN_PADDED_TCP_LEN
        syn_hdr = create_syn(syn_hdr, addr); // prepare the TCP SYN packet

        uint32_t src_addr = ip_str_to_n32(ANP_IP_CLIENT_EXT);
        uint32_t dst_addr = htonl((((struct sockaddr_in *) addr)->sin_addr).s_addr);

        // store allocated subuff for deallocation and comparison
        sock_entry->tcp_state.tx_sub = syn_sub;
        sock_entry->tcp_state.state = SYN_SENT;
        sock_entry->src_port = syn_hdr->src_port;
        sock_entry->dst_port = syn_hdr->dst_port;
        sock_entry->seq_num = syn_hdr->seq_num;
        sock_entry->src_addr = src_addr;
        sock_entry->dst_addr = ip_str_to_n32(inet_ntoa(((struct sockaddr_in *) addr)->sin_addr));

        debug_tcp_hdr("SYN out", syn_hdr);

        int err = tcp_output(dst_addr, syn_sub);
        if (err < 0)
            return err;

        printf("Waiting on SYN-ACK......\n");

        pthread_mutex_unlock(&sock_entry->tcp_state_mut); // release the lock

        // wait on SYN-ACK
        pthread_mutex_lock(&sock_entry->tcp_state.sig_mut);
        while (!sock_entry->tcp_state.condition) {
            // wait on SYN-ACK, see ip_rx.c for receiving end.
            pthread_cond_wait(&sock_entry->tcp_state.sig_cond, &sock_entry->tcp_state.sig_mut);
        }

        pthread_mutex_unlock(&sock_entry->tcp_state.sig_mut);

        pthread_mutex_lock(&sock_entry->tcp_state_mut);
        if (!sock_entry->tcp_state.condition) {
            return -1;
        }

        // ACK PACKET
        struct subuff *ack_sub = alloc_tcp_sub();
        if (!ack_sub) {
            printf("Error: allocation of the TCP tx_sub failed \n");
            return -1;
        }

        sub_push(ack_sub, TCP_HDR_LEN);
        struct tcphdr *ack_hdr = TCP_HDR_FROM_SUB(ack_sub);
        struct tcphdr *rx_hdr = TCP_HDR_FROM_SUB(sock_entry->tcp_state.rx_sub);

        // Preparing TCP ACK packet
        ack_hdr->src_port = sock_entry->src_port;
        ack_hdr->dst_port = sock_entry->dst_port;
        ack_hdr->seq_num = sock_entry->seq_num + htonl(1);
        ack_hdr->ack_num = htonl(ntohl(rx_hdr->seq_num) + 1);
        ack_hdr->data_offset = 8; // header contains 8 x 32 bits
        ack_hdr->ack = 1;
        ack_hdr->window = htons(TCP_MAX_WINDOW);  // max amount can be received, not the best option, but currently works

        ack_hdr->checksum = 0;  // zeroing checksum before recalculating
        ack_hdr->checksum = do_tcp_csum((uint8_t *) ack_hdr, TCP_HDR_LEN, IPP_TCP, sock_entry->src_addr,
                                        sock_entry->dst_addr);

        printf("Sending ACK......\n");
        debug_tcp_hdr("ACK out", ack_hdr);

        err = ip_output(dst_addr, ack_sub);
        if (err < 0) {
            printf("\nGetting err: %d, errno: %d \n", err, errno);
            return err;
        }

        sock_entry->tcp_state.state = ESTABLISHED; // Three-way handshake complete, the connection is now ESTABLISHED
        sock_entry->tcp_state.sequence_num = ack_hdr->seq_num;
        sock_entry->seq_num = ack_hdr->seq_num; // update the last sequence number for future use
        pthread_mutex_unlock(&sock_entry->tcp_state_mut); // release the lock

        return 0;
    }

    // the default path
    return _connect(sockfd, addr, addrlen);
}

// TODO: ANP milestone 5 -- implement the send, recv, and close calls
ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    // check whether the current file descriptor is an ANP socket, if it is not then use the default path
    bool is_anp_sockfd = is_anp_socket(sockfd);

    if (is_anp_sockfd) {
        printf("\nSending payload of size %zu in progress...... \n", len);
        struct anp_socket_entry *sock_entry = get_socket(sockfd);
        pthread_mutex_lock(&sock_entry->tcp_state_mut); // ensures no two or more connections are made at the same time

        if (sock_entry->tcp_state.state != ESTABLISHED) {
            printf("Connection is not ESTABLISHED; Expected ESTABLISHED connection to send packages... \n");
            return -1;
        }

        struct subuff *send_sub = alloc_tcp_payload(len);
        if (!send_sub) {
            printf("Error: allocation of the TCP tx_sub failed \n");
            return -1;
        }

        // Pushing data
        printf("Copied buffer of len: %zu into payload \n", len);
        uint8_t *payload_buf = sub_push(send_sub, len);
        memcpy(payload_buf, buf, len);

        printf("Creating header...... \n");
        // Pushing header
        struct tcphdr *send_hdr = (struct tcphdr *) sub_push(send_sub, TCP_HDR_LEN);
        struct tcphdr *rx_hdr = TCP_HDR_FROM_SUB(sock_entry->tcp_state.rx_sub);

        // Preparing the packet
        send_hdr->src_port = sock_entry->src_port;
        send_hdr->dst_port = sock_entry->dst_port;
        send_hdr->seq_num = htonl(SIMPLE_ISN + 1);
        send_hdr->ack_num = htonl(ntohl(rx_hdr->seq_num) + 1);
        send_hdr->data_offset = 8; // header contains 8 x 32 bits
        send_hdr->psh = 1;
        send_hdr->ack = 1;
        send_hdr->window = htons(
                TCP_MAX_WINDOW);  // max amount can be received, not the best option, but currently works

        send_hdr->checksum = 0; // zeroing checksum before recalculating
        send_hdr->checksum = do_tcp_csum((uint8_t *) send_hdr, TCP_HDR_LEN + len, IPP_TCP, sock_entry->src_addr,
                                         sock_entry->dst_addr) -
                             htons(256);

        int err = tcp_output(ntohl(sock_entry->dst_addr), send_sub);
        if (err < 0) {
            return err;
        }

        printf("Waiting on ACK......\n");
        pthread_mutex_unlock(&sock_entry->tcp_state_mut);

        // wait on ACK
        pthread_mutex_lock(&sock_entry->tcp_state.sig_mut);
        while (!sock_entry->tcp_state.condition) {
            // wait on ACK, see ip_rx.c for receiving end.
            pthread_cond_wait(&sock_entry->tcp_state.sig_cond, &sock_entry->tcp_state.sig_mut);
        }

        pthread_mutex_lock(&sock_entry->tcp_state_mut);
        if (!sock_entry->tcp_state.condition) {
            return -1;
        }


        sock_entry->tcp_state.sequence_num = send_hdr->seq_num;
        return len;
    }
    // the default path
    return _send(sockfd, buf, len, flags);
}

struct tcphdr *wait_on_tcp_response(struct anp_socket_entry *sock_entry) {
    pthread_mutex_lock(&sock_entry->tcp_state.sig_mut);
    while (!sock_entry->tcp_state.condition) {
        // Wait to be signalled by an incoming TCP response from ip_rx
        pthread_cond_wait(&sock_entry->tcp_state.sig_cond, &sock_entry->tcp_state.sig_mut);
    }
    pthread_mutex_unlock(&sock_entry->tcp_state.sig_mut);

    return TCP_HDR_FROM_SUB(sock_entry->tcp_state.rx_sub);
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {

    bool is_anp_sockfd = is_anp_socket(sockfd);

    if (is_anp_sockfd) {
        size_t read_len = 0;
        struct anp_socket_entry *socket_entry = get_socket(sockfd);

        pthread_mutex_lock(&socket_entry->tcp_state.sig_mut);
        while (!socket_entry->tcp_state.condition) {
            // Wait to be signalled by an incoming TCP response from ip_rx
            pthread_cond_wait(&socket_entry->tcp_state.sig_cond,
                              &socket_entry->tcp_state.sig_mut);
        }
        pthread_mutex_unlock(&socket_entry->tcp_state.sig_mut);

        pthread_mutex_lock(&socket_entry->tcp_state_mut);
        async_printf("Read TCP packet.\n");
        struct list_head *item;
        struct recv_packet_entry *entry;
        async_printf("reading received packets\n");
        int i = 0;
        list_for_each(item, &recv_packets) {
            entry = list_entry(item, struct recv_packet_entry, list);
            if (entry->sockfd != sockfd)
                continue;


            if (len < entry->length) {
                read_len = len;
            } else {
                read_len = entry->length;
            }

            memcpy(buf, entry->buffer, read_len);
            list_del(item);
            goto ret;
        }
        ret:
        pthread_mutex_unlock(&socket_entry->tcp_state_mut);
        return read_len;
    }
    return _recv(sockfd, buf, len, flags);
}

int close(int sockfd) {

    bool is_anp_sockfd = is_anp_socket(sockfd);

    if (is_anp_sockfd) {
        struct anp_socket_entry *sock_entry = get_socket(sockfd);
        pthread_mutex_lock(&sock_entry->tcp_state_mut); // ensures no two or more connections are made at the same time


        // SEND FIN
        struct subuff *close_sub = alloc_tcp_sub();
        if (!close_sub) {
            printf("Error: allocation of the TCP tx_sub failed \n");
            return -1;
        }

        struct tcphdr *close_hdr = (struct tcphdr *) sub_push(close_sub, 20);

        close_hdr->src_port = sock_entry->src_port;
        close_hdr->dst_port = sock_entry->dst_port;
        close_hdr->seq_num = htonl(SIMPLE_ISN + 1);
        close_hdr->ack_num = htonl(1);
        close_hdr->data_offset = 8; // header contains 5 x 32 bits
        close_hdr->fin = 1;
        close_hdr->ack = 1;
        close_hdr->window = htons(TCP_MAX_WINDOW);  // we can receive the max amount

        close_hdr->checksum = 0;
        close_hdr->checksum = do_tcp_csum((uint8_t *) close_hdr, TCP_HDR_LEN, IPP_TCP, sock_entry->src_addr,
                                          sock_entry->dst_addr);

        int err = tcp_output(ntohl(sock_entry->dst_addr), close_sub);
        if (err < 0)
            return err;

        printf("FIN sent \n");
        printf("Waiting on FIN-ACK..\n");
        sock_entry->tcp_state.state = FIN_WAIT_1;
        pthread_mutex_unlock(&sock_entry->tcp_state_mut);

        // wait on FIN-ACK
        pthread_mutex_lock(&sock_entry->tcp_state.sig_mut);
        while (!sock_entry->tcp_state.condition) {
            // wait on SYN-ACK, see ip_rx.c for receiving end.
            pthread_cond_wait(&sock_entry->tcp_state.sig_cond, &sock_entry->tcp_state.sig_mut);
        }
        pthread_mutex_unlock(&sock_entry->tcp_state.sig_mut);

        // SEND LAST ACK
        pthread_mutex_lock(&sock_entry->tcp_state_mut);

        struct subuff *ack_sub = alloc_tcp_sub();
        if (!ack_sub) {
            printf("Error: allocation of the TCP tx_sub failed \n");
            return -1;
        }

        sub_push(ack_sub, 20);
        struct tcphdr *ack_hdr = TCP_HDR_FROM_SUB(ack_sub);
        struct tcphdr *rx_hdr = TCP_HDR_FROM_SUB(sock_entry->tcp_state.rx_sub);

        // Preparing TCP ACK packet
        ack_hdr->src_port = sock_entry->src_port;
        ack_hdr->dst_port = sock_entry->dst_port;
        ack_hdr->seq_num = htonl(SIMPLE_ISN + 1);
        ack_hdr->ack_num = htonl(ntohl(rx_hdr->seq_num) + 1);
        ack_hdr->data_offset = 8; // header contains 5 x 32 bits
        ack_hdr->ack = 1;
        ack_hdr->window = htons(
                TCP_MAX_WINDOW);  // max amount can be received, not the best option, but currently works

        ack_hdr->checksum = 0;  // zeroing checksum before recalculating
        ack_hdr->checksum = do_tcp_csum((uint8_t *) ack_hdr, TCP_HDR_LEN, IPP_TCP, sock_entry->src_addr, sock_entry->dst_addr);

        printf("Sending ACK..\n");
        debug_tcp_hdr("ACK out \n", ack_hdr);

        err = ip_output(ntohl(sock_entry->dst_addr), ack_sub);
        if (err < 0) {
            printf("Getting err: %d, errno: %d \n", err, errno);
            return err;
        }

        sock_entry->tcp_state.state = CLOSED; // Four-way handshake complete, the connection is now CLOSED
        pthread_mutex_unlock(&sock_entry->tcp_state_mut);

        return 0;

    }
    // the default path
    return _close(sockfd);
}

void _function_override_init() {
    __start_main = dlsym(RTLD_NEXT, "__libc_start_main");
    _socket = dlsym(RTLD_NEXT, "socket");
    _connect = dlsym(RTLD_NEXT, "connect");
    _send = dlsym(RTLD_NEXT, "send");
    _recv = dlsym(RTLD_NEXT, "recv");
    _close = dlsym(RTLD_NEXT, "close");
}

struct tcp_sock_state *get_tcp_state(struct anp_socket_entry *socket_entry) {


}
