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

static int (*__start_main)(int (*main) (int, char * *, char * *), int argc, \
                           char * * ubp_av, void (*init) (void), void (*fini) (void), \
                           void (*rtld_fini) (void), void (* stack_end));

static ssize_t (*_send)(int fd, const void *buf, size_t n, int flags) = NULL;
static ssize_t (*_recv)(int fd, void *buf, size_t n, int flags) = NULL;

static int (*_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*_socket)(int domain, int type, int protocol) = NULL;
static int (*_close)(int sockfd) = NULL;

static int is_socket_supported(int domain, int type, int protocol)
{
    if (domain != AF_INET){
        return 0;
    }
    if (!(type & SOCK_STREAM)) {
        return 0;
    }
    if (protocol != 0 && protocol != IPPROTO_TCP) {
        return 0;
    }
    printf("supported socket domain %d type %d and protocol %d \n", domain, type, protocol);
    return 1;
}

// TODO: ANP milestone 3 -- implement the socket, and connect calls
int socket(int domain, int type, int protocol) {
    if (is_socket_supported(domain, type, protocol)) {
        struct anp_socket_entry *entry = calloc(1, sizeof(struct anp_socket_entry));
        list_init(&entry->list);
        entry->sockfd = MIN_SOCKFD + sockets_size;
        sockets_size++;
        list_add_tail(&entry->list, &sockets);
        printf("Added sockfd to list : %d\n", entry->sockfd);
        return entry->sockfd;
        // return -ENOSYS;
    }
    // if this is not what anpnetstack support, let it go, let it go!
    printf("Unsupported socket. domain: %d, type: %d, protocol %d.", domain, type, protocol);
    return _socket(domain, type, protocol);
}

struct anp_socket_entry* get_sock(int sockfd){
  struct anp_socket_entry* sock = NULL;
  struct list_head *item;
  struct anp_socket_entry *entry;
  list_for_each(item, &sockets) {
    entry = list_entry(item, struct anp_socket_entry, list);
    if (entry->sockfd == sockfd)
      sock = entry;
  }
  return sock;
}

bool is_anp_sock(int sockfd){
  return get_sock(sockfd) != NULL;
}


int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (addr->sa_family != AF_INET) {
      printf("Unsupported sa_family");
      goto drop_connection;
    }

    bool is_anp_sockfd = is_anp_sock(sockfd);
    struct subuff *sub;
    struct tcphdr *hdr;
    if(is_anp_sockfd){
        struct anp_socket_entry* sock_entry = get_sock(sockfd);
        hdr = &sock_entry->tcp_state.prev_hdr;

        if(sock_entry->tcp_state.state != CLOSED){
            printf("Socket is not closed");
            return -1;
        }
        sub = alloc_tcp_sub();
        sub_push(sub, TCP_HDR_LEN);

        hdr->syn = 0x1;
        hdr->seq_num = 0;
        hdr->dst_port = (((struct sockaddr_in *)addr)->sin_port);
        hdr->dst_port = 0;
        hdr->ack_num = 0;
        hdr->checksum = 0;
        uint32_t dest_addr = (((struct sockaddr_in *)addr)->sin_addr).s_addr;
        uint32_t src_addr = ip_str_to_n32(ANP_IP_CLIENT_EXT);
        hdr->checksum = do_tcp_csum((uint8_t *)&hdr, TCP_HDR_LEN, IPP_TCP, src_addr, dest_addr);

        debug_tcp_hdr("", hdr);

        ip_output(dest_addr, sub); // sending SYN

        sock_entry->tcp_state.state = SYN_SENT;

        pthread_mutex_lock(&sock_entry->tcp_state.sig_mut);
        while(!sock_entry->tcp_state.condition) {
          // wait on SYN-ACK, see ip_rx.c for receiving end.
            pthread_cond_timedwait(&sock_entry->tcp_state.sig_cond,
                            &sock_entry->tcp_state.sig_mut,
                                 (const struct timespec *)TCP_CONNECT_TIMEOUT);
        }
        pthread_mutex_unlock(&sock_entry->tcp_state.sig_mut);
        if(!sock_entry->tcp_state.condition){
            return -1;
        }

        return 0;
    }
    drop_connection:
    // the default path
    return _connect(sockfd, addr, addrlen);
}

// TODO: ANP milestone 5 -- implement the send, recv, and close calls
ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    bool is_anp_sockfd = is_anp_sock(sockfd);
    if(is_anp_sockfd) {
        //TODO: implement your logic here
        return -ENOSYS;
    }
    // the default path
    return _send(sockfd, buf, len, flags);
}

ssize_t recv (int sockfd, void *buf, size_t len, int flags){
    //FIXME -- you can remember the file descriptors that you have generated in the socket call and match them here
    bool is_anp_sockfd = false;
    if(is_anp_sockfd) {
        //TODO: implement your logic here
        return -ENOSYS;
    }
    // the default path
    return _recv(sockfd, buf, len, flags);
}

int close (int sockfd){
    //FIXME -- you can remember the file descriptors that you have generated in the socket call and match them here
    bool is_anp_sockfd = false;
    if(is_anp_sockfd) {
      // deallocate sock_cache
        //TODO: implement your logic here
        return -ENOSYS;
    }
    // the default path
    return _close(sockfd);
}

void _function_override_init()
{
    __start_main = dlsym(RTLD_NEXT, "__libc_start_main");
    _socket = dlsym(RTLD_NEXT, "socket");
    _connect = dlsym(RTLD_NEXT, "connect");
    _send = dlsym(RTLD_NEXT, "send");
    _recv = dlsym(RTLD_NEXT, "recv");
    _close = dlsym(RTLD_NEXT, "close");
}