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
#include "timer.h"
#include <dlfcn.h>

LIST_HEAD(sockets);
uint32_t sockets_size = 0;

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
        printf("New socket count is: %d\n", sockets_size);
        entry->tcp_state.state = CLOSED;
        return entry->sockfd;
        // return -ENOSYS;
    }
    // if this is not what anpnetstack support, let it go, let it go!
    printf("Unsupported socket. domain: %d, type: %d, protocol %d.", domain, type, protocol);
    return _socket(domain, type, protocol);
}

struct anp_socket_entry* get_socket(int sockfd){
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

bool is_anp_socket(int sockfd){
  return get_socket(sockfd) != NULL;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  if (addr->sa_family != AF_INET) {
      printf("Unsupported sa_family");
      goto drop_connection;
  }

  bool is_anp_sockfd = is_anp_socket(sockfd);

  if(is_anp_sockfd){
      struct anp_socket_entry* sock_entry = get_socket(sockfd);
      if(sock_entry->tcp_state.state != CLOSED){
          printf("Socket is not closed; Expected CLOSED socket for connect");
          return -1;
      }

      struct subuff* sub = alloc_tcp_sub();
      if (!sub) {
          printf("Error: allocation of the TCP tx_sub failed \n");
          return -1;
      }

      struct tcphdr*syn_hdr = (struct tcphdr *)sub_push(sub, MIN_PADDED_TCP_LEN);
      syn_hdr = create_syn(syn_hdr, addr);

      uint32_t src_addr = ip_str_to_n32(ANP_IP_CLIENT_EXT);
      uint32_t dest_addr = htonl((((struct sockaddr_in *)addr)->sin_addr).s_addr);

      // store allocated subuff for deallocation and comparison
      sock_entry->tcp_state.tx_sub = sub;

      debug_tcp_hdr("SYN out", syn_hdr);
      int err = tcp_output(dest_addr, sub);
      if(err < 0)
        return err;
      sock_entry->tcp_state.state = SYN_SENT;
      printf("SYN sent\n");
      printf("Waiting on SYN-ACK..\n");

      // wait on SYN-ACK
      pthread_mutex_lock(&sock_entry->tcp_state.sig_mut);
      while(!sock_entry->tcp_state.condition) {
        // wait on SYN-ACK, see ip_rx.c for receiving end.
          pthread_cond_wait(&sock_entry->tcp_state.sig_cond,
                          &sock_entry->tcp_state.sig_mut);
      }

      pthread_mutex_unlock(&sock_entry->tcp_state.sig_mut);
      if(!sock_entry->tcp_state.condition){
          return -1;
      }

      sock_entry->tcp_state.state = ESTABLISHED;

      struct subuff* ack_sub = alloc_tcp_sub();
      sub_push(ack_sub, MIN_PADDED_TCP_LEN);

      struct tcphdr* ack_hdr = TCP_HDR_FROM_SUB(ack_sub);

      struct tcphdr* rx_hdr = TCP_HDR_FROM_SUB(sock_entry->tcp_state.rx_sub);
      ack_hdr->seq_num = htonl(SIMPLE_ISN + 1);
      ack_hdr->ack_num = htonl(ntohl(rx_hdr->seq_num) + 1);

      ack_hdr->ack = 0x1;
      ack_hdr->window = htons(TCP_MAX_WINDOW);  // we can receive the max amount
      sub->protocol = IPP_TCP;
      ack_hdr->data_offset = 0x8; // header contains 8 x 32 bits
      // random port between 1024 and 65536
      ack_hdr->src_port = syn_hdr->src_port;
      ack_hdr->reserved = 0b0000;
      ack_hdr->dst_port = ((struct sockaddr_in *)addr)->sin_port;
      ack_hdr->checksum = 0;  // zero checksum before calculating

      ack_hdr->checksum = (do_tcp_csum((uint8_t *)ack_hdr, ack_hdr->data_offset * 4,
                                  htons(IPP_TCP), htonl(src_addr), htonl(dest_addr))) - htons(256);

      printf("Sending ACK..\n");
      debug_tcp_hdr("ACK out", ack_hdr);
      err = ip_output(dest_addr, ack_sub);
      if(err < 0) {
        printf("Getting err: %d, errno: %d", err, errno);
        return err;
      }
      sock_entry->src_port = ack_hdr->src_port;
      sock_entry->dest_port = ack_hdr->dst_port;

      sock_entry->src_addr = src_addr;
      sock_entry->dest_addr = dest_addr;
      sock_entry->tcp_state.state = ESTABLISHED;
      u32_ip_to_str("TCP connection established to ", ntohl(dest_addr));

      return 0;
  }
  drop_connection:
  // the default path
  return _connect(sockfd, addr, addrlen);
}

// TODO: ANP milestone 5 -- implement the send, recv, and close calls
ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    bool is_anp_sockfd = is_anp_socket(sockfd);
    if(is_anp_sockfd) {
        printf("SEND called \n");
        struct anp_socket_entry* sock_entry = get_socket(sockfd);
        printf("SOCKET IS %i \n", sockfd);

//        printf("boop %d", sock_entry->tcp_state.state);
        if(sock_entry->tcp_state.state != ESTABLISHED) {
            printf("Socket is not ESTABLISHED; Expected ESTABLISHED socket for sending");
            return -1;
        }

        uint32_t payload = len;
        struct subuff *sub = alloc_sub(MIN_ALLOCATED_TCP_SUB + payload);
        sub_reserve(sub, MIN_ALLOCATED_TCP_SUB + payload);
        if (!sub) {
            printf("Error: allocation of the TCP tx_sub failed \n");
            return -1;
        }
        sub->protocol = IPP_TCP;
        printf("Copying buffer of len: %zu into payload\n", len);
        uint8_t *payload_buf = sub_push(sub, payload);
        memcpy(payload_buf, buf, len);

        printf("Creating header\n");
        // push header
        struct tcphdr *send_hdr = (struct tcphdr *)sub_push(sub, TCP_HDR_LEN);
        struct tcphdr *rx_hdr = TCP_HDR_FROM_SUB(sock_entry->tcp_state.rx_sub);

        send_hdr->src_port = ntohs(sock_entry->src_port);
        send_hdr->dst_port = ntohs(sock_entry->dest_port);

        send_hdr->seq_num = htonl(SIMPLE_ISN + 1);
        send_hdr->ack_num = htonl(ntohl(rx_hdr->seq_num) + 1);

        send_hdr->psh = 0x1;

        send_hdr->window = htons(TCP_MAX_WINDOW);  // we can receive the max amount
        send_hdr->data_offset = 0x8; // header contains 8 x 32 bits

        send_hdr->checksum = 0;
        send_hdr->checksum = do_tcp_csum((void *)send_hdr, TCP_HDR_LEN + payload, IPP_TCP, sock_entry->src_addr, sock_entry->dest_addr);

        printf("Sending packet \n");
        u32_ip_to_str("Sending payload to: \n", sock_entry->dest_addr);
        int err = tcp_output(sock_entry->dest_addr, sub);
        if(err < 0){
          return err;
        }
        //ip_output(sock_entry->dest_addr, sub);
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

    bool is_anp_sockfd = is_anp_socket(sockfd);
    if(is_anp_sockfd) {
      // deallocate sock_cache
        struct anp_socket_entry *sock_entry = get_socket(sockfd);

        struct subuff *sub = alloc_sub(MIN_ALLOCATED_TCP_SUB);
        sub_reserve(sub, MIN_ALLOCATED_TCP_SUB);
        if (!sub) {
            printf("Error: allocation of the TCP tx_sub failed \n");
            return -1;
        }
        sub->protocol = IPP_TCP;

        struct tcphdr *close_hdr = (struct tcphdr *) sub_push(sub, MIN_PADDED_TCP_LEN);

        close_hdr->src_port = ntohs(sock_entry->src_port);
        close_hdr->dst_port = ntohs(sock_entry->dest_port);

        close_hdr->seq_num = htonl(SIMPLE_ISN + 1);
        close_hdr->ack_num = htonl(1);

        close_hdr->fin = 0x1;
        close_hdr->ack = 0x1;

        close_hdr->window = htons(TCP_MAX_WINDOW);  // we can receive the max amount
        close_hdr->data_offset = 0x8; // header contains 8 x 32 bits

        close_hdr->checksum = 0;
        close_hdr->checksum = do_tcp_csum((uint8_t *)close_hdr, close_hdr->data_offset * 4,
                                                     IPP_TCP, sock_entry->src_addr, sock_entry->dest_addr);


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
