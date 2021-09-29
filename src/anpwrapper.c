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

uint8_t *sub_pop(struct subuff *sub, unsigned int len)
{
  sub->data += len;
  sub->len -= len;
  return sub->data;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  if (addr->sa_family != AF_INET) {
      printf("Unsupported sa_family");
      goto drop_connection;
  }

  bool is_anp_sockfd = is_anp_socket(sockfd);
  printf("Length of TCP header is %lu\n", TCP_HDR_LEN + IP_HDR_LEN + ETH_HDR_LEN);

  if(is_anp_sockfd){
      struct anp_socket_entry* sock_entry = get_socket(sockfd);
      if(sock_entry->tcp_state.state != CLOSED){
          printf("Socket is not closed; Expected CLOSED socket for connect");
          return -1;
      }

      struct subuff* sub = alloc_tcp_sub();
      if (!sub) {
          printf("Error: allocation of the TCP sub failed \n");
          return -1;
      }

      struct tcphdr* hdr = (struct tcphdr *)sub_push(sub, MIN_ALLOCATED_TCP_SUB - ( IP_HDR_LEN + ETH_HDR_LEN));

      //struct iphdr *ip_hdr = IP_HDR_FROM_SUB(sub);
      //struct tcphdr* hdr = (struct tcphdr *)ip_hdr->data;

      hdr->seq_num = htonl(69280981);
      hdr->ack_num = 0;

      hdr->syn = 0x1;
      hdr->window = htons(TCP_MAX_WINDOW);  // we can receive the max amount

      hdr->data_offset = 0x8; // header contains 5 x 32 bits
      hdr->reserved = 0b0000;
      // random port between 1024 and 65536
      hdr->src_port = htons(rand()%(65536-1024 + 1) + 1024);
      hdr->dst_port = ((struct sockaddr_in *)addr)->sin_port;
      hdr->checksum = 0;  // zero checksum before calculating
      sub->protocol = IPP_TCP;

      uint32_t dest_addr = htonl((((struct sockaddr_in *)addr)->sin_addr).s_addr);
      uint32_t src_addr = ip_str_to_n32(ANP_IP_CLIENT_EXT);

      hdr->checksum = do_tcp_csum((uint8_t *)hdr, MIN_ALLOCATED_TCP_SUB - ( IP_HDR_LEN + ETH_HDR_LEN),
                                  htons(IPP_TCP), htonl(src_addr), htonl(dest_addr));
      //hdr->checksum = htons(0x594e);
      // store allocated subuff for deallocation and comparison
      sock_entry->tcp_state.sub = sub;
      debug_tcp_hdr("out", hdr);

      int err = ip_output(dest_addr, sub);

      if(err == -EAGAIN) {
        try_again(5, 1, err == -EAGAIN, {
          // important line. If you run the ip_output multiple times
          // the sub continually gets pushed to without being popped
          sub_pop(sub, IP_HDR_LEN);
          struct iphdr* ip = IP_HDR_FROM_SUB(sub);
          printf("Failed to find address in ARP cache, trying again..(%d/5)\n",i);
          err = ip_output(dest_addr, sub);
        });
      }
      // if err is something different than -EAGAIN or is still -EAGAIN after n tries:
      if(err < 0){
        printf("ip_output returned error: %d\n", err);
        return -1;
      } else if(err > 0){
        printf("Written %d bytes to TAP device.\n", err);
      }

      sock_entry->tcp_state.state = SYN_SENT;
      printf("SYN sent\n");
      printf("Waiting on SYN-ACK..\n");

      // wait on SYN-ACK
      pthread_mutex_lock(&sock_entry->tcp_state.sig_mut);

      while(!sock_entry->tcp_state.condition) {
        // wait on SYN-ACK, see ip_rx.c for receiving end.
        printf("mutex1\n");
          pthread_cond_wait(&sock_entry->tcp_state.sig_cond,
                          &sock_entry->tcp_state.sig_mut);
          printf("mutex2\n");
      }
      pthread_mutex_unlock(&sock_entry->tcp_state.sig_mut);
      printf("Received SYN-ACK");

      if(!sock_entry->tcp_state.condition){
          return -1;
      }
      sock_entry->tcp_state.state = ESTABLISHED;
      printf("Sending ACK..\n");

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

        printf("Not yet implemented");
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
