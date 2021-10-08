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

#ifndef ANPNETSTACK_ANPWRAPPER_H
#define ANPNETSTACK_ANPWRAPPER_H

#include "linklist.h"
#include "tcp.h"
#include "utilities.h"
#include "config.h"

#define MIN_SOCKFD 1000000



struct anp_socket_entry {
  struct list_head list;

  pthread_mutex_t tcp_state_mut;
  struct tcp_sock_state tcp_state;

  int sockfd;

  uint32_t dest_addr;
  uint16_t dest_port;

  uint32_t src_addr;
  uint16_t src_port;

  //struct recv_packet_entry recv_packets;

};

/**
 * Thread safe getter for the tcp_state struct
 * @param socket_entry
 * @return
 */
struct tcp_sock_state* get_tcp_state(struct anp_socket_entry* socket_entry);

// shared between thread, defined in .c
// TODO: add a mutex & encapsulate in a struct
extern struct list_head sockets;
extern uint32_t sockets_size;


void _function_override_init();

// Abusing macro's a bit to function like lambdas
#define try_again(max_tries, secdelay, cond, func)   \
  do{                                                \
      for(int i = 1; cond && i <= max_tries; i++){   \
        func;                                        \
        sleep(secdelay);                             \
      }                                              \
  } while(false)

#endif //ANPNETSTACK_ANPWRAPPER_H
