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

static LIST_HEAD(sockets);
static uint32_t sockets_size = 0;


struct anp_socket_entry {
  struct list_head list;
  struct tcp_sock_state tcp_state;
  int sockfd;
};

void _function_override_init();
#define try_again(n, secdelay, cond, func) do{ for(int i = 1; cond && i <= n; i++){ func; sleep(secdelay); }} while(false)
#endif //ANPNETSTACK_ANPWRAPPER_H
