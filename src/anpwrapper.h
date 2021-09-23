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

#define MIN_SOCKFD 1000000

// Bit Flags
enum state_flag {
  NS = 1 << 9,
  CWR = 1 << 8
  //
};

enum control_flags {
  URG = 1 << 5,
  ACK = 1 << 4,
  PSH = 1 << 3,
  RST = 1 << 2,
  SYN = 1 << 1,
  FIN = 1
};

enum socket_state {
  LISTEN,
  SYN_SENT,
  SYN_RECEIVED,
  ESTABLISHED,
  FIN_WAIT_1,
  FIN_WAIT_2,
  CLOSE_WAIT,
  CLOSING,
  LAST_ACK,
  TIME_WAIT,
  CLOSED
};

struct tcp_hdr {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t seq_num;
  uint32_t ack_num;
  uint8_t data_offset : 4;
  uint8_t reserved : 6;
  uint8_t control_bits : 6; // see control_flags
  uint16_t window;
  uint16_t checksum;
} __attribute__((packed));

struct anp_socket_entry {
  struct list_head list;
  enum socket_state state;
  int sockfd;
};

struct anp_socket_head {
  struct list_head head;
  uint32_t length;
};

//static LIST_HEAD(sock_cache);

void _function_override_init();

#endif //ANPNETSTACK_ANPWRAPPER_H
