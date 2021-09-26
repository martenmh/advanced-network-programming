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
#include "ip.h"
#include "subuff.h"


#ifndef ANPNETSTACK_TCP_H
#define ANPNETSTACK_TCP_H

// Bit Flags
enum state_flag {
  NS = 1 << 9,
  CWR = 1 << 8
  //
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

struct tcphdr {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t seq_num;
  uint32_t ack_num;
  uint8_t data_offset : 4;
  uint8_t reserved : 6;
  // "Inspired" by linux's tcphdr
#if defined(LITTLE_ENDIAN)
    uint8_t fin : 1,
            syn : 1,
            rst : 1,
            psh : 1,
            ack : 1,
            urg : 1;
#elif defined(BIG_ENDIAN)
    uint8_t urg : 1,
            ack : 1,
            psh : 1,
            rst : 1,
            syn : 1,
            fin : 1;
#endif

  uint8_t control_bits : 6; // see control_flags
  uint16_t window;
  uint16_t checksum;
  uint16_t urgent_ptr;
  uint8_t options[];
  // padding
  // data
} __attribute__((packed));

struct variable_options {
  uint8_t kind;
  uint8_t length;
  uint8_t data[];
} __attribute__((packed));

union tcp_options{
  uint8_t option_kind;
  struct variable_options options;
} __attribute__((packed));

static struct subuff* alloc_tcp_sub();

#define TCP_HDR_LEN sizeof(struct tcphdr)

#endif // ANPNETSTACK_TCP_H
