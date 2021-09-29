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

#include <endian.h>

#ifndef ANPNETSTACK_TCP_H
#define ANPNETSTACK_TCP_H


#define debug_tcp_hdr(msg, hdr)                                                \
  printf("TCP (HDR) "msg" (src_port: %hu, dst_port: %u, seq_num: %u, ack_nuk: %u, data_offset %hhu, \
        reserved: %hhu, [urg: %hhu, ack: %hhu, psh: %hhu, rst: %hhu, syn: %hhu, fin: %hu], window: %hu, csum: 0x%04x, urg_ptr: %hu\n", \
                 hdr->src_port, hdr->dst_port, hdr->seq_num, hdr->ack_num, hdr->data_offset, hdr->reserved, hdr->urg, hdr->ack, hdr->psh, hdr->rst, hdr->syn, hdr->fin, \
                 hdr->window, hdr->checksum, hdr->urgent_ptr  \
                 )


// Bit Flags
enum state_flag {
  NS = 1 << 9,
  CWR = 1 << 8
  //
};

enum TCP_STATE {
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
#if __BYTE_ORDER == __LITTLE_ENDIAN
  uint8_t reserved : 4;
  uint8_t data_offset : 4;  // header length
#elif __BYTE_ORDER == __BIG_ENDIAN
  uint8_t data_offset : 4;  // header length
  uint8_t reserved : 4;
#endif

  // "Inspired" by linux's tcphdr
#if __BYTE_ORDER == __LITTLE_ENDIAN
  uint8_t fin : 1,
      syn : 1,
      rst : 1,
      psh : 1,
      ack : 1,
      urg : 1,
      ece : 1,
      cwr : 1;
#elif __BYTE_ORDER == __BIG_ENDIAN
  uint8_t fin : 1,
      syn : 1,
      rst : 1,
      psh : 1,
      ack : 1,
      urg : 1;
#endif
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

struct subuff* alloc_tcp_sub();

struct tcp_sock_state {
  // signalling
  pthread_mutex_t sig_mut;
  pthread_cond_t sig_cond;
  bool condition;
  // state information
  enum TCP_STATE state; // current state in TCP state machine
  //struct tcphdr prev_hdr;
  struct subuff* sub;
};

int tcp_rx(struct subuff *sub);
bool tcp_headers_related(struct tcphdr* tx_hdr, struct tcphdr* rx_hdr);

#define TCP_HDR_LEN sizeof(struct tcphdr)
// TODO: Implement
#define TCP_PAYLOAD_LEN(_tcp) assert(false)
#define TCP_HDR_FROM_SUB(_sub) (struct tcphdr *)(_sub->head + IP_HDR_LEN + ETH_HDR_LEN)

#define MIN_ALLOCATED_TCP_SUB 64
#define TCP_CONNECT_TIMEOUT 10000 // 10 sec
#define TCP_SEQ_START 1024  // really trivial but useful for debugging
#endif // ANPNETSTACK_TCP_H
