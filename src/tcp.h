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
  printf("TCP (HDR) "msg" (src_port: %hu, dst_port: %u, seq_num: %u, ack_num: %u, data_offset %hhu, \
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
  LISTEN, // not implemented
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

extern struct list_head recv_packets;
extern uint32_t recv_packets_size;
extern pthread_mutex_t recv_packets_mut;

struct recv_packet_entry {
  struct list_head list;
  // identification
  uint32_t rx_seq_num;
  int sockfd;
  // buffer
  size_t length;
  void* buffer;
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
  uint8_t fin : 1;
  uint8_t syn : 1;
  uint8_t rst : 1;
  uint8_t psh : 1;
  uint8_t ack : 1;
  uint8_t urg : 1;
  uint8_t ece : 1;
  uint8_t cwr : 1;
  #elif __BYTE_ORDER == __BIG_ENDIAN
  uint8_t fin : 1;
  uint8_t syn : 1;
  uint8_t rst : 1;
  uint8_t psh : 1;
  uint8_t ack : 1;
  uint8_t urg : 1;
  #endif

  uint16_t window;
  uint16_t checksum;
  uint16_t urgent_ptr;
  uint8_t data[];
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

struct subuff *alloc_tcp_sub();
struct subuff *alloc_tcp_payload(size_t payload);

struct tcp_sock_state {
  // signalling 1
  pthread_mutex_t sig_mut;
  pthread_cond_t sig_cond;
  volatile bool condition;
  // singalling 2
  pthread_mutex_t sig_mut2;
  pthread_cond_t sig_cond2;
  volatile bool condition2;

  // state information
  volatile enum TCP_STATE state; // current state in TCP state machine
  //struct tcphdr prev_hdr;
  volatile struct subuff* tx_sub;
  volatile struct subuff* rx_sub;

  volatile uint32_t sequence_num;
};

int tcp_rx(struct subuff *sub);
bool tcp_headers_related(struct tcphdr* tx_hdr, struct tcphdr* rx_hdr);
struct tcphdr *create_syn(struct tcphdr* hdr, const struct sockaddr* addr);

//void tcp_acknowledge(){
//
//}
int tcp_output(uint32_t dst_addr, struct subuff* sub);
int validate_tcphdr(struct tcphdr* hdr, uint32_t src_addr, uint32_t dst_addr);
uint8_t *sub_pop(struct subuff *sub, unsigned int len);
void tcp_csum(struct tcphdr* out_hdr, const struct sockaddr* addr);

#define TCP_HDR_LEN 32
#define TCP_PADDED_HDR_LEN(_sub) ((TCP_HDR_FROM_SUB(_sub))->data_offset * 4)
#define TCP_PAYLOAD_LEN(_sub) ((IP_PAYLOAD_LEN((IP_HDR_FROM_SUB(_sub)))) - (TCP_PADDED_HDR_LEN(_sub)))
#define TCP_PAYLOAD_FROM_SUB(_sub) ((void *)(_sub->head + IP_HDR_LEN + ETH_HDR_LEN + ((TCP_HDR_FROM_SUB(_sub))->data_offset) * 4))
#define TCP_HDR_FROM_SUB(_sub) (struct tcphdr *)(_sub->head + IP_HDR_LEN + ETH_HDR_LEN)

#define TCP_MAX_WINDOW 65495

// Initial Sequence Number (ISN)
#define SIMPLE_ISN  0xC0FFEE  //  unsafe but arbitrary in this case
#define MIN_PADDED_TCP_LEN (MIN_ALLOCATED_TCP_SUB - ( IP_HDR_LEN + ETH_HDR_LEN))
#define MIN_ALLOCATED_TCP_SUB 66
#define TCP_CONNECT_TIMEOUT 10000 // 10 sec
#define TCP_SEQ_START 1024  // really trivial but useful for debugging
#endif // ANPNETSTACK_TCP_H
