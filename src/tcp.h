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

#ifndef ANPNETSTACK_TCP_H
#define ANPNETSTACK_TCP_H

#include "ip.h"
#include "subuff.h"
#include <endian.h>

#define debug_tcp_hdr(msg, hdr)                                                \
  printf("\nTCP (HDR) "msg" (src_port: %hu, dst_port: %u, seq_num: %u, ack_num: %u, data_offset: %hhu, "\
        "reserved: %hhu, [urg: %hhu, ack: %hhu, psh: %hhu, rst: %hhu, syn: %hhu, fin: %hu], window: %hu, csum: 0x%04x, urg_ptr: %hu\n", \
        hdr->src_port, hdr->dst_port, hdr->seq_num, hdr->ack_num, hdr->data_offset, hdr->reserved, hdr->urg, hdr->ack, hdr->psh, hdr->rst, hdr->syn, hdr->fin, \
        hdr->window, hdr->checksum, hdr->urgent_ptr  \
        ) // debugging tool using the same logic as debug ip

// TCP states used in the state machine, not all states are currently implemented
enum TCP_STATE {
    LISTEN    = 0,
    SYN_SENT  = 1,
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

// TCP header structure, options are not yet implemented
struct tcphdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t reserved: 4;
    uint8_t data_offset: 4;  // header length in bit words
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t data_offset : 4;  // header length in bit words
    uint8_t reserved : 4;
#endif
    // "Inspired" by linux's tcphdr
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t fin: 1;
    uint8_t syn: 1;
    uint8_t rst: 1;
    uint8_t psh: 1;
    uint8_t ack: 1;
    uint8_t urg: 1;
    uint8_t ece: 1;
    uint8_t cwr: 1;
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
    uint8_t options[];
} __attribute__((packed));

// TCP state machine structure
struct tcp_sock_state {
    // signalling 1
    pthread_mutex_t sig_mut;
    pthread_cond_t sig_cond;
    volatile bool condition;
    // signalling 2
    pthread_mutex_t sig_mut2;
    pthread_cond_t sig_cond2;
    volatile bool condition2;
    // state information
    volatile enum TCP_STATE state; // current state in TCP state machine
    volatile struct subuff *tx_sub;
    volatile struct subuff *rx_sub;
    volatile bool failed;
};

struct recv_packet_entry {
    struct list_head list;
    // identification
    uint32_t rx_seq_num;
    int sockfd;
    // buffer
    size_t length;
    void *buffer;
};


extern struct list_head recv_packets;
extern uint32_t recv_packets_size;
pthread_mutex_t recv_packets_mut;


// useful functions
bool tcp_headers_related(struct tcphdr *tx_hdr, struct tcphdr *rx_hdr);
struct subuff *alloc_tcp_sub();
struct subuff *alloc_tcp_payload(size_t payload);
struct tcphdr *create_syn(struct tcphdr *hdr, const struct sockaddr *addr);
int tcp_rx(struct subuff *sub);
int tcp_output(uint32_t dst_addr, struct subuff *sub);
int validate_csum(struct tcphdr *hdr, uint32_t src_addr, uint32_t dst_addr);
uint8_t *sub_pop(struct subuff *sub, unsigned int len);


// useful macros and constants
#define TCP_HDR_FROM_SUB(_sub) (struct tcphdr *)((_sub)->head + IP_HDR_LEN + ETH_HDR_LEN)
#define TCP_PADDED_HDR_LEN(_sub) ((TCP_HDR_FROM_SUB(_sub))->data_offset * 4)
#define TCP_PAYLOAD_LEN(_sub) ((IP_PAYLOAD_LEN((IP_HDR_FROM_SUB(_sub)))) - (TCP_PADDED_HDR_LEN(_sub)))
#define TCP_PAYLOAD_FROM_SUB(_sub) ((void *)((_sub)->head + IP_HDR_LEN + ETH_HDR_LEN + ((TCP_HDR_FROM_SUB(_sub))->data_offset) * 4))
#define TCP_HDR_LEN 32 // TCP header length for 8 bit words long header
#define TCP_MAX_WINDOW 65495 // max possible window size of a TCP packet
#define TCP_SERVER_MSS 1460 // maximum payload segment size that can be transported in a single packet, set by the server, but can be adjusted

// Initial Sequence Number (ISN)
#define SIMPLE_ISN  0xC0FFEE  // unsafe but arbitrary in this case
#define TCP_CONNECT_TIMEOUT 10000 // 10 sec


#endif // ANPNETSTACK_TCP_H