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
#include "tcp.h"
#include "anpwrapper.h"

bool tcp_headers_related(struct tcphdr *tx_hdr, struct tcphdr *rx_hdr) {
  return (ntohl(tx_hdr->seq_num) + 1 == ntohl(rx_hdr->ack_num) && // received sequence number should be seq_num + 1
            tx_hdr->src_port == rx_hdr->dst_port && // received destination port should be our source
            tx_hdr->dst_port == rx_hdr->src_port);  // received source port should be our destination
}

int tcp_rx(struct subuff *sub){
  struct list_head *item;
  struct anp_socket_entry *entry;
  struct iphdr* ip_hdr = IP_HDR_FROM_SUB(sub);
  struct tcphdr* hdr = TCP_HDR_FROM_SUB(sub);

  list_for_each(item, &sockets) {
    printf("item n\n");
    entry = list_entry(item, struct anp_socket_entry, list);
    if(!tcp_headers_related(TCP_HDR_FROM_SUB(entry->tcp_state.tx_sub), hdr)){
      continue;
    }
    printf("Incoming TCP response is related to an existing TCP connection.\n");

    switch(entry->tcp_state.state){
    case SYN_SENT:
//      if(!hdr->syn){
//        printf("Received Impossible state; Expected SYN or SYN-ACK.\n");
//        goto drop_segment;
//      }
      if(hdr->ack){
        //syn_ack();
      } else {

      }
      break;
    case ESTABLISHED:
      break;
    case SYN_RECEIVED:
      break;
    case FIN_WAIT_1:
      break;
    case FIN_WAIT_2:
      break;
    case CLOSE_WAIT:
      break;
    case CLOSING:
      break;
    case LAST_ACK:
      break;
    case TIME_WAIT:
      break;
    case CLOSED:
      break;
    }

    if(entry->tcp_state.state == SYN_SENT && hdr->ack && hdr->syn) {
      printf("Validating Checksum..\n");
      // TODO: correctly validate checksum\
      int err = validate_tcphdr(hdr, ip_hdr->saddr, ip_hdr->daddr);
      int err = 0;
      if(err != 0){
        printf("Checksum of incoming TCP response is incorrect, dropping segment.\n");
        return err;
      }

      printf("Received TCP SYN-ACK\n");
      entry->tcp_state.rx_sub = sub;

      pthread_mutex_lock(&entry->tcp_state.sig_mut);
      entry->tcp_state.condition = true;
      pthread_cond_signal(
          &entry->tcp_state.sig_cond); // signal connect() call
      pthread_mutex_unlock(&entry->tcp_state.sig_mut);
    } else if(hdr->rst){

    }

    printf("Successfully received TCP response.\n");
    return 0;
  }
drop_segment:
  printf("Failed to receive TCP segment.\n");
  return 0;
}

int validate_tcphdr(struct tcphdr* hdr, uint32_t src_addr, uint32_t dst_addr){
  uint16_t old_csum = hdr->checksum;
  hdr->checksum = 0;
  debug_tcp_hdr("checkcheck", hdr);
  uint16_t new_csum = do_tcp_csum((uint8_t *)hdr, hdr->data_offset * 4,
                              htons(IPP_TCP), htonl(src_addr), htonl(dst_addr));

  printf("\n\n debug: old_csum(0x%04x) != new_csum(0x%04x)\n\n", old_csum, new_csum);

  if(old_csum != new_csum){
      return -1;
  }
  return 0;
}

void tcp_csum(struct tcphdr* out_hdr, const struct sockaddr* addr){
  out_hdr->checksum = 0;  // zero checksum before calculating

  uint32_t dest_addr = htonl((((struct sockaddr_in *)addr)->sin_addr).s_addr);
  uint32_t src_addr = ip_str_to_n32(ANP_IP_CLIENT_EXT);

  out_hdr->checksum = do_tcp_csum((uint8_t *)out_hdr, out_hdr->data_offset * 4,
                              htons(IPP_TCP), htonl(src_addr), htonl(dest_addr));
}

struct tcphdr* create_syn(struct tcphdr* hdr, const struct sockaddr* addr){
  hdr->seq_num = htonl(SIMPLE_ISN);
  hdr->ack_num = 0;

  hdr->syn = 0x1;
  hdr->window = htons(TCP_MAX_WINDOW);  // we can receive the max amount

  hdr->data_offset = 0x8; // header contains 8 x 32 bits
  // random port between 1024 and 65536
  srand(time(NULL));
  hdr->src_port = htons(rand()%(65536-1024 + 1) + 1024);
  hdr->reserved = 0b0000;
  hdr->dst_port = ((struct sockaddr_in *)addr)->sin_port;
  hdr->checksum = 0;  // zero checksum before calculating

  uint32_t dest_addr = htonl((((struct sockaddr_in *)addr)->sin_addr).s_addr);
  uint32_t src_addr = ip_str_to_n32(ANP_IP_CLIENT_EXT);

  hdr->checksum = (do_tcp_csum((uint8_t *)hdr, hdr->data_offset * 4,
                              htons(IPP_TCP), htonl(src_addr), htonl(dest_addr))) - htons(256);
  return hdr;
}

int tcp_output(uint32_t dest_addr, struct subuff* sub){
  int err = ip_output(dest_addr, sub);

  if(err == -EAGAIN) {
    try_again(5, 1, err == -EAGAIN, {
      // important line. If you run the ip_output multiple times
      // the tx_sub continually gets pushed to without being popped
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
  return 0;
}

struct subuff* alloc_tcp_sub(){
    struct subuff *sub = alloc_sub(MIN_ALLOCATED_TCP_SUB);
    sub_reserve(sub, MIN_ALLOCATED_TCP_SUB);
    sub->protocol = IPP_TCP;
    return sub;
}

struct subuff* alloc_tcp_payload(size_t payload){
    struct subuff *sub = alloc_sub(MIN_ALLOCATED_TCP_SUB + payload);
    sub_reserve(sub, MIN_ALLOCATED_TCP_SUB + payload);
    sub->protocol = IPP_TCP;
    return sub;
}

uint8_t *sub_pop(struct subuff *sub, unsigned int len) {
  sub->data += len;
  sub->len -= len;
  return sub->data;
}
