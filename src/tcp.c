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
  return (tx_hdr->seq_num + 1 == rx_hdr->seq_num && // received sequence number should be seq_num + 1
            tx_hdr->src_port == rx_hdr->dst_port && // received destination port should be our source
            tx_hdr->dst_port == rx_hdr->src_port);  // received source port should be our destination
}

int tcp_rx(struct subuff *sub){
  struct list_head *item;
  struct anp_socket_entry *entry;
  list_for_each(item, &sockets) {
    entry = list_entry(item, struct anp_socket_entry, list);
    struct tcphdr* hdr = TCP_HDR_FROM_SUB(sub);
    if(!tcp_headers_related(TCP_HDR_FROM_SUB(entry->tcp_state.sub), hdr)){
      continue;
    }
    if(entry->tcp_state.state == SYN_SENT) {
      if(!hdr->ack || !hdr->syn) continue;

      pthread_mutex_lock(&entry->tcp_state.sig_mut);
      entry->tcp_state.condition = true;
      pthread_cond_signal(
          &entry->tcp_state.sig_cond); // signal connect() call
      pthread_mutex_unlock(&entry->tcp_state.sig_mut);
    }
  }
}

struct subuff* alloc_tcp_sub(){
    struct subuff *sub = alloc_sub(66);
    sub_reserve(sub, 66);
    sub->protocol = IPP_TCP;
    return sub;
}