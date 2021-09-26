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

bool tcp_headers_related(struct tcphdr *tx_hdr, struct tcphdr *rx_hdr) {
  return (tx_hdr->seq_num + 1 == rx_hdr->seq_num && // received sequence number should be seq_num + 1
            tx_hdr->src_port == rx_hdr->dst_port && // received destination port should be our source
            tx_hdr->dst_port == rx_hdr->src_port);  // received source port should be our destination
}

int tcp_rx(struct subuff *sub){
    // TODO: Replace ip_rx.c TCP path
}

struct subuff* alloc_tcp_sub(){
    struct subuff *sub = alloc_sub(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
    sub_reserve(sub, ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
    sub->protocol = htons(IPP_TCP);
    return sub;
}