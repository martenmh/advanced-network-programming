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

#include "icmp.h"
#include "ip.h"
#include "tap_netdev.h"
#include "utilities.h"

void icmp_rx(struct subuff *sub)
{
    //FIXME: implement your ICMP packet processing implementation here
    //    ICMP_V4_ECHO
    //figure out various type of ICMP packets, and implement the ECHO response type (icmp_reply)

    struct iphdr *ip_hdr = IP_HDR_FROM_SUB(sub);
    struct icmp_hdr*icmp_hdr = (struct icmp_hdr *)(ip_hdr->data);
    uint16_t icmp_len = ip_hdr->len - IP_HDR_LEN;

    debug_icmp(icmp_hdr, icmp_len);

    uint16_t rx_csum = icmp_hdr->checksum;

    icmp_hdr->checksum = 0; // zero checksum before computing it
    uint16_t csum = do_csum(icmp_hdr, icmp_len, 0);

    if(csum != rx_csum){
      printf("Error: ICMP Checksums do not match.");
      goto drop_pkt;
    }

    switch(icmp_hdr->type){
    case ICMP_V4_ECHO:
      u32_ip_to_str("Read ICMP ECHO request from:", ip_hdr->saddr);
      icmp_reply(sub);
      break;
    case ICMP_V4_REPLY:
      u32_ip_to_str("Read ICMP reply from:", ip_hdr->saddr);
      break;

    case 3: // Destination
      switch(icmp_hdr->code){
      case 0: printf("Destination network unreachable.\n"); break;
      case 1: printf("Destination host unreachable.\n"); break;
      case 2: printf("Destination protocol unreachable.\n"); break;
      case 3: printf("Destination port unreachable.\n"); break;
      case 6: printf("Destination network unknown.\n"); break;
      case 7: printf("Destination host unknown.\n"); break;
      default: printf("Error: Unknown ICMP code: '%i'.\n", icmp_hdr->code);
      }
      break;
    case 4: printf("Source quench (congestion control).\n"); break;
    case 9: printf("Router advertisement.\n"); break;
    case 10: printf("Router discovery.\n"); break;
    case 11: printf("TTL expired.\n"); break;
    case 12: printf("IP header bad.\n"); break;
    default: printf("Error: Unknown ICMP type: '%i'.\n", icmp_hdr->type);
    }
    drop_pkt:
    free_sub(sub);
}

void icmp_reply(struct subuff *sub) {
    struct iphdr *ip_hdr = IP_HDR_FROM_SUB(sub);
    uint16_t icmp_len = ip_hdr->len - IP_HDR_LEN;

    // prepare the subuff for ip_output
    sub_reserve(sub, ETH_HDR_LEN + IP_HDR_LEN + icmp_len);
    // push back the ICMP header
    sub_push(sub, icmp_len);

    struct icmp_hdr*icmp_hdr = (struct icmp_hdr *)(ip_hdr->data);
    icmp_hdr->code = 0;
    icmp_hdr->type = ICMP_V4_REPLY;

    icmp_hdr->checksum = 0;  // zero checksum before computing it
    icmp_hdr->checksum = do_csum(icmp_hdr, icmp_len, 0);

    // set protocol to ICMP
    sub->protocol = IPP_NUM_ICMP;

    u32_ip_to_str("Sending ICMP reply to: ", ip_hdr->saddr);
    debug_icmp(icmp_hdr, icmp_len);

    // set destination to the source of ICMP ECHO, and send the prepared subuff
    ip_output(ip_hdr->saddr, sub);
}
