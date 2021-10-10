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
#include "utilities.h"

LIST_HEAD(recv_packets);
uint32_t recv_packets_size = 0;

bool tcp_headers_related(struct tcphdr *tx_hdr, struct tcphdr *rx_hdr) {
    return (ntohl(tx_hdr->seq_num) + 1 == ntohl(rx_hdr->ack_num) && // received sequence number should be seq_num + 1
            tx_hdr->src_port == rx_hdr->dst_port && // received destination port should be our source
            tx_hdr->dst_port == rx_hdr->src_port);  // received source port should be our destination
}

void wake_up_tcp(struct anp_socket_entry* entry, bool failed){
  pthread_mutex_lock(&entry->tcp_state.sig_mut);
  entry->tcp_state.condition = true;
  entry->tcp_state.failed = failed;
  pthread_cond_signal(&entry->tcp_state.sig_cond); // signal connect() call
  pthread_mutex_unlock(&entry->tcp_state.sig_mut);

  pthread_mutex_lock(&entry->tcp_state.sig_mut);
  entry->tcp_state.condition = false;
  pthread_mutex_unlock(&entry->tcp_state.sig_mut);
}

int tcp_rx(struct subuff *sub) {
    struct list_head *item;
    struct anp_socket_entry *entry;
    struct tcphdr *hdr = TCP_HDR_FROM_SUB(sub);

    list_for_each(item, &sockets) {
        entry = list_entry(item, struct anp_socket_entry, list);

        if (!tcp_headers_related(TCP_HDR_FROM_SUB(entry->tcp_state.tx_sub), hdr)) {
            continue;
        }

        async_printf("Incoming TCP response is related to an existing TCP connection \n");
        pthread_mutex_lock(&entry->tcp_state_mut);
        entry->tcp_state.rx_sub = sub;
        enum TCP_STATE tcp_state = entry->tcp_state.state;
        pthread_mutex_unlock(&entry->tcp_state_mut);
        async_printf("\nTCP state = %d\n", tcp_state);
        switch (tcp_state) {
            case SYN_SENT:
                if (hdr->ack == 1 && hdr->syn == 1) {
                    async_printf("\nIncoming TCP SYN-ACK \n");
                    async_printf("Validating checksum..... \n");
                    // validate checksum of the incoming packet
                    //int err = validate_csum(hdr, entry->src_addr, entry->dst_addr);
                    int err = 0;
                    if (err != 0) {
                        async_printf("\nChecksum of incoming TCP response is incorrect, dropping segment \n");
                        return err;
                    } else { // lock tcp_state
                        pthread_mutex_lock(&entry->tcp_state_mut);
                        entry->tcp_state.rx_sub = sub;

                        // send signal to waiting connect():
                        wake_up_tcp(entry, false);

                        pthread_mutex_unlock(&entry->tcp_state_mut);
                    } // unlock tcp_state
                } else {
                  async_printf("Incoming TCP packet is not SYN ACK\n");

                  pthread_mutex_lock(&entry->tcp_state_mut);
                  entry->tcp_state.rx_sub = sub;
                  wake_up_tcp(entry, true);
                  pthread_mutex_unlock(&entry->tcp_state_mut);
                }
                break;

            case ESTABLISHED:
                // although the implementation isn't great as we're copying the entire payload..
                // it seems to be the only way the implementation stays correct
                // create a recv_packets entry
                async_printf("allocating recv_entry \n");
                struct recv_packet_entry *recv_entry = calloc(1, sizeof(struct recv_packet_entry));
                list_init(&recv_entry->list);
                recv_entry->rx_seq_num = (TCP_HDR_FROM_SUB(sub))->seq_num;
                recv_entry->rx_ack_num = (TCP_HDR_FROM_SUB(sub))->ack_num;
                recv_entry->sockfd = entry->sockfd;

                recv_entry->length = TCP_PAYLOAD_LEN(sub);
                // allocate a buffer and copy payload into it

                //recv_entry->buffer = calloc(1, recv_entry->length);
                recv_entry->buffer = malloc(recv_entry->length);
                async_printf("Reading entry with length of: %zu \n", recv_entry->length);
                wireshark_print(TCP_PAYLOAD_FROM_SUB(sub), TCP_PAYLOAD_LEN(sub));

                memcpy(recv_entry->buffer, TCP_PAYLOAD_FROM_SUB(sub), recv_entry->length);
                async_printf("Copied! \n");

                pthread_mutex_lock(&recv_packets_mut);
                list_add_tail(&recv_entry->list, &recv_packets);
                pthread_mutex_unlock(&recv_packets_mut);

                async_printf("Received TCP packet designated for recv() \n");
                pthread_mutex_lock(&entry->tcp_state_mut);
                entry->tcp_state.rx_sub = sub;
                async_printf("copied entry, signalling now! \n");
                // signal waiting recv() call
                wake_up_tcp(entry, false);

                pthread_mutex_unlock(&entry->tcp_state_mut);
                async_printf("signalled \n");
                break;

            case SYN_RECEIVED:
                break;
            case FIN_WAIT_1:
                break;
            case FIN_WAIT_2:
                break;
            case CLOSE_WAIT:
              printf("\nReceived FIN-ACK......\n");
              entry->tcp_state.rx_sub = sub;
              wake_up_tcp(entry, false);
                break;
            case CLOSING:
                break;
            case LAST_ACK:
                break;
            case TIME_WAIT:
                break;
            case CLOSED:
                break;
            case LISTEN:
                break;

            default:
                async_printf("\nUnknown TCP state: %d \n", tcp_state);
                return -1;
        }
    }

    async_printf("\nSuccessfully received TCP response!\n");
    return 0;
}

int validate_csum(struct tcphdr *hdr, uint32_t src_addr, uint32_t dst_addr) {
    uint16_t old_csum = hdr->checksum;
    hdr->checksum = 0;
    uint16_t new_csum = do_tcp_csum((uint8_t *) hdr, hdr->data_offset * 4, IPP_TCP, src_addr, dst_addr);
    if (old_csum != new_csum) {
        return -1;
    }
    return 0;
}

struct tcphdr *create_syn(struct tcphdr *hdr, const struct sockaddr *addr) {
    hdr->src_port = htons(random_port(1024, 65536)); // min 1024, max 65536
    hdr->dst_port = ((struct sockaddr_in *) addr)->sin_port;
    hdr->seq_num = htonl(SIMPLE_ISN);
    hdr->ack_num = htonl(0);
    hdr->data_offset = 8; // header contains 8 x 32 bits
    hdr->syn = 1;
    hdr->window = htons(TCP_MAX_WINDOW);  // max amount can be received, not the best option, but currently works
    uint32_t dst_addr = ip_str_to_n32(inet_ntoa(((struct sockaddr_in *) addr)->sin_addr));
    uint32_t src_addr = ip_str_to_n32(ANP_IP_CLIENT_EXT);
    hdr->checksum = 0;  // zeroing checksum before recalculating
    hdr->checksum = do_tcp_csum((uint8_t *) hdr, TCP_HDR_LEN, IPP_TCP, src_addr, dst_addr);

    return hdr;
}

/**
 * Wrapper around ip_output with additional error checking and redoing method
 * @param dst_addr
 * @param sub
 * @return
 */

int tcp_output(uint32_t dst_addr, struct subuff *sub) {
    int err = ip_output(dst_addr, sub);

    if (err == -EAGAIN) {
        try_again(5, 1, err == -EAGAIN, {
            // important line. If you run the ip_output multiple times
            // the tx_sub continually gets pushed to without being popped
            sub_pop(sub, IP_HDR_LEN);
            struct iphdr *ip = IP_HDR_FROM_SUB(sub);
            printf("\nFailed to find the address in ARP cache, trying again...... (%d/5)\n", i);
            err = ip_output(dst_addr, sub);
        });
    }
    // if err is something different from -EAGAIN or is still -EAGAIN after n tries:
    if (err < 0) {
        async_printf("\nip_output returned error: %d\n", err);
        return -1;
    }
    printf("\nPacket is sent successfully!\n");
    printf("Written %d bytes to TAP device\n", err);
    return 0;
}

struct subuff *alloc_tcp_sub() {
    struct subuff *sub = alloc_sub(TCP_HDR_LEN + IP_HDR_LEN + ETH_HDR_LEN); // MIN_ALLOCATED_TCP_SUB
    sub_reserve(sub, TCP_HDR_LEN + IP_HDR_LEN + ETH_HDR_LEN); // MIN_ALLOCATED_TCP_SUB
    sub->protocol = IPP_TCP;
    return sub;
}

struct subuff *alloc_tcp_payload(size_t payload) {
    struct subuff *sub = alloc_sub(TCP_HDR_LEN + IP_HDR_LEN + ETH_HDR_LEN + payload);
    sub_reserve(sub, TCP_HDR_LEN + IP_HDR_LEN + ETH_HDR_LEN + payload);
    sub->protocol = IPP_TCP;
    return sub;
}

uint8_t *sub_pop(struct subuff *sub, unsigned int len) {
    sub->data += len;
    sub->len -= len;
    return sub->data;
}
