/*
 Copyright 2021 Lin Wang
 This code is part of the Advanced Network Programming (2021) course at
 Vrije Universiteit Amsterdam.
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
      https://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<48>  EthernetAddress;
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_h {
  EthernetAddress dstAddr;
  EthernetAddress srcAddr;
  bit<16>         etherType;
}

header ipv4_t {
  bit<4>    version;
  bit<4>    ihl;
  bit<8>    diffserv;
  bit<16>   totalLen;
  bit<16>   identification;
  bit<3>    flags;
  bit<13>   fragOffset;
  bit<8>    ttl;
  bit<8>    protocol;
  bit<16>   hdrChecksum;
  ip4Addr_t srcAddr;
  ip4Addr_t dstAddr;
}

header tcp_t{
  bit<16> srcPort;
  bit<16> dstPort;
  bit<32> seqNo;
  bit<32> ackNo;
  bit<4>  dataOffset;
  bit<4>  res;
  bit<1>  cwr;
  bit<1>  ece;
  bit<1>  urg;
  bit<1>  ack;
  bit<1>  psh;
  bit<1>  rst;
  bit<1>  syn;
  bit<1>  fin;
  bit<16> window;
  bit<16> checksum;
  bit<16> urgentPtr;
}

header srcRoute_t {
  bit<1>    bos;
  bit<15>   port;
}

struct metadata {
  /* empty */
}

struct headers {
  ethernet_h  ethernet;
  ipv4_t      ipv4;
  tcp_t       tcp;

}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

// Parse all headers up to the TCP header
parser MyParser(packet_in packet,
         out headers hdr,
         inout metadata meta,
         inout standard_metadata_t standard_metadata) {

  state start {
    transition parse_ethernet;
  }

  state parse_ethernet{
    packet.extract(hdr.ethernet);
    transition select(hdr.ethernet.etherType){
    TYPE_IPV4: parse_ipv4;
    default: accept;
    }
  }

  state parse_ipv4{
    packet.extract(hdr.ipv4);
    // if the protocol is TCP, parse a TCP header
    transition select(hdr.ipv4.protocol){
      6 : parse_tcp;
    default: accept;
    }
  }

  state parse_tcp{
    // extract binary data into a TCP header
    packet.extract(hdr.tcp);
    transition accept;
  }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/
// what's security?
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
  apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
  action drop() {
    mark_to_drop(standard_metadata);
  }

  // forward a IPv4 packet, see topo/s*-runtime.json for arguments
  action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
    standard_metadata.egress_spec = port;
    hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
    hdr.ethernet.dstAddr = dstAddr;
    hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
  }

  // forward a TCP ack packet, see topo/s*-runtime.json for arguments
  action tcp_ack_forward(macAddr_t dstAddr, egressSpec_t port) {
      ipv4_forward(dstAddr, port);
  }

  action multicast_forward(bit<16> mcast_grp) {
      standard_metadata.mcast_grp = mcast_grp;
  }

  // IPv4 table
  table ipv4_lpm {
    key = {
      hdr.ipv4.dstAddr : lpm;
    }
    actions = {
      ipv4_forward;
      drop;
      NoAction;
    }

    size = 1024;
    default_action = drop();
  }

  // table for TCP ack packets, same as IPv4. However, the magic is in topo/s*-runtime.json
  table tcp_ack_exact {
    key = {
      hdr.ipv4.dstAddr : lpm;
    }
    actions = {
      tcp_ack_forward;
      drop;
      NoAction;
    }
    size = 1024;
    default_action = drop();
  }

    table tcp_duplicate {
            key = {
                    hdr.ipv4.dstAddr : lpm;
            }
            actions = {
                multicast_forward;
                drop;
                NoAction;
            }
            size = 1024;
            default_action = drop();
    }

  apply {
    // if packet has only ack flag, then multicast it
    if (hdr.tcp.isValid() && hdr.tcp.ack == 1 && hdr.tcp.syn == 0 && hdr.tcp.fin == 0) {
      tcp_duplicate.apply();
    // if packet is an ACK, send to 1-3-2 path
    } else if (hdr.tcp.isValid() && hdr.tcp.ack == 1) {
        tcp_ack_exact.apply();
    } else if (hdr.ipv4.isValid()) { // send all others to 1-2 path
      ipv4_lpm.apply();
    }
  }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
  apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
  apply {
    update_checksum(
        hdr.ipv4.isValid(),
        { hdr.ipv4.version,
         hdr.ipv4.ihl,
         hdr.ipv4.diffserv,
         hdr.ipv4.totalLen,
         hdr.ipv4.identification,
         hdr.ipv4.flags,
         hdr.ipv4.fragOffset,
         hdr.ipv4.ttl,
         hdr.ipv4.protocol,
         hdr.ipv4.srcAddr,
         hdr.ipv4.dstAddr },
        hdr.ipv4.hdrChecksum,
        HashAlgorithm.csum16);
  }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
  apply {
    packet.emit(hdr.ethernet);
    packet.emit(hdr.ipv4);
    packet.emit(hdr.tcp); // important to add this, don't know why but it's necessary for correctly parsing
  }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
  MyParser(),
  MyVerifyChecksum(),
  MyIngress(),
  MyEgress(),
  MyComputeChecksum(),
  MyDeparser()
) main;