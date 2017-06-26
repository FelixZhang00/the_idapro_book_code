/*
   The IDA Pro Book - Pcap Loader
   Copyright (C) 2008 Chris Eagle <cseagle@gmail.com>
   
   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the Free
   Software Foundation; either version 2 of the License, or (at your option) 
   any later version.
   
   This program is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
   FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for 
   more details.
   
   You should have received a copy of the GNU General Public License along with 
   this program; if not, write to the Free Software Foundation, Inc., 59 Temple 
   Place, Suite 330, Boston, MA 02111-1307 USA
*/

#ifndef __PCAP_H
#define __PCAP_H

//for timeval
#include <sys/time.h>

#define PCAP_MAGIC 0xA1B2C3D4

//from tcpdump.org's pcap.h
struct pcap_file_header {
        uint32 magic;
        uint16 version_major;
        uint16 version_minor;
        int32 thiszone;     /* gmt to local correction */
        uint32 sigfigs;    /* accuracy of timestamps */
        uint32 snaplen;    /* max length saved portion of each pkt */
        uint32 linktype;   /* data link type (LINKTYPE_*) */
};

struct pcap_pkthdr {
        struct timeval ts;      /* time stamp */
        uint32 caplen;     /* length of portion present */
        uint32 len;        /* length this packet (off wire) */
};

#define ETHER_TYPE_IP 0x800

struct ether_header {
   uint8 ether_dhost[6];
   uint8 ether_shost[6];
   uint16 ether_type;
};

#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17

struct iphdr {
   uint8 vhl;
   uint8 tos;
   uint16 tot_len;
   uint16 id;
   uint16 frag_off;
   uint8 ttl;
   uint8 protocol;
   uint16 check;
   uint32 saddr;
   uint32 daddr;
};

struct tcphdr {
   uint16 source;
   uint16 dest;
   uint32 seq;
   uint32 seq_ack;
   uint8 doff;
   uint8 flags;
   uint16 window;
   uint16 check;
   uint16 urg_ptr;
};

struct udphdr {
   uint16 source;
   uint16 dest;
   uint16 len;
   uint16 check;
};

#endif
