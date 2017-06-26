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

/* Pcap loader
 * This loader loads pcap capture files
 */

#include "../idaldr.h"
#include <typeinf.hpp>
#include "pcap_loader.h"

//--------------------------------------------------------------------------
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//
static int idaapi accept_pcap_file(linput_t *li,
                       char fileformatname[MAX_FILE_FORMAT_NAME], int n) {
   uint32   magic;
   // read as much of the file as you need to to determine whether
   // it is something that you recognize
   if(n || lread4bytes(li, &magic, false)) {  //read as little endian by default
      return 0;
   }
   if (magic != PCAP_MAGIC) {
      return 0;
   }
   //if you recognize the file, then say so
   qsnprintf(fileformatname, MAX_FILE_FORMAT_NAME, "Ida Pcap Loader");
   return 1;
}

//----------------------------------------------------------------------
//      initialize user configurable options based on the input file.
static bool idaapi init_loader_options(linput_t*) {
   //set the processor type
   set_processor_type("metapc", SETPROC_ALL|SETPROC_FATAL);
   return true;
}

char *pcap_types = 
   "struct timeval {\n"
      "int tv_sec;\n"
      "int tv_usec;\n"
   "};\n"
   "struct pcap_file_header {\n"
        "int magic;\n"
        "short version_major;\n"
        "short version_minor;\n"
        "int thiszone;\n"
        "int sigfigs;\n"
        "int snaplen;\n"
        "int linktype;\n"
   "};\n"
   "struct pcap_pkthdr {\n"
        "struct timeval ts;\n"
        "int caplen;\n"
        "int len;\n"
   "};\n"

   "struct ether_header {\n"
      "char ether_dhost[6];\n"
      "char ether_shost[6];\n"
      "short ether_type;\n"
   "};\n"
   
   "struct iphdr {\n"
      "char vhl;\n"
      "char tos;\n"
      "short tot_len;\n"
      "short id;\n"
      "short frag_off;\n"
      "char ttl;\n"
      "char protocol;\n"
      "short check;\n"
      "int saddr;\n"
      "int daddr;\n"
   "};\n"
   
   "struct tcphdr {\n"
      "short source;\n"
      "short dest;\n"
      "int seq;\n"
      "int seq_ack;\n"
      "char doff;\n"
      "char flags;\n"
      "short window;\n"
      "short check;\n"
      "short urg_ptr;\n"
   "};\n"
   
   "struct udphdr {\n"
      "short source;\n"
      "short dest;\n"
      "short len;\n"
      "short check;\n"
   "};\n";
      
static tid_t pcap_hdr_struct;
static tid_t pkthdr_struct;
static tid_t ether_struct;
static tid_t ip_struct;
static tid_t tcp_struct;
static tid_t udp_struct;

void add_types() {
/*
#ifdef ADDTIL_DEFAULT
   add_til2("gnuunx.til", ADDTIL_SILENT);
#else
   add_til("gnuunx.til");
#endif
   pcap_hdr_struct = til2idb(-1, "pcap_file_header");
   pkthdr_struct = til2idb(-1, "pcap_pkthdr");
   ether_struct = til2idb(-1, "ether_header");
   ip_struct = til2idb(-1, "iphdr");
   tcp_struct = til2idb(-1, "tcphdr");
   udp_struct = til2idb(-1, "udphdr");

*/   
   til_t *t = new_til("pcap.til", "pcap header types");
   parse_decls(t, pcap_types, msg, HTI_PAK1);
   sort_til(t);
   pcap_hdr_struct = import_type(t, -1, "pcap_file_header");
   pkthdr_struct = import_type(t, -1, "pcap_pkthdr");
   ether_struct = import_type(t, -1, "ether_header");
   ip_struct = import_type(t, -1, "iphdr");
   tcp_struct = import_type(t, -1, "tcphdr");
   udp_struct = import_type(t, -1, "udphdr");
   free_til(t);

}

//--------------------------------------------------------------------------
//
//      load file into the database.
// This is only called if the user chooses our loader as the one to use
static void idaapi load_pcap_file(linput_t *li, ushort neflags,
                      const char * /*fileformatname*/) {
   //NOTE, if you are using an existing Ida processor module,
   //then all you really need to do is load bytes from the file
   //into the database, create sections, and add entry points
   ssize_t len;
   pcap_pkthdr pkt;

   add_types();
   create_filename_cmt();
   //read the program header from the input file
   //file2base does a seek and read from the input file into the database
   //file2base is prototyped in loader.h
   file2base(li, 0, 0, sizeof(pcap_file_header), FILEREG_PATCHABLE);
//   set_selector(1, 0);
   //try to add a new code segment to contain the program bytes
   if (!add_segm(0, 0, sizeof(pcap_file_header), ".file_header", CLASS_DATA)) {
      loader_failure();
   }   

   doStruct(0, sizeof(pcap_file_header), pcap_hdr_struct);

   uint32 pos = sizeof(pcap_file_header);
   while ((len = qlread(li, &pkt, sizeof(pkt))) == sizeof(pkt)) {
      mem2base(&pkt, pos, pos + sizeof(pkt), pos);
      pos += sizeof(pkt);
      file2base(li, pos, pos, pos + pkt.caplen, FILEREG_PATCHABLE);
      pos += pkt.caplen;
   }

   if (!add_segm(0, sizeof(pcap_file_header), pos, ".packets", CLASS_DATA)) {
      loader_failure();
   }
   //retrieve a handle to the new segment
   segment_t *s = getseg(sizeof(pcap_file_header));
   //so that we can set 32 bit addressing mode on
   set_segm_addressing(s, 1);  //set 32 bit addressing

   //apply headers structs for each packet in the database
   for (uint32 ea = sizeof(pcap_file_header); ea < pos;) {
      uint32 pcap = ea;  //start of packet
      doStruct(pcap, sizeof(pcap_pkthdr), pkthdr_struct);
      uint32 eth = pcap + sizeof(pcap_pkthdr);
      //apply Ethernet header struct
      doStruct(eth, sizeof(ether_header), ether_struct);
      //Test Ethernet type field
      uint16 etype = get_word(eth + 12);
      etype = (etype >> 8) | (etype << 8);  //htons
      uint32 ip = eth + sizeof(ether_header);
      if (etype == ETHER_TYPE_IP) {
         //Apply IP header struct
         doStruct(ip, sizeof(iphdr), ip_struct);
         //Test IP protocol
         uint8 proto = get_byte(ip + 9);
         //compute IP header length
         uint32 iphl = (get_byte(ip) & 0xF) * 4;
         if (proto == IP_PROTO_TCP) {
            doStruct(ip + iphl, sizeof(tcphdr), tcp_struct);
         }
         else if (proto == IP_PROTO_UDP) {
            doStruct(ip + iphl, sizeof(udphdr), udp_struct);
         }
      }
      ea += get_long(pcap + 8) + sizeof(pcap_pkthdr);
   }
}

//----------------------------------------------------------------------
//
//      LOADER DESCRIPTION BLOCK
//
//----------------------------------------------------------------------
loader_t LDSC = {
  IDP_INTERFACE_VERSION,
  0,                            // loader flags
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//
   accept_pcap_file,
//
//      load file into the database.
//
   load_pcap_file,
//
//	create output file from the database.
//	this function may be absent.
//
   NULL,
//      take care of a moved segment (fix up relocations, for example)
   NULL,
//      initialize user configurable options based on the input file.
   NULL,
};

//----------------------------------------------------------------------
