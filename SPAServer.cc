
/***************************************************************************
 *                                                                         *
 *                   _        _____               ____                     *
 *           /\     | |      |  __ \      /\     |  _ \      /\            *
 *          /  \    | |      | |  | |    /  \    | |_) |    /  \           *
 *         / /\ \   | |      | |  | |   / /\ \   |  _ <    / /\ \          *
 *        / ____ \  | |___   | |__| /  / ____ \  | |_) /  / ____ \         *
 *       /_/    \_\ | ____|  |_____/  /_/    \_\ |____/  /_/    \_\        *
 *                                                                         *
 *    == {Port Knocking/Single Packet Authorization} Security Suite ==     *
 *                                                                         *
 ***************************************************************************
 *                                                                         *
 * This file is part of Aldaba Knocking Suite.                             *
 *                                                                         *
 * Copyright (c) 2010, Luis MartinGarcia. (aldabaknocking@gmail.com)       *
 *                                                                         *
 * Aldaba is free software; you can redistribute it and/or modify it under *
 * the terms of the GNU General Public License as published by the Free    *
 * Software Foundation; Version 2 of the License, with the exceptions,     *
 * conditions and clarifications described in the file named LICENSE.txt,  *
 * distributed with Aldaba or available from:                              *
 * <http://www.aldabaknocking.com/LICENSE.txt>                             *
 *                                                                         *
 * Aldaba is distributed in the hope that it will be useful, but WITHOUT   *
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or   *
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License   *
 * v2.0 for more details.                                                  *
 *                                                                         *
 * You should have received a copy of the GNU General Public License along *
 * with Aldaba; if not, write to the Free Software Foundation, Inc.,       *
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA                *
 *                                                                         *
 * Please check file LICENSE.txt for the complete version of the license,  *
 * as this disclaimer does not contain the full information. Also, note    *
 * that although Aldaba is licensed under the GNU GPL v2.0 license, it may *
 * be possible to obtain copies of it under different, less restrictive,   *
 * alternative licenses. Requests will be studied on a case by case basis. *
 * If you wish to obtain Aldaba under a different license, please use the  *
 * email address shown above.                                              *
 *                                                                         *
 ***************************************************************************/

#include "aldaba.h"
#include "SPAServer.h"
#include "tools.h"
#include "blowfish.h"
#include "output.h"
#include "ServerOps.h"
#include "SPAHeader.h"
#include "IPv4Header.h"
#include "IPv6Header.h"
#include "UDPHeader.h"
#include "tools.h"
#include <pcap.h>
#include <assert.h>
#include "post_auth.h"
#include "ssh_cookie.h"

extern ServerOps o;
extern SPAServer spa_srv;

SPAServer::SPAServer() {
  this->reset();
} /* End of SPAServer constructor */


SPAServer::~SPAServer() {
} /* End of SPAServer destructor */


/** Sets every attribute to its default value- */
void SPAServer::reset() {
} /* End of reset() */


/** Handles the server side of Single Packet Authorization. */
int SPAServer::run(){
  output(OUT_9, "%s()\n", __func__);
  bpf_u_int32 netaddr=0, mask=0;
  struct bpf_program filter;
  char errbuf[PCAP_ERRBUF_SIZE];
  char *filterstring=NULL;
  pcap_t *descr = NULL;
  int hlen=-1;
  memset(errbuf,0,PCAP_ERRBUF_SIZE);

  /* Look up info from the capture device. */
  if ( pcap_lookupnet( o.getInterface(), &netaddr, &mask, errbuf) == -1 ){
    fatal(OUT_2,"ERROR: pcap_lookupnet(%s): %s",o.getInterface(), errbuf);
  }

  /* Open network device for packet capture */
  if((descr=pcap_open_live(o.getInterface(), PCAP_BUFSIZE_SPA, o.getPromiscuous(), -1, errbuf))==NULL){
    fatal(OUT_2,"ERROR: %s\n",errbuf);
  }
  indent(OUT_4, 1, "Listening on device \"%s\", link-type %s (%s), capture size %d bytes.\n",
         o.getInterface(), pcap_datalink_val_to_name(pcap_datalink(descr)),
         pcap_datalink_val_to_description(pcap_datalink(descr)), PCAP_BUFSIZE_SPA);
  
  /* Check for supported Data-Link types and obtain data-link header length */
  if( (hlen=get_link_header_length(pcap_datalink(descr)))<=0 ){
    fatal(OUT_2, "ERROR: Unsupported network interface data link type\n");
  }else{
    o.setLinkHeaderLength(hlen);
  }
 
  /* Filter expression for the BPF filter so we sniff only relevant packets */
  if ( (filterstring=SPAServer::getFilterString())==NULL ){
    fatal(OUT_2, "Unexpected error constructing the BPF filter.\n");
  }

  /* If we are sniffing on many interfaces set the subnet mask to zero */
  if (!strcmp("any", o.getInterface()))
    mask = 0;

  /* Compiles the filter expression into a BPF filter program */
  if( pcap_compile(descr, &filter, filterstring, PCAP_OPTIMIZE, mask) == -1 ){
    fatal(OUT_2, "Unexpected error compiling the BPF filter.\n");
  }

  /* Load the filter program into the packet capture device. */
  if( pcap_setfilter(descr, &filter) == -1 ){
    fatal(OUT_2, "Unexpected error setting the BPF filter.\n");
  }

  /* Everytime we have a packet, call SPA_process_packet() */
  if ( pcap_loop(descr, -1, spa_packet_handler_wrapper, NULL) < 0 ){
    fatal(OUT_2, "pcap_loop() exited unexpectedly.\n");
  }
  return OP_SUCCESS; /* Never reached */
} /* End of run() */


/** It generates a string like "udp and (dst port 6800 or dst port 8080)",
  * suitable to be used in BPF filter generation. The generated string can be
  * passed to pcap_compile(). If more than one target port is supplied, the
  * BPF filter will include up to ten ports. */
#define MAX_PORTS_FOR_BPF_FILTER 10
char *SPAServer::getFilterString(){
  output(OUT_9, "%s()\n", __func__);
  static char filterstring[1024];
  char tmpbuff[64];
  memset(tmpbuff, 0, sizeof(tmpbuff));
  memset(filterstring, 0, sizeof(filterstring));

  /* It must be a UDP packet */
  strncpy(filterstring, "udp and (", sizeof(filterstring)-1);

  /* First port to filter */
  snprintf(tmpbuff,sizeof(tmpbuff), "dst port %d ", o.getSequencePort(0));
  strncat(filterstring, tmpbuff, sizeof(filterstring)-1);

  /* Rest of ports */
  for (size_t i=1; i<o.getNumberOfSequencePorts() && i<MAX_PORTS_FOR_BPF_FILTER; i++){
    snprintf(tmpbuff, sizeof(tmpbuff), "or dst port %d ", o.getSequencePort(i));
    strncat(filterstring, tmpbuff, sizeof(filterstring)-1);
  }
  /* Close parentheses */
  strncat(filterstring, ")",sizeof(filterstring)-1);
  return filterstring;
}/* End of SPA_getFilterString() */


/** Captured packet handler */
int SPAServer::spa_packet_handler(u8 *args, const struct pcap_pkthdr* pkthdr, const u8 *packet){
  output(OUT_9, "%s()\n", __func__);
  u32 pktlen=0;
  IPv4Header i4;
  IPv6Header i6;
  UDPHeader udp;
  SPAHeader spa;
  pktlen=o.getLinkHeaderLength() + IP_HEADER_LEN + UDP_HEADER_LEN + SPA_HEADER_LEN;
  const u8 *aux=packet;
  u32 auxlen=pkthdr->len;
  int tmp;
  args=NULL; /* The args parameter is not used here. */

  /* Only process the packets whose length makes sense (allow 40 bytes of
   * possible IP options) */
  if ( (pkthdr->len<pktlen) || (pkthdr->len>(pktlen+40)) ){
      warning(OUT_7,"Received packet of incorrect length (%u). Packet discarded.\n", pkthdr->len);
      return OP_FAILURE;
  }

  aux+=o.getLinkHeaderLength();
  auxlen-=o.getLinkHeaderLength();

  /* Parse received packet. */
  if(i4.storeRecvData(aux, auxlen)!=OP_SUCCESS)
      return OP_FAILURE;

  if(i4.getVersion()==6){ /* AF_INET6 */
    if(i6.storeRecvData(aux, auxlen)!=OP_SUCCESS)
        return OP_FAILURE;
    /* Make sure the header does not contain bogus values */
    if( (tmp=i6.validate())<=0 ){
        return OP_FAILURE;
    }else{
        aux+=tmp;
        auxlen-=tmp;
    }
    /* Make sure we received UDP */
    if( i6.getNextHeader()!=17 )
        return OP_FAILURE;
    /* Store the UDP part */
    udp.storeRecvData(aux, auxlen);
  }else{ /* AF_INET */
    /* Make sure the header does not contain bogus values */
    if( (tmp=i4.validate())<=0 ){
        return OP_FAILURE;
    }else{
        aux+=tmp;
        auxlen-=tmp;
    }
    /* Make sure we received UDP */
    if( i4.getNextProto()!=17 )
        return OP_FAILURE;
    /* Store the UDP part */
    udp.storeRecvData(aux, auxlen);
  }
  /* Place the packet pointer after the UDP packet, when the SPA pkt starts */
  if( (tmp=udp.validate())<=0 ){
    return OP_FAILURE;
  }else{
    aux+=tmp;
    auxlen-=tmp;
  }
  /* At this point we should have a buffer of the exact length */
  if(auxlen!=SPA_HEADER_LEN)
      return OP_FAILURE;
  /* Make sure the UDP pkt is targetted to one of our sequence ports */
  bool ok=false;
  for(size_t i=0; i<o.getNumberOfSequencePorts(); i++){
    if( udp.getDstPort()==o.getSequencePort(i) ){
        ok=true;
        break;
    }
  }
  if(ok==false)
      return OP_FAILURE;

  /* Parse the SPA packet */
  if( spa.storeRecvData(aux, auxlen)!=OP_SUCCESS )
      return OP_FAILURE;

  if( spa.decrypt( o.getCipher(), o.getCipherMode(), o.getCipherKey(), o.getCipherKeyLength() )!=OP_SUCCESS )
      return OP_FAILURE;

  if( spa.getMagicNumber()!=SPA_MAGIC_NUMBER)
      return OP_FAILURE;

  if( spa.getSPAVersion()!=SPA_CURRENT_VERSION )
      return OP_FAILURE;
  
  if( spa.verifyMAC(o.getCipherKey(), o.getCipherKeyLength())!=OP_SUCCESS )
      return OP_FAILURE;

  /* Verify the timeout is within the allowed window */
  u32 now=(u32)time(NULL);
  if(!((now-MAX_CLOCK_SKEW_SECONDS)< spa.getTimestamp() && spa.getTimestamp() < (now+MAX_CLOCK_SKEW_SECONDS)) ){
      indent(OUT_4, 1, "Received very old authentication (%u). Discarded.\n", spa.getTimestamp());
      return OP_FAILURE;
  }

  /* Verify the packet has not been replayed */
  if( this->auth_record_lookup(spa.getTimestamp(), spa.getNonce(), SPA_NONCE_LEN) != NULL ){
      indent(OUT_4, 1, "Replay attack detected! Old SPA authentication received\n");
      return OP_FAILURE;
  }else{
      this->auth_record_insert_new(spa.getTimestamp(), spa.getNonce(), SPA_NONCE_LEN);
      this->ssh_auth_insert_new(spa.getTimestamp(), spa.getNonce(), SPA_NONCE_LEN);
  }

  if( o.SSHCookie() ){
      indent(OUT_6, 1, "Passing SSH authentication token to the cookie server.\n");
      server_insert_cookie(spa.getNonce());
  }
  /* If we get here it means that the received SPA packet is valid and
   * that we should take the appropriate action */
  return this->post_auth(&spa);

} /* End of spa_packet_handler() */


int SPAServer::post_auth(SPAHeader *spa){
  output(OUT_9, "%s()\n", __func__);
  assert(spa);
  IPAddress ip;
  IPAddress fwd_ip;

   indent(OUT_4, 1, "Valid SPA authentication received [");

  /* Extract the authorized IP address */
   ip=spa->getAddress();

  /* Determine which action to take */
  if(spa->getActionPort1()==SPA_ACTION_FORWARD){
      if(spa->getActionPort2()==SPA_ACTION_FORWARD && spa->getProtocolPort1()==spa->getProtocolPort2()){
          output(OUT_4, "Forward %d to %d for %s]\n", spa->getPort1(), spa->getPort2(), ip.toString() );
          fwd_ip=spa->getForwardAddress();
          forward_port(spa->getPort1(), spa->getPort2(), ip, fwd_ip, spa->getProtocolPort1());
          return OP_SUCCESS;
      }else{
          return OP_FAILURE; /* Forwarding needs to be set on both ports */
      }
  }else if(spa->getActionPort1()==SPA_ACTION_OPEN){
    output(OUT_4, "Open %d", spa->getPort1());
    open_port(spa->getPort1(), ip, spa->getProtocolPort1());
  }else if(spa->getActionPort1()==SPA_ACTION_CLOSE){
    output(OUT_4, "Close %d", spa->getPort1());
    close_port(spa->getPort1(), ip, spa->getProtocolPort1());
  }

  /* Now for port 2 */
  if(spa->getActionPort2()==SPA_ACTION_OPEN){
    output(OUT_4, "Open %d", spa->getPort2());
    open_port(spa->getPort2(), ip, spa->getProtocolPort2());
  }else if(spa->getActionPort2()==SPA_ACTION_CLOSE){
    output(OUT_4, "Close %d", spa->getPort2());
    close_port(spa->getPort2(), ip, spa->getProtocolPort2());
  }else if(spa->getActionPort2()==SPA_ACTION_FORWARD){
      return OP_FAILURE;
  }
  output(OUT_4, " to %s]\n", ip.toString());

  return OP_SUCCESS;
} /* End of post_auth() */


/** This handler is a wrapper for the SPAServer::spa_packet_handler()
  * method. We need this because C++ does not allow to use class methods as
  * callback functions for pcap_loop(). */
void spa_packet_handler_wrapper(u8 *args, const struct pcap_pkthdr* pkthdr, const u8 *packet){
  output(OUT_9, "%s()\n", __func__);
  spa_srv.spa_packet_handler(args, pkthdr, packet);
  return;
} /* End of recv_hs_server_handler() */
