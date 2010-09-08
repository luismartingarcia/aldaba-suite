
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
#include "PKServer.h"
#include "tools.h"
#include "blowfish.h"
#include "output.h"
#include "ServerOps.h"
#include "PKDataLight4.h"
#include "PKDataLight6.h"
#include "PKDataStrong4.h"
#include "PKDataStrong6.h"
#include "IPv4Header.h"
#include "IPv6Header.h"
#include "TCPHeader.h"
#include "UDPHeader.h"
#include "Random.h"
#include "tools.h"
#include <pcap.h>
#include <assert.h>
#include "post_auth.h"

extern ServerOps o;
extern PKServer pk_srv;

PKServer::PKServer() {
  this->reset();
} /* End of PKServer constructor */


PKServer::~PKServer() {
} /* End of PKServer destructor */


/** Sets every attribute to its default value- */
void PKServer::reset() {
} /* End of reset() */


/** Handles the server side of Single Packet Authorization. */
int PKServer::run(){
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
    fatal(OUT_2,"ERROR: pcap_lookupnet(): %s", errbuf );
  }

  /* Open network device for packet capture */
  if((descr=pcap_open_live(o.getInterface(), PCAP_BUFSIZE_PK, o.getPromiscuous(), -1, errbuf))==NULL){
    fatal(OUT_2,"ERROR: %s\n",errbuf);
  }
  indent(OUT_4, 1, "Listening on device \"%s\", link-type %s (%s), capture size %d bytes.\n",
         o.getInterface(), pcap_datalink_val_to_name(pcap_datalink(descr)),
         pcap_datalink_val_to_description(pcap_datalink(descr)), PCAP_BUFSIZE_PK);

  /* Check for supported Data-Link types and obtain data-link header length */
  if( (hlen=get_link_header_length(pcap_datalink(descr)))<=0 ){
    fatal(OUT_2, "ERROR: Unsupported network interface data link type\n");
  }else{
    o.setLinkHeaderLength(hlen);
  }

  /* Filter expression for the BPF filter so we sniff only relevant packets */
  if ( (filterstring=PKServer::getFilterString())==NULL ){
    fatal(OUT_2, "Unexpected error constructing the BPF filter.\n");
  }
  indent(OUT_6, 1, "Using BPF filter=\"%s\".\n", filterstring);
         

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
  if ( pcap_loop(descr, -1, pk_packet_handler_wrapper, NULL) < 0 ){
    fatal(OUT_2, "pcap_loop() exited unexpectedly.\n");
  }
  return OP_SUCCESS; /* Never reached */
} /* End of run() */


/** It generates a string like "udp and (dst port 6800 or dst port 8080)",
  * suitable to be used in BPF filter generation. The generated string can be
  * passed to pcap_compile(). If more than one target port is supplied, the
  * BPF filter will include up to ten ports. */
#define MAX_PORTS_FOR_BPF_FILTER 10
char *PKServer::getFilterString(){
  output(OUT_9, "%s()\n", __func__);
  static char filterstring[1024];
  char tmpbuff[64];
  memset(tmpbuff, 0, sizeof(tmpbuff));
  memset(filterstring, 0, sizeof(filterstring));

  if( o.issetBPF() ){
    strncpy(filterstring, o.getBPF(), sizeof(filterstring)-1);
  }else if(o.getIPVersion()==AF_INET6) {
      filterstring[0]='\0';
  }else if( o.getNumberOfSequencePorts()> MAX_PORTS_FOR_BPF_FILTER ){
    strncpy(filterstring, "tcp[13] == 0x02", sizeof(filterstring)-1);
  }else{
      /* TCP SYN flag must be set */
      strncpy(filterstring, "tcp[13] == 0x02 and (", sizeof(filterstring)-1);

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
  }
  return filterstring;
}/* End of SPA_getFilterString() */



/** Captured packet handler */
int PKServer::pk_packet_handler(u8 *args, const struct pcap_pkthdr* pkthdr, const u8 *packet){
  output(OUT_9, "%s()\n", __func__);
  PKAuthAttempt *attempt=NULL;
  IPv4Header i4;
  IPv6Header i6;
  TCPHeader tcp;
  IPAddress ip;
  u32 min_len=0;  
  const u8 *aux=packet;
  u8 *chunk_data=NULL;
  size_t chunk_len=0;
  u32 auxlen=pkthdr->len;
  int tmp;
  args=NULL; /* The args parameter is not used here. */


  /* Only process the packets whose length makes sense (allow 40 bytes of
   * possible IP options) */
  if(o.getIPVersion()==AF_INET6)
    min_len=o.getLinkHeaderLength() + IPv6_HEADER_LEN + TCP_HEADER_LEN;
  else
    min_len=o.getLinkHeaderLength() + IP_HEADER_LEN + TCP_HEADER_LEN;
  if ( (pkthdr->len<min_len)){
      warning(OUT_7,"Received packet of incorrect length. Packet discarded.\n");
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
        ip.setAddress(i6.getSourceAddress());
    }
    /* Make sure we received TCP */
    if( i6.getNextHeader()!=6 )
        return OP_FAILURE;
    /* Store the UDP part */
    tcp.storeRecvData(aux, auxlen);

  }else{ /* AF_INET */
    /* Make sure the header does not contain bogus values */
    if( (tmp=i4.validate())<=0 ){
          return OP_FAILURE;
    }else{
        aux+=tmp;
        auxlen-=tmp;
        ip.setAddress( i4.getSrcIP() );
    }
    /* Make sure we received TCP */
    if( i4.getNextProto()!=6 )
        return OP_FAILURE;
    /* Store the UDP part */
    tcp.storeRecvData(aux, auxlen);
  }

  /* Place the packet pointer after the UDP packet, when the SPA pkt starts */
  if( (tmp=tcp.validate())<=0 ){
    return OP_FAILURE;
  }else{
    aux+=tmp;
    auxlen-=tmp;
  }

  /* At this point we should have processed the whole packet. If more than zero
   * bytes are left to process, then we don't want this packet. */
  if(auxlen!=0)
      return OP_FAILURE;

  /* Make sure the TCP pkt is targetted to one of our sequence ports */
  if( o.getField()!=COVERT_TCP_DPORT ){
      bool ok=false;
      for(size_t i=0; i<o.getNumberOfSequencePorts(); i++){
        if( tcp.getDstPort()==o.getSequencePort(i) ){
            ok=true;
            break;
        }
      }
      if(ok==false)
          return OP_FAILURE;
  }

  if((chunk_data=PKServer::extract_field_data(&i4, &tcp, o.getField(), &chunk_len))==NULL )
      return OP_FAILURE;

  if( (attempt=this->auth_lookup(ip))==NULL ){ /* First knock */
      indent(OUT_4, 1, "Received new knocking attempt from %s (port %d).\n", ip.toString(), tcp.getDstPort());
      attempt=this->auth_new(chunk_len, o.getNumberOfSequencePorts());
      attempt->setAddress(ip);
      attempt->update(chunk_data, tcp.getDstPort(), o.getSequencePortArray());
      this->auth_insert(attempt);
  }else{ /* Part of an existing auth attempt */
      
      attempt->update(chunk_data, tcp.getDstPort(), o.getSequencePortArray());
      if(attempt->complete()){
          indent(OUT_4, 1, "Received final knock packet from %s (port %d).\n", ip.toString(), tcp.getDstPort());
          return handle_complete_attempt(attempt);
      }else{
          indent(OUT_4, 1, "Received intermediate knock packet from %s (port %d).\n", ip.toString(), tcp.getDstPort());
      }
  }

  return OP_SUCCESS;
} /* End of spa_packet_handler() */



int PKServer::handle_complete_attempt(PKAuthAttempt *attempt){
  output(OUT_9, "%s()\n", __func__);
  int result=OP_SUCCESS;
  size_t data_len=0;
  u8 *data=NULL;
  IPAddress finaladdr;
  tcp_port_t finalport;
  bool open=false;
  assert(attempt);
  data=attempt->getData(&data_len);
  indent(OUT_5, 2, "Received knock ciphertext: "); hex2strln(OUT_5, data, data_len);

  /* Decrypt knock data */
  if ( blowfish_decrypt_buffer(data, data, o.getCipherKey(), data_len) != 0){
    warning(OUT_3, "Unable to encrypt Port Knocking authentication data.");
    result=OP_FAILURE;
  }else{
    indent(OUT_5, 2, "Received knock plaintext:  "); hex2strln(OUT_5, data, data_len);
    if(o.getAuthType()==AUTH_TYPE_LIGHT){
        if(o.getIPVersion()==AF_INET6){
            PKDataLight6 pkdl6;
            pkdl6.storeRecvData(data, data_len);
            finaladdr=pkdl6.getAddress();
            finalport=pkdl6.getPort();
            open=(pkdl6.getAction()==ACTION_OPEN);
            if( pkdl6.validateKnockData(o.getMacKey(), o.getMacKeyLength()) ){
                this->post_auth(&pkdl6);
                result=OP_SUCCESS;
            }else{
                result=OP_FAILURE;
            }
        }else{ /* AF_INET */
            PKDataLight4 pkdl4;
            pkdl4.storeRecvData(data, data_len);
            finaladdr=pkdl4.getAddress();
            finalport=pkdl4.getPort();
            open=(pkdl4.getAction()==ACTION_OPEN);
            if( pkdl4.validateKnockData(o.getMacKey(), o.getMacKeyLength()) ){
                this->post_auth(&pkdl4);
                result=OP_SUCCESS;
            }else{
                result=OP_FAILURE;
            }
        }
    }else{ /* AUTH_TYPE_STRONG */
        u32 now=(u32)time(NULL);
        if(o.getIPVersion()==AF_INET6){
            PKDataStrong6 pkds6;
            pkds6.storeRecvData(data, data_len);
            finaladdr=pkds6.getAddress();
            finalport=pkds6.getPort();
            open=(pkds6.getAction()==ACTION_OPEN);
            if( pkds6.validateKnockData(o.getMacKey(), o.getMacKeyLength()) ){
                /* Verify the timeout is within the allowed window */
                if(!((now-MAX_CLOCK_SKEW_SECONDS)< pkds6.getTimestamp() && pkds6.getTimestamp() < (now+MAX_CLOCK_SKEW_SECONDS)) ){
                    indent(OUT_4, 1, "Received very old authentication (%u). Discarded.\n", pkds6.getTimestamp());
                    result=OP_FAILURE;
                /* Verify the packet has not been replayed */
                }else if( this->auth_record_lookup(pkds6.getTimestamp(), pkds6.getNonce(), pkds6.getNonceLength()) != NULL ){
                    indent(OUT_4, 1, "Replay attack detected! Old PK-IPv6-Strong authentication received\n");
                    result=OP_FAILURE;
                }else{
                    this->auth_record_insert_new(pkds6.getTimestamp(), pkds6.getNonce(), pkds6.getNonceLength());
                    this->post_auth(&pkds6);
                    result=OP_SUCCESS;
                }
            }else{
                result=OP_FAILURE;
            }
        }else{ /* AF_INET */
            PKDataStrong4 pkds4;
            pkds4.storeRecvData(data, data_len);
            finaladdr=pkds4.getAddress();
            finalport=pkds4.getPort();
            open=(pkds4.getAction()==ACTION_OPEN);
            if( pkds4.validateKnockData(o.getMacKey(), o.getMacKeyLength()) ){
                /* Verify the timeout is within the allowed window */
                if(!((now-MAX_CLOCK_SKEW_SECONDS)< pkds4.getTimestamp() && pkds4.getTimestamp() < (now+MAX_CLOCK_SKEW_SECONDS)) ){
                    indent(OUT_4, 1, "Received very old authentication (%u). Discarded.\n", pkds4.getTimestamp());
                    result=OP_FAILURE;
                /* Verify the packet has not been replayed */
                }else if( this->auth_record_lookup(pkds4.getTimestamp(), pkds4.getNonce(), pkds4.getNonceLength()) != NULL ){
                    indent(OUT_4, 1, "Replay attack detected! Old PK-IPv6-Strong authentication received\n");
                    result=OP_FAILURE;
                }else{
                    this->auth_record_insert_new(pkds4.getTimestamp(), pkds4.getNonce(), pkds4.getNonceLength());
                    this->post_auth(&pkds4);
                    result=OP_SUCCESS;
                }
            }else{
                result=OP_FAILURE;
            }
        }
    }

    indent(OUT_4, 1, "%s %s-%s authentication received [%s port %d to %s].\n",
           (result==OP_SUCCESS) ? "Valid" : "Invalid",
           o.getIPVersion_str(), o.getAuthType_str(),
           (open) ? "Open" : "Close", finalport, finaladdr.toString());
  }

  /* Free the knock attempt structure */
  this->auth_remove(attempt->getAddress());
  
  return result;
}



u8 *PKServer::extract_field_data(IPv4Header *ip4, TCPHeader *tcp, int field, size_t *final_len){
  output(OUT_9, "%s()\n", __func__);
  static u8 tmpbuff[MAX_COVERT_PAYLOAD_LEN];
  u8 *tmp8=(u8 *)tmpbuff;
  u16 *tmp16=(u16 *)tmpbuff;
  u32 *tmp32=(u32 *)tmpbuff;
  size_t len=0;
  assert(tcp);
  switch(field){
        case COVERT_IP_TOS:
            assert(ip4);
            *tmp8=ip4->getTOS();
            len=COVERT_IP_TOS_LEN;
        break;

        case COVERT_IP_ID:
            assert(ip4);
            *tmp16=ip4->getIdentification();
            len=COVERT_IP_ID_LEN;
        break;

        case COVERT_TCP_SPORT:
            *tmp16=tcp->getSrcPort();
            len=COVERT_TCP_SPORT_LEN;
        break;

        case COVERT_TCP_DPORT:
            *tmp16=tcp->getDstPort();
            len=COVERT_TCP_DPORT_LEN;
        break;

        case COVERT_TCP_WINDOW:
            *tmp16=tcp->getWindow();
            len=COVERT_TCP_WINDOW_LEN;
        break;

        case COVERT_TCP_URP:
            *tmp16=tcp->getUrgPointer();
            len=COVERT_TCP_URP_LEN;
        break;

        case COVERT_TCP_CSUM:
            *tmp16=tcp->getSum();
            len=COVERT_TCP_CSUM_LEN;
        break;

        case COVERT_TCP_ACK:
            *tmp32=tcp->getAck();
            len=COVERT_TCP_ACK_LEN;
        break;

        case COVERT_TCP_SEQ:
            *tmp32=tcp->getSeq();
            len=COVERT_TCP_SEQ_LEN;
        break;

        default:
            if(final_len!=NULL)
                *final_len=0;
            return NULL;
        break;
  }
  if(final_len!=NULL)
      *final_len=len;
  return tmpbuff;
} /* End of extract_field_data() */



PKAuthAttempt *PKServer::auth_new(size_t chunk_len, u16 seq_ports){
  output(OUT_9, "%s()\n", __func__);
  PKAuthAttempt *auth = new PKAuthAttempt(chunk_len, seq_ports);
  return auth;
}


int PKServer::auth_insert(PKAuthAttempt *x){
  output(OUT_9, "%s()\n", __func__);
  this->auths.push_back(x);
  return OP_SUCCESS;
}


int PKServer::auth_remove(IPAddress addr){
  output(OUT_9, "%s()\n", __func__);
  for (vector<PKAuthAttempt *>::iterator it = this->auths.begin(); it!=this->auths.end(); ++it) {
    if( (*it)->getAddress()==addr ){
        this->auths.erase(it);
        delete *it;
        return OP_SUCCESS;
    }
  }
  return OP_FAILURE;
}


PKAuthAttempt *PKServer::auth_lookup(IPAddress addr){
  output(OUT_9, "%s()\n", __func__);
  for(size_t i=0; i<this->auths.size(); i++ ){
    if( this->auths[i]->getAddress()==addr )
        return this->auths[i];
  }
  return NULL;
}


int PKServer::post_auth(PKDataLight4 *pkdata){
  output(OUT_9, "%s()\n", __func__);
  assert(pkdata);
  bool action= (pkdata->getAction()==ACTION_OPEN) ? true : false;
  return post_auth(pkdata->getPort(), action, pkdata->getAddress());
} /* End of post_auth() */


int PKServer::post_auth(PKDataLight6 *pkdata){
  output(OUT_9, "%s()\n", __func__);
  assert(pkdata);
  bool action= (pkdata->getAction()==ACTION_OPEN) ? true : false;
  return post_auth(pkdata->getPort(), action, pkdata->getAddress());
} /* End of post_auth() */


int PKServer::post_auth(PKDataStrong4 *pkdata){
  output(OUT_9, "%s()\n", __func__);
  assert(pkdata);
  bool action= (pkdata->getAction()==ACTION_OPEN) ? true : false;
  return post_auth(pkdata->getPort(), action, pkdata->getAddress());
} /* End of post_auth() */


int PKServer::post_auth(PKDataStrong6 *pkdata){
  output(OUT_9, "%s()\n", __func__);
  assert(pkdata);
  bool action= (pkdata->getAction()==ACTION_OPEN) ? true : false;
  return post_auth(pkdata->getPort(), action, pkdata->getAddress());
} /* End of post_auth() */


int PKServer::post_auth(tcp_port_t port, bool open, IPAddress ip){
  output(OUT_9, "%s()\n", __func__);
  if(open)
    return open_port(port, ip, KNOCK_PORT_PROTO_ANY);
  else
    return close_port(port, ip, KNOCK_PORT_PROTO_ANY);
} /* End of post_auth() */


/** This handler is a wrapper for the PKServer::pk_packet_handler()
  * method. We need this because C++ does not allow to use class methods as
  * callback functions for pcap_loop(). */
void pk_packet_handler_wrapper(u8 *args, const struct pcap_pkthdr* pkthdr, const u8 *packet){
  output(OUT_9, "%s()\n", __func__);
  pk_srv.pk_packet_handler(args, pkthdr, packet);
  return;
} /* End of recv_hs_server_handler() */

