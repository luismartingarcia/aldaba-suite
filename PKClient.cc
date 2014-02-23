
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
#include "PKClient.h"
#include "tools.h"
#include "blowfish.h"
#include "output.h"
#include "GeneralOps.h"
#include "ClientOps.h"
#include "PKDataLight4.h"
#include "PKDataLight6.h"
#include "PKDataStrong4.h"
#include "PKDataStrong6.h"
#include "Random.h"
#include "tools.h"
#include <assert.h>

extern ClientOps o;

PKClient::PKClient() {
  this->reset();
} /* End of PKClient constructor */


PKClient::~PKClient() {
} /* End of PKClient destructor */


/** Sets every attribute to its default value- */
void PKClient::reset() {
  port_max_len=0;
  addr_max_len=0;
} /* End of reset() */


/** Handles the client side of the Port Knocking technique. */
int PKClient::run(){
  output(OUT_9, "%s()\n", __func__);
  PKDataLight4 pkdl4;
  PKDataLight6 pkdl6;
  PKDataStrong4 pkds4;
  PKDataStrong6 pkds6;
  u8 data[1024];
  u32 data_len=0;

  /* Light authentication */
  if( o.getAuthType() == AUTH_TYPE_LIGHT){
      if( o.getIPVersion()==AF_INET6){ /* IP Version 6 */
        /* Encode knock data */
         if ( pkdl6.setKnockData( o.getKnockIP() , o.getKnockPort(KNOCK_PORT_1) , o.getAction(KNOCK_PORT_1), o.getMacKey(), o.getMacKeyLength() )!=OP_SUCCESS)
             fatal(OUT_2, "Unable to generate Port Knocking authentication data.");
         pkdl6.getKnockData(data, &data_len);
         indent(OUT_4, 1, "Sending IPv6_LIGHT authentication [%s port %d to %s].\n",
                pkdl6.getAction()==ACTION_OPEN ? "Open" : "Close", pkdl6.getPort(), pkdl6.getAddress().toString());
      }else{ /* IP Version 4 */
         /* Encode knock data */
         if ( pkdl4.setKnockData( o.getKnockIP() , o.getKnockPort(KNOCK_PORT_1) , o.getAction(KNOCK_PORT_1), o.getMacKey(), o.getMacKeyLength() )!=OP_SUCCESS)
             fatal(OUT_2, "Unable to generate Port Knocking authentication data.");
         pkdl4.getKnockData(data, &data_len);
         indent(OUT_4, 1, "Sending IPv4_LIGHT authentication [%s port %d to %s].\n",
                pkdl4.getAction()==ACTION_OPEN ? "Open" : "Close", pkdl4.getPort(), pkdl4.getAddress().toString());
      }
  /* Strong authentication */
  }else if (o.getAuthType() == AUTH_TYPE_STRONG){
      if( o.getIPVersion()==AF_INET6){ /* IP Version 6 */
        /* Encode knock data */
         if ( pkds6.setKnockData( o.getKnockIP() , o.getKnockPort(KNOCK_PORT_1) , o.getAction(KNOCK_PORT_1), o.getMacKey(), o.getMacKeyLength() )!=OP_SUCCESS)
             fatal(OUT_2, "Unable to generate Port Knocking authentication data.");
         pkds6.getKnockData(data, &data_len);
         indent(OUT_4, 1, "Sending IPv6_STRONG authentication [%s port %d to %s].\n",
                pkds6.getAction()==ACTION_OPEN ? "Open" : "Close", pkds6.getPort(), pkds6.getAddress().toString());
      }else{ /* IP Version 4 */
         /* Encode knock data */
         if ( pkds4.setKnockData( o.getKnockIP() , o.getKnockPort(KNOCK_PORT_1) , o.getAction(KNOCK_PORT_1), o.getMacKey(), o.getMacKeyLength() )!=OP_SUCCESS)
             fatal(OUT_2, "Unable to generate Port Knocking authentication data.");
         pkds4.getKnockData(data, &data_len);
         indent(OUT_4, 1, "Sending IPv4_STRONG authentication [%s port %d to %s].\n",
                pkds4.getAction()==ACTION_OPEN ? "Open" : "Close", pkds4.getPort(), pkds4.getAddress().toString());
      }
  }else{
    fatal(OUT_2, "Wrong authentication type set in PKClient::%s(). Please report a bug", __func__);
  }
  indent(OUT_5, 2, "Plaintext:  "); hex2strln(OUT_5, data, data_len);

  /* Encrypt knock data */
  if ( blowfish_encrypt_buffer(data, data, o.getCipherKey(), data_len) != 0)
    fatal(OUT_2, "Unable to encrypt Port Knocking authentication data.");

  indent(OUT_5, 2, "Ciphertext: "); hex2strln(OUT_5, data, data_len);

  /* And send it */
  indent(OUT_5, 2, "Transmitted packets:\n");
  if( send_knock(data, data_len, o.getField() )!=OP_SUCCESS ){
    fatal(OUT_2, "Error sending port knocking information to %s\n", o.getDestinationIP().toString());
  }else{
    indent(OUT_4, 1, "Port Knocking authentication data was successfully sent to %s.\n", o.getDestinationIP().toString());
  }
  return OP_SUCCESS;
} /* End of run() */


int PKClient::send_knock(u8 *data, u32 data_len, int field){
  output(OUT_9, "%s(%p, %lu, %d)\n", __func__, data, (unsigned long)data_len, field);
  int fd=0, one=1;
  u8 *pkt=NULL;
  u32 pkt_len=0;
  u8 *curr_chunk=NULL;
  unsigned int chunks=0;
  unsigned int chunk_len=0;
  tcp_port_t *portlist=NULL;
  size_t total_ports=0;
  tcp_port_t current_port=0;
  size_t knocks_sent=0;
  u8 rand_data[16];
  bool noise=true;
  size_t client_position=0;
  IPAddress *current_src_host=NULL;
  IPAddress target_host=o.getDestinationIP();
  struct sockaddr_storage ss;
  struct sockaddr_in *s4=(struct sockaddr_in *)&ss;
  struct sockaddr_in6 *s6=(struct sockaddr_in6 *)&ss;
  memset(&ss, 0, sizeof(struct sockaddr_storage));
  assert(data!=NULL);

  /* Determine chuck length and total number of chunks */
  chunk_len=field2len(field);
  chunks=data_len/chunk_len;
  if((data_len%chunk_len)!=0)
     chunks++;

  /* Acquire suitable socket */
  if( o.getIPVersion()==AF_INET6 ){
    /* Get a raw socket for TCP */
    if( (fd = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP) ) == -1 ){
        fatal(PERR_2, "%s(): socket() failed.",__func__); /* Exit */
    }
    set_up_socket_ipv6(fd, o.issetInterface() ? o.getInterface() : NULL );
  }else{
    /* Get a raw socket for TCP */
    if( (fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW) ) == -1 ){
        fatal(PERR_2, "%s(): socket() failed.",__func__); /* Exit */
    }
    /* We need to tell the kernel that we'll be adding our own IP header */
    /* Otherwise the kernel will create its own. The ugly "one" variable */
    /* is a bit obscure but R.Stevens says we have to do it this way ;-) */
    if( setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0){
        fatal(PERR_2, "%s(): setsockopt() failed", __func__);
    }
  }

  /* Place the source IP somewhere in the middle of the decoy list */
  if(o.getNumberOfDecoys()<=0){
     o.addDecoy(o.getSourceIP());
  }else{
     /* Insert source IP in a random position */
     size_t position= (o.rand.getRandom32() % o.getNumberOfDecoys());
     IPAddress *current=o.getDecoy(position);
     IPAddress copy=*current;
     *current=o.getSourceIP();
     o.addDecoy(copy);
     client_position=position;
  }
  
  /* Place target ports in the noise port list */
  if( o.getNoisePackets()<=0 ){
    portlist=o.getSequencePortArray(&total_ports);
  }else{
    portlist=o.getNoisePortList();
    total_ports=o.getNoisePackets();
  }

  this->display_pk_table_header(portlist, total_ports, chunk_len);

  for(size_t prts=0; prts<total_ports; prts++){
    current_port=portlist[prts];
    for(size_t hsts=0; hsts<o.getNumberOfDecoys(); hsts++){
        current_src_host=o.getDecoy(hsts);
        if( o.isSequencePort(current_port) && hsts==client_position ){
            curr_chunk=(data+(knocks_sent*chunk_len));
            knocks_sent++;
            noise=false;
        }else{
            o.rand.getRandomData(rand_data, chunk_len);
            curr_chunk=rand_data;
            noise=true;
        }
        pkt=build_packet(&pkt_len, current_src_host, &target_host, current_port , curr_chunk, field );

        if( o.getIPVersion()==AF_INET6){
            target_host.getIPv6Address(s6);
            s6->sin6_port=0;
            s6->sin6_family=AF_INET6;
            if ( sendto(fd, pkt, pkt_len, 0, (struct sockaddr *)s6, sizeof(struct sockaddr_in6)) < 0){
                warning(PERR_2, "%s(): sendto(%s)", __func__, target_host.toString());
                return -1;
            }
        }else{
            /* Send it through the raw socket */
            target_host.getIPv4Address(s4);
            s4->sin_port=htons(current_port);
            if ( sendto(fd, pkt, pkt_len, 0, (struct sockaddr *)s4, sizeof(struct sockaddr_in)) < 0){
                warning(PERR_2, "%s(): sendto(%s)", __func__, target_host.toString());
                return -1;
            }
        }
        this->display_pk_table_entry(current_src_host, &target_host, current_port, curr_chunk, chunk_len, noise);
    }
  }
  this->display_pk_table_header(portlist, total_ports, chunk_len);

  /* Free stuff */
  // @todo TODO 

  return OP_SUCCESS;
} /* End of send_knock() */


u8 *PKClient::build_packet(u32 *final_len, IPAddress *src_host, IPAddress *target_host, u16 port, u8 *chunk, int field){
  output(OUT_9, "%s(%d)\n", __func__, port);
  IPv4Header i4;
  TCPHeader t;
  static u8 pkt[2048];
  u32 pkt_len=0;
  //u32 chunk_len=0;

  if(chunk==NULL)
     fatal(OUT_2, "%s(): NULL parameter supplied\n", __func__);

  //chunk_len=field2len(field);

  /* Craft TCP Header. First set up all default values, then store knock data */
  t.setSrcPort((1024 + ( o.rand.getRandom16()%(65535-1024) )));
  t.setDstPort( port );
  t.setSeq( o.rand.getRandom32() );
  t.setAck(0);
  t.setOffset();
  t.setSYN();
  t.setWindow((1024 + (o.rand.getRandom16()%(65535-1024) )));
  t.setUrgPointer(0);

    /* Fill the IP header object with some info from AldabaOps */
    switch( o.getIPVersion() ){

        case AF_INET:
            i4.setNextElement( &t );
            i4.setTTL(DEFAULT_IP_TTL);
            i4.setTOS( DEFAULT_IP_TOS );
            i4.setIdentification( o.rand.getRandom16NonZero() );
            i4.setDstIP( target_host->getIPv4Address() );
            i4.setSrcIP( src_host->getIPv4Address() ) ;
            i4.setNextProto("TCP");
            i4.setTotalLength();

            /* Now overwrite the desired field with real data */
            this->set_covert_field_chunk(&i4, &t, chunk, field);

            /* Finish the header and dump it to a buffer we can pass to send() */
            i4.setSum();
            if( field!=COVERT_TCP_CSUM)
                t.setSum( i4.getSrcIP(), i4.getDstIP() );

            /* Store result in send buffer */
            pkt_len = i4.dumpToBinaryBuffer(pkt, sizeof(pkt));
        break;

        case AF_INET6:

            /* Now overwrite the desired field with real data */
            this->set_covert_field_chunk(NULL, &t, chunk, field);

            /* Set checksum to zero and trust the kernel to set it up for us */
            t.setSum(0);
            
            /* Since we cannot include our own header like we do in IPv4, the
             * buffer we return is the TCP one. */
            pkt_len = t.dumpToBinaryBuffer(pkt, sizeof(pkt));
        break;

        default:
            fatal(OUT_2, "%s(): Wrong IP version.", __func__);
        break;
     }

    if(final_len!=NULL)
        *final_len=pkt_len;
    return pkt;
} /* End of build_packet() */


int PKClient::set_covert_field_chunk(IPv4Header *ip4, TCPHeader *tcp, u8 *chunk, int field){
  output(OUT_9, "%s()\n", __func__);
  if(tcp==NULL || chunk==NULL || field2len(field)<=0 )
    fatal(OUT_2, "%s(): NULL parameter supplied\n", __func__);

  switch(field){
        case COVERT_IP_TOS:
            if(ip4!=NULL)
                ip4->setTOS(chunk[0]);
        break;

        case COVERT_IP_ID:
            if(ip4!=NULL)
               ip4->setIdentification( *((u16 *)chunk) );
        break;

        case COVERT_TCP_SPORT:
            tcp->setSrcPort( *((u16 *)chunk) );
        break;

        case COVERT_TCP_DPORT:
            tcp->setDstPort( *((u16 *)chunk) );
        break;

        case COVERT_TCP_WINDOW:
            tcp->setWindow( *((u16 *)chunk) );
        break;

        case COVERT_TCP_URP:
            tcp->setUrgPointer( *((u16 *)chunk) );
        break;

        case COVERT_TCP_CSUM:
            tcp->setSum(( *((u16 *)chunk) ));
        break;

        case COVERT_TCP_ACK:
            tcp->setAck( *((u32 *)chunk) );
        break;

        case COVERT_TCP_SEQ:
            tcp->setSeq( *((u32 *)chunk) );
        break;
        
        default:
            fatal(OUT_2, "%s() Invalid parameter supplied.", __func__);
        break;
  }
  return OP_SUCCESS;
} /* End of set_covert_field_chunk */


 int PKClient::display_pk_table_header(tcp_port_t *portlist, size_t total_ports, size_t data_len){
  size_t aux=0;
  static int once=1;

  /* Determine the length of the longest IP strings and port numbers */
  if(once==1){
      for(size_t i=0; i<total_ports; i++){
         if(portlist[i]>=10000){
            port_max_len=5;
            break;
         }else if(portlist[i]>=1000){
            if(port_max_len<4)
                port_max_len=4;
         }else if(portlist[i]>=100){
            if(port_max_len<3)
                port_max_len=3;
         }else if(portlist[i]>=10){
            if(port_max_len<2)
                port_max_len=2;
         }else{
            if(port_max_len<1)
                port_max_len=1;
         }
      }
      for(size_t i=0; i<o.getNumberOfDecoys(); i++){
        if( (aux=strlen( o.getDecoy(i)->toString())) > addr_max_len )
            addr_max_len=aux;
      }

  }

line:
  /* Print delimiters... */
  indent(OUT_5, 3, " +");
  for(size_t i=0; i< addr_max_len+2; i++ )
     output(OUT_5,"-");

  output(OUT_5,"+");
  for(size_t i=0; i< strlen( o.getDestinationIP().toString() )+2; i++ )
     output(OUT_5,"-");


  output(OUT_5,"+");
  for(size_t i=0; i< port_max_len+2; i++ )
     output(OUT_5,"-");

  output(OUT_5,"+");
  for(size_t i=0; i< (data_len*2)+2; i++ )
     output(OUT_5,"-");

  output(OUT_5,"+");
  for(size_t i=0; i< strlen("knock")+2; i++ )
     output(OUT_5,"-");

  output(OUT_5,"+\n");


  if(once==1){
      once=0;
      
      /* Print delimiters... */
      indent(OUT_5, 3, " | SOURCE");
      for(size_t i=0; i< addr_max_len-5; i++ )
         output(OUT_5," ");

      output(OUT_5,"| TARGET");
      for(size_t i=0; i< strlen( o.getDestinationIP().toString() )-5; i++ )
      output(OUT_5," ");

      if(port_max_len==1)
        output(OUT_5,"|PRT");
      else if (port_max_len==2)
          output(OUT_5,"|PORT");
      else if (port_max_len==3)
          output(OUT_5,"| PORT");
      else if (port_max_len==4)
          output(OUT_5,"| PORT ");
      else
          output(OUT_5,"| PORT  ");


      if(data_len==1)
        output(OUT_5,"|DATA");
      else if (data_len==2)
          output(OUT_5,"| DATA ");
      else
          output(OUT_5,"|   DATA   ");

      output(OUT_5, "| TYPE  |\n");

      goto line;
  }
  return OP_SUCCESS;
}



int PKClient::display_pk_table_entry(IPAddress *src, IPAddress *dst, tcp_port_t port, u8 *data, size_t data_len, bool noise){
  indent(OUT_5, 3, " | %-*s ", (int)this->addr_max_len, src->toString());
  output(OUT_5,"| %s | %-*d | ", dst->toString(), (int)this->port_max_len, port);
  hex2str(OUT_5, data, (u32)data_len);
  output(OUT_5," | %s |\n", (noise) ? "Noise" : "KNOCK");
  return OP_SUCCESS;
}
