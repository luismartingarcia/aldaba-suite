
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
#include "SPAClient.h"
#include "tools.h"
#include "blowfish.h"
#include "output.h"
#include "ClientOps.h"
#include "IPAddress.h"
#include "PKDataLight4.h"
#include "IPv4Header.h"
#include "IPv6Header.h"
#include "TCPHeader.h"
#include "Random.h"
#include "SPAHeader.h"
#include "ssh_cookie.h"

extern ClientOps o;

SPAClient::SPAClient() {
    this->reset();
} /* End of SPAClient constructor */


SPAClient::~SPAClient() {

} /* End of SPAClient destructor */


/** Sets every attribute to its default value- */
void SPAClient::reset() {
  port_max_len=0;
  addr_max_len=0;
} /* End of reset() */


/** Handles the client side of the Port Knocking technique. */
int SPAClient::run(){
  output(OUT_9, "%s()\n", __func__);
  SPAHeader spa;
  spa.setInitializationVector( o.rand.getRandomData(SPA_IV_LEN) );
  spa.setSPAVersion(SPA_CURRENT_VERSION);
  spa.setIPVersion( o.getIPVersion()==AF_INET6 ? 0x06 : 0x04 );
  spa.setProtocolPort1(0); /* @todo Fixme! */

  if( o.issetKnockPort(KNOCK_PORT_1) ){
    spa.setPort1( o.getKnockPort(KNOCK_PORT_1) );
    spa.setProtocolPort1( o.getKnockPortProto(KNOCK_PORT_1) );
    switch(o.getAction(KNOCK_PORT_1)){
        case ACTION_OPEN:
            spa.setActionPort1(SPA_ACTION_OPEN);
        break;
        case ACTION_CLOSE:
            spa.setActionPort1(SPA_ACTION_CLOSE);
        break;
        case ACTION_FORWARD:
            spa.setActionPort1(SPA_ACTION_FORWARD);
        break;
        break;

        default:
          fatal(OUT_2, "Wrong action in ServerOps. This is a bug.");
        break;
    }
  }else{
    spa.setPort1(0);
    spa.setActionPort1(0);
    spa.setProtocolPort1(0);
  }

  if( o.issetKnockPort(KNOCK_PORT_2) ){
    spa.setPort2( o.getKnockPort(KNOCK_PORT_2) );
    spa.setProtocolPort2( o.getKnockPortProto(KNOCK_PORT_2) );
    switch(o.getAction(KNOCK_PORT_2)){
        case ACTION_OPEN:
            spa.setActionPort2(SPA_ACTION_OPEN);
        break;
        case ACTION_CLOSE:
            spa.setActionPort2(SPA_ACTION_CLOSE);
        break;
        case ACTION_FORWARD:
            spa.setActionPort2(SPA_ACTION_FORWARD);
        break;
        break;

        default:
          fatal(OUT_2, "Wrong action in ServerOps. This is a bug.");
        break;
    }
  }else{
    spa.setPort2(0);
    spa.setActionPort2(0);
    spa.setProtocolPort2(0);
  }

  spa.setMagicNumber(0xA1DABA77);  /* @todo define it somewhere? */
  spa.setReserved(0);
  IPAddress knock=o.getKnockIP();
  if(knock.getVersion()==AF_INET6)
    spa.setAddress( knock.getIPv6Address() );
  else
    spa.setAddress( knock.getIPv4Address() );

  /* Set Forward IP if needed */
  if( o.issetForwardIP() ){
      IPAddress fwd_ip=o.getForwardIP();
      if(fwd_ip.getVersion()==AF_INET6)
        spa.setForwardAddress( fwd_ip.getIPv6Address() );
      else
        spa.setForwardAddress( fwd_ip.getIPv4Address() );
  }

  spa.setTimestamp( (u32)time(NULL) );
  spa.setNonce( o.rand.getRandomData(SPA_NONCE_LEN) );
  //spa.setUsername("");
  //spa.setUserdata();
  spa.setMAC( o.getCipherKey(), o.getCipherKeyLength() );

  indent(OUT_4, 1, "Sending SPA-%s authentication [%s port %d to %s].\n", o.getIPVersion_str(),
        (spa.getActionPort1()==SPA_ACTION_OPEN ? "Open" : ((spa.getActionPort1()==SPA_ACTION_CLOSE) ? "Close" : "Forward") ),
        spa.getPort1(), spa.getAddress().toString() );

  /* Store aldaba SSHn cookie if requested */
  if( o.SSHCookie() ){
      client_insert_cookie(spa.getNonce());
  }

  spa.encrypt(o.getCipher(), o.getCipherMode(), o.getCipherKey(), o.getCipherKeyLength());

  if( this->spa_send(&spa)!=OP_SUCCESS )
      return OP_FAILURE;
  else
      indent(OUT_4, 1, "SPA authentication data was successfully sent to %s.\n", o.getDestinationIP().toString());

  return OP_SUCCESS;

} /* End of run() */



int SPAClient::spa_send(SPAHeader *hdr){
  output(OUT_9, "%s()\n", __func__);
  int sd=-1;
  struct sockaddr_in s4;
  struct sockaddr_in6 s6;
  u8 spa_data[SPA_HEADER_LEN];
  u8 rand_data[SPA_HEADER_LEN];
  u32 data_len=0;
  u8 *curr_buffer=NULL;
  tcp_port_t *portlist=NULL;
  size_t total_ports=0;
  tcp_port_t current_port=0;
  IPAddress target_host=o.getDestinationIP();
  bool noise=true;
  memset(&s4, 0, sizeof(struct sockaddr_in));
  memset(&s6, 0, sizeof(struct sockaddr_in6));

  if(hdr==NULL)
    fatal(OUT_2, "%s(): NULL parameter supplied.", __func__);

  /* Place target port in the noise port list */
  if( o.getNoisePackets()<=0 ){
    portlist=o.getSequencePortArray(&total_ports);
  }else{
    portlist=o.getNoisePortList();
    total_ports=o.getNoisePackets();
  }
  
  /* Dump SPA packet to a buffer we can pass in a sendto() call */
  data_len=hdr->dumpToBinaryBuffer(spa_data, SPA_HEADER_LEN);

  this->display_spa_table_header(portlist, total_ports);
  for(size_t prts=0; prts<total_ports; prts++){
        current_port=portlist[prts];
        if( o.isSequencePort(current_port)){
            noise=false;
            curr_buffer=spa_data;
        }else{
            o.rand.getRandomData(rand_data, SPA_HEADER_LEN);
            curr_buffer=rand_data;
            noise=true;
        }
        if( o.getIPVersion()==AF_INET6){
            target_host.getIPv6Address(&s6);
            s6.sin6_family=AF_INET6;
            s6.sin6_port=htons(current_port);
            if( (sd=socket(PF_INET6, SOCK_DGRAM, 0))<0 ){
                warning(PERR_2, "Unable to acquire IPv6 socket.");
                return OP_FAILURE;
            }
            if( sendto(sd, curr_buffer, SPA_HEADER_LEN, 0, (struct sockaddr *)&s6, sizeof(struct sockaddr_in6) ) < (int)data_len ){
                warning(PERR_2, "%s() sendto()", __func__);
                return OP_FAILURE;
            }
            close(sd);
        }else{
            target_host.getIPv4Address(&s4);
            s4.sin_family=AF_INET;
            s4.sin_port=htons(current_port);
            if( (sd=socket(PF_INET, SOCK_DGRAM, 0))<0 ){
                warning(PERR_2, "Unable to acquire IPv4 socket.");
                return OP_FAILURE;
            }
            if ( sendto(sd, curr_buffer, SPA_HEADER_LEN, 0, (struct sockaddr *)&s4, sizeof(s4)) < 0){
                warning(PERR_2, "%s() sendto()", __func__);
                return OP_FAILURE;;
            }
            close(sd);
        }
        this->display_spa_table_entry(target_host, current_port, o.getAction(0), noise);

  }
    this->display_spa_table_header(portlist, total_ports);

  /* Free stuff */
  // @todo TODO

  return OP_SUCCESS;
} /* End of spa_send() */




 int SPAClient::display_spa_table_header(tcp_port_t *portlist, size_t total_ports){
  static int once=1;

  /* Print header only when there are noise packets or decoys */
  
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
  }

line:
  /* Print delimiters... */
  indent(OUT_5, 3, " +");
  for(size_t i=0; i< strlen( o.getDestinationIP().toString() )+2; i++ )
     output(OUT_5,"-");


  output(OUT_5,"+");
  for(size_t i=0; i< port_max_len+2; i++ )
     output(OUT_5,"-");

  output(OUT_5,"+");
  for(size_t i=0; i< 3+2; i++ )
     output(OUT_5,"-");

  output(OUT_5,"+");
  for(size_t i=0; i< strlen("Forward")+2; i++ )
     output(OUT_5,"-");

  output(OUT_5,"+");
  for(size_t i=0; i< strlen("Noise")+2; i++ )
     output(OUT_5,"-");

  output(OUT_5,"+\n");

  if(once==1){
    once=0;
      /* Print delimiters... */
      if(strlen(o.getDestinationIP().toString())>5){
        indent(OUT_5, 3, " | TARGET");
        for(size_t i=0; i<strlen(o.getDestinationIP().toString())-5; i++ )
            output(OUT_5," ");
      }else{
        indent(OUT_5, 3, " | TRG ");
      }

      if(port_max_len==1)
        output(OUT_5,"|DPT");
      else if (port_max_len==2)
          output(OUT_5,"|DPRT");
      else if (port_max_len==3)
          output(OUT_5,"|DPORT");
      else if (port_max_len==4)
          output(OUT_5,"| DPRT ");
      else
          output(OUT_5,"| DPORT ");

      output(OUT_5, "|BYTES");
      output(OUT_5, "| ACTION  ");
      output(OUT_5, "| TYPE  |\n");

      goto line;
  }
  return OP_SUCCESS;
}



int SPAClient::display_spa_table_entry(IPAddress dst, tcp_port_t port, int action, bool noise){
  indent(OUT_5, 3, " | %s | %-*d ", dst.toString(), (int)this->port_max_len, port);
  output(OUT_5,"| %d ", SPA_HEADER_LEN);
  output(OUT_5,"| %-7s ", ((action==ACTION_OPEN) ? "Open" : ((action==ACTION_CLOSE) ? "Close" : "Forward" ) ) );
  output(OUT_5,"| %-5s |\n", (noise) ? "Noise" : "SPA");
  return OP_SUCCESS;
}