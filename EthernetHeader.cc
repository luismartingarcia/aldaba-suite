
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
 * as this disclaimer does not contain the complete information. Also, note*
 * that although Aldaba is licensed under the GNU GPL v2.0 license, it may *
 * be possible to obtain copies of it under different, less restrictive,   *
 * alternative licenses. Requests will be studied on a case by case basis. *
 * If you wish to obtain Aldaba under a different license, please use the  *
 * email address shown above.                                              *
 *                                                                         *
 ***************************************************************************/

#include "EthernetHeader.h"
#include "aldaba.h"
#include "tools.h"


EthernetHeader::EthernetHeader(){
  memset( &h, 0, ETH_HEADER_LEN );
  memset( &f, 0, ETH_FOOTER_LEN );
  length=14; /* We don't count the crc yet */
} /* End of EthernetHeader constructor */


EthernetHeader::~EthernetHeader(){

} /* End of EthernetHeader destructor */


/** @warning This method is essential for the superclass getBinaryBuffer()
 *  method to work. Do NOT change a thing unless you know what you're doing  */
u8 * EthernetHeader::getBufferPointer(){
  return (u8*)(&h);
} /* End of getBufferPointer() */


/** Sets Source MAC address
 *  @warning Supplied buffer must contain at least 6 bytes */
int EthernetHeader::setSrcMAC(u8 *m){
  if(m==NULL)
    fatal(OUT_2, "EthernetHeader::setSrcMAC(u8*): NULL value supplied ");
  memcpy(h.eth_smac, m, 6);
  return OP_SUCCESS;
} /* End of setSrcMAC() */


/** Sets Source MAC address. If it receives "rand", a random MAC is set.
 *  @warning Supplied buffer must have format "FF:FF:FF:FF:FF:FF" */
int EthernetHeader::setSrcMAC(char *p){
  u8 dummy[6];
  if(p==NULL)
    fatal(OUT_2, "EthernetHeader::setSrcMAC(char *): NULL value supplied ");
  if( parseMAC(p, dummy) != OP_SUCCESS )
    return OP_FAILURE;
  memcpy(h.eth_smac, dummy, 6);
  return OP_SUCCESS;
} /* End of setSrcMAC() */


/** Returns source port in HOST byte order
 *  @warning Returned pointer points directly to a Class internal buffer. If
 *  contents are changed, the instance of the class will be affected. */
u8* EthernetHeader::getSrcMAC(){
  return this->h.eth_smac;
} /* End of getSrcMAC() */


/** Sets Destination MAC address
 *  @warning Supplied buffer must contain at least 6 bytes */
int EthernetHeader::setDstMAC(u8 *m){
  if(m==NULL)
    fatal(OUT_2, "EthernetHeader::setDstMAC(u8 *): NULL value supplied ");
  memcpy(h.eth_dmac, m, 6);
  return OP_SUCCESS;
} /* End of setDstMAC() */


/** Sets destination port. If it receives "rand", a random destination port is set.
 *  @warning MAC must be supplied in host byte order. This method performs
 *  byte order conversion using htons() */
int EthernetHeader::setDstMAC(char *p){
  u8 dummy[6];
  if(p==NULL)
    fatal(OUT_2, "EthernetHeader::setDstMAC(char *): NULL value supplied ");
  if( parseMAC(p, dummy) != OP_SUCCESS )
    return OP_FAILURE;
  memcpy(h.eth_dmac, dummy, 6);
  return OP_SUCCESS;
} /* End of setDstMAC() */


/** Returns destination port in HOST byte order */
u8 *EthernetHeader::getDstMAC(){
  return this->h.eth_dmac;
} /* End of getDstMAC() */


int EthernetHeader::setEtherType(u16 val){
  h.eth_type=htons(val);
  return OP_SUCCESS;
} /* End of setEtherType() */


/** Returns destination port in HOST byte order */
u16 EthernetHeader::getEtherType(){
  return this->h.eth_type;
} /* End of getEtherType() */

