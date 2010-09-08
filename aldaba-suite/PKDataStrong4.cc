
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

#include "RawData.h"
#include "aldaba.h"
#include "output.h"
#include "IPAddress.h"
#include "PKDataStrong4.h"
#include "tools.h"
#include "sha256.h"
#include "hmac_sha256.h"
#include "GeneralOps.h"

extern GeneralOps o;

PKDataStrong4::PKDataStrong4(){
    this->reset();
} /* End of PKDataStrong4 contructor */


PKDataStrong4::~PKDataStrong4(){

} /* End of PKDataStrong4 destructor */


/** Puts the object back to its initial state */
void PKDataStrong4::reset(){
  memset(&(this->h), 0, sizeof(this->h));
  this->length=0; /* Zero until set() is called. */
  return;
} /* End of reset() */


/** Returns a pointer to the knock data.
  * @warning The caller must ensure setKnockData() has been called before
  * calling this method. Otherwise a zeroed buffer will be returned  */
u8 *PKDataStrong4::getBufferPointer(){
  return (u8 *)(&h);
} /* End of getBufferPointer() */


/** Returns a pointer to the knock data.
  * @warning The caller must ensure setKnockData() has been called before
  * calling this method. Otherwise a zeroed buffer will be returned
  * @param len is a pointer to an unsigned integer var where the knock data
  * length is stored by this function (if not NULL). */
u8 *PKDataStrong4::getBufferPointer(u32 *len){
  if(len!=NULL)
    *len=(u32)this->length;
  return (u8 *)(&h);
} /* End of getBufferPointer() */


/** Stores supplied data in the internal buffer so the information
  * can be accessed using the standard get & set methods.
  * @warning  The PKDataStrong4 class is able to hold a maximum of
  * PK_STRONG_IPv4_DATA_LEN bytes. If the supplied buffer is longer than that, it
  * will fatal().
  * @warning Supplied len MUST be PK_STRONG_IPv4_DATA_LEN bytes (min IP header
  * length).
  * @return OP_SUCCESS on success. Fatals on error. */
int PKDataStrong4::storeRecvData(const u8 *buf, size_t len){
  if(buf==NULL || len!=PK_STRONG_IPv4_DATA_LEN){
      fatal(OUT_2, "%s(): Invalid parameters.", __func__);
  }else{
    this->reset(); /* Re-init the object, just in case the caller had used it already */
    this->length=PK_STRONG_IPv4_DATA_LEN;
    memcpy(&(this->h), buf, PK_STRONG_IPv4_DATA_LEN);
  }
 return OP_SUCCESS;
} /* End of storeRecvData() */



/** Stores knock data in the supplied buffer.
  * @warning supplied pointer MUST be able to hold at least
  * PK_STRONG_IPv4_DATA_LEN bytes.
  * @returns the number of bytes written to the buffer or -1 in case of error
  * @warning If setKnockData() has not been called before, 0 bytes will be
  * written and the value 0 will be returned. Therefore, caller should check
  * for positive, non-zero, values to make sure the call succeded. */
void PKDataStrong4::getKnockData(u8 *buff, u32 *final_len){
  if(buff!=NULL)
    memcpy(buff,  &(this->h), this->length);
  if(final_len!=NULL)
    *final_len=(u32)this->length;
} /* End of getKnockData() */


/** Returns a pointer to the knock data.
  * @warning The caller must ensure setKnockData() has been called before
  * calling this method. Otherwise a zeroed buffer will be returned
  * @param len is a pointer to an unsigned integer var where the knock data
  * length is stored by this function (if not NULL). */
u8 *PKDataStrong4::getKnockData(u32 *len){
  if(len!=NULL)
    *len=(u32)this->length;
  return (u8 *)(&h);
} /* End of getKnockData() */


/** Returns a pointer to the knock data.
  * @warning The caller must ensure setKnockData() has been called before
  * calling this method. Otherwise a zeroed buffer will be returned  */
u8 *PKDataStrong4::getKnockData(){
  return (u8 *)(&h);
} /* End of getKnockData() */


/** Stores caller supplied knock data in the object's internal buffer.
  * Normally the caller would store the knock data so it can later call
  * validate(), which will determine if the data is valid or not.
  * @warning supplied pointer MUST hold at least PK_STRONG_IPv4_DATA_LEN bytes.
  * @returns OP_SUCCESS on success and OP_FAILURE in case of error.
  * @warning This method overwrites the object's internal buffers. This includes
  * data produced by the other setKnockData(). */
int PKDataStrong4::setKnockData(u8 *buff){
  if(buff==NULL)
    return OP_FAILURE;
  memcpy(&(this->h), buff, PK_STRONG_IPv4_DATA_LEN);
  this->length=PK_STRONG_IPv4_DATA_LEN;
  return OP_SUCCESS;
} /* End of getKnockData() */


/** Encode knock data.
  * @param ip is the knock IP address, which MUST be an IPv4 address
  * @param port is the knock port.
  * @param action MUST be one of OPEN_PORT or CLOSE_PORT
  * @param buffer is the target buffer where the knock data will be stored. Note
  * that it MUST be able to hold at least PK_LIGHT_IPv4_DATA_LEN bytes. */
int PKDataStrong4::setKnockData(u8 *buffer, u32 *final_len, IPAddress ip, tcp_port_t port, int action, u8 *key, size_t keylen){

  u8 hmac[HMAC_SHA256_LEN];
  pk_strong_header_ipv4 *p = (pk_strong_header_ipv4 *)buffer;

  if(buffer==NULL)
     fatal(OUT_2, "%s(): NULL parameter supplied", __func__);
  if( ip.getVersion()!=AF_INET )
     fatal(OUT_2, "%s() Expected IP version 4 address. Please report a bug.", __func__);

  memcpy(p->nonce, o.rand.getRandomData(PK_STRONG_IPv4_NONCE_LEN), PK_STRONG_IPv4_NONCE_LEN);

    /* Set or unset the least significant bit */
  if(action==ACTION_OPEN)
    p->nonce[PK_STRONG_IPv4_NONCE_LEN-1] |= 0x01;
  else
    p->nonce[PK_STRONG_IPv4_NONCE_LEN-1] &= ~(0x01);

  p->timestamp = htonl( (u32)time(NULL) );
  p->knock_ip=ip.getIPv4Address();
  p->knock_port=htons(port);
  memset(p->mac, 0, PK_STRONG_IPv4_MAC_LEN);

  /* Now compute the HMAC-SHA256. Note that the last two bytes are set to zero,
   * except for the "action bit", which may be one or zero, depending on whether
   * the specified action is "OPEN_PORT" or "CLOSE_PORT" respectively */
  HMAC_SHA256::hmac_sha256(key, keylen, buffer, PK_STRONG_IPv4_DATA_LEN, hmac, HMAC_SHA256_LEN);

  /* Copy the 6 most significant bytes of the hash */
  memcpy(p->mac, hmac, PK_STRONG_IPv4_MAC_LEN);

  /* Update length */
  if(final_len!=NULL)
    *final_len=PK_STRONG_IPv4_DATA_LEN;

 return OP_SUCCESS;
} /* End of getKnockData_IPv4() */


/** Encode knock data.
  * @param ip is the knock IP address, which MUST be an IPv4 address
  * @param port is the knock port.
  * @param action MUST be one of OPEN_PORT or CLOSE_PORT */
int PKDataStrong4::setKnockData(IPAddress ip, tcp_port_t port, int action, u8 *key, size_t keylen){
  this->length=PK_STRONG_IPv4_DATA_LEN;
  return setKnockData((u8 *)&this->h, &this->length, ip, port, action, key, keylen);
}

IPAddress PKDataStrong4::getAddress(){
  IPAddress ip;
  ip.setAddress(this->h.knock_ip);
  return ip;
} /* End of getAddress() */


tcp_port_t PKDataStrong4::getPort(){
  return ntohs(this->h.knock_port);
}

int PKDataStrong4::getAction(){
  if( this->h.nonce[PK_STRONG_IPv4_NONCE_LEN-1]%2==0 )
    return ACTION_CLOSE;
  else
    return ACTION_OPEN;
}/* End of getPort() */


u32 PKDataStrong4::getTimestamp(){
  return ntohl(this->h.timestamp);
} /* End of getTimestamp() */


u8 *PKDataStrong4::getNonce(size_t *final_len){
  if(final_len!=NULL)
    *final_len=PK_STRONG_IPv4_NONCE_LEN;
  return this->h.nonce;
} /* End of getNonce() */


u8 *PKDataStrong4::getNonce(){
  return this->getNonce(NULL);
} /* End of getNonce() */


size_t PKDataStrong4::getNonceLength(){
    return PK_STRONG_IPv4_NONCE_LEN;
} /* End of getNonceLength() */


bool PKDataStrong4::validateKnockData(u8 *key, size_t keylen){
  u8 hmac[HMAC_SHA256_LEN];
  u8 backup[PK_STRONG_IPv4_MAC_LEN];
  memcpy(backup, this->h.mac,PK_STRONG_IPv4_MAC_LEN);
  memset(this->h.mac, 0, PK_STRONG_IPv4_MAC_LEN);
  HMAC_SHA256::hmac_sha256(key, keylen, (u8 *)&this->h , PK_STRONG_IPv4_DATA_LEN, hmac, HMAC_SHA256_LEN);
  memcpy(this->h.mac, backup, PK_STRONG_IPv4_MAC_LEN);
  if(memcmp(backup, hmac, PK_STRONG_IPv4_MAC_LEN)==0)
    return true;
  else
    return false;
} /* End of validateKnockData() */

/** Prints knock data as hexadecimal bytes.*/
const char *PKDataStrong4::toString(){
  static char buffer[256];
  snprintf(buffer, 256, "%s;%d;", this->getAddress().toString(), this->getPort());
  /** @todo finish this! */
  return buffer;
} /* End of IP_Id_printString() */
