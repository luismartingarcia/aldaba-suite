
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
 
#include "SPAHeader.h"
#include "aldaba.h"
#include "output.h"
#include "tools.h"
#include "crypto_tools.h"
#include "hmac_sha256.h"
#include "IPAddress.h"
#include <assert.h>


SPAHeader::SPAHeader(){
  this->reset();
} /* End of SPAHeader constructor */


SPAHeader::~SPAHeader() {
  this->reset();
} /* End of SPAHeader destructor */

/** Sets every attribute to its default value- */
void SPAHeader::reset() {
  memset(&h, 0, sizeof(spahdr_t));
  this->length=sizeof(spahdr_t); 
  this->setSPAVersion(0x01);
  this->setMagicNumber(0xA1DABA77);
} /* End of SPAHeader destructor */


/** @warning This method is essential for the superclass getBinaryBuffer()
 *  method to work. Do NOT change a thing unless you know what you're doing  */
u8 *SPAHeader::getBufferPointer(){
  return (u8*)(&h);
} /* End of getBufferPointer() */


/** Stores supplied packet in the internal buffer so the information
  * can be accessed using the standard get & set methods.
  * @warning  The SPAHeader class is able to hold a maximum of SPA_HEADER_LEN
  * bytes. If the supplied buffer is bigger than that, only the first
  * SPA_HEADER_LEN bytes will be stored in the internal buffer.
  * @warning Supplied len MUST be at least SPA_HEADER_LEN bytes (SPA length).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error */
int SPAHeader::storeRecvData(const u8 *buf, size_t len){
  if(buf==NULL || len<SPA_HEADER_LEN){
    return OP_FAILURE;
  }else{
    this->reset(); /* Re-init the object, just in case the caller had used it already */
    this->length=SPA_HEADER_LEN;
    memcpy(&(this->h), buf, SPA_HEADER_LEN);
  }
 return OP_SUCCESS;
} /* End of storeRecvData() */


/** This method is provided for consistency with other classes of the
  * PacketElement family. 99.9% of the cases, it returns 40 (the length of the
  * IPv6 header). If for some reason, the internal state of the object is not
  * correct, OP_FAILURE (-1) is returned. */
int SPAHeader::validate(){
  if( this->length!=SPA_HEADER_LEN)
      return OP_FAILURE;
  else
      return SPA_HEADER_LEN;
} /* End of validate() */



/** Sets InitializationVector.
  *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int SPAHeader::setInitializationVector(u8 * val){
  assert(val);
  memcpy(this->h.iv, val, SPA_IV_LEN);
  return OP_SUCCESS;
} /* End of setInitializationVector() */


/** Returns value of attribute h.iv */
u8 *SPAHeader::getInitializationVector(){
  return this->h.iv;
} /* End of getInitializationVector() */


/** Sets SPAVersion.
  *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int SPAHeader::setSPAVersion(u8 val){
  this->h.spa_version=val;
  return OP_SUCCESS;
} /* End of setSPAVersion() */


/** Returns value of attribute h.spa_version */
u8 SPAHeader::getSPAVersion(){
  return this->h.spa_version;
} /* End of getSPAVersion() */


/** Sets IPVersion.
  *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int SPAHeader::setIPVersion(u8 val){
  this->h.ip_version=val;
  return OP_SUCCESS;
} /* End of setIPVersion() */



/** Returns value of attribute h.ip_version */
u8 SPAHeader::getIPVersion(){
  return this->h.ip_version;
} /* End of getIPVersion() */


/** Sets ProtocolPort1.
  *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int SPAHeader::setProtocolPort1(u8 val){
  this->h.proto_p1=val;
  return OP_SUCCESS;
} /* End of setProtocolPort1() */


/** Returns value of attribute h.proto_p1 */
u8 SPAHeader::getProtocolPort1(){
  return this->h.proto_p1;
} /* End of getProtocolPort1() */


/** Sets ActionPort1.
  *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int SPAHeader::setActionPort1(u8 val){
  this->h.action_p1=val;
  return OP_SUCCESS;
} /* End of setActionPort1() */


/** Returns value of attribute h.action_p1 */
u8 SPAHeader::getActionPort1(){
  return this->h.action_p1;
} /* End of getActionPort1() */


/** Sets ProtocolPort2.
  *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int SPAHeader::setProtocolPort2(u8 val){
  this->h.proto_p2=val;
  return OP_SUCCESS;
} /* End of setProtocolPort2() */


/** Returns value of attribute h.proto_p2 */
u8 SPAHeader::getProtocolPort2(){
  return this->h.proto_p2;
} /* End of getProtocolPort2() */


/** Sets ActionPort2.
  *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int SPAHeader::setActionPort2(u8 val){
  this->h.action_p2=val;
  return OP_SUCCESS;
} /* End of setActionPort2() */


/** Returns value of attribute h.action_p2 */
u8 SPAHeader::getActionPort2(){
  return this->h.action_p2;
} /* End of getActionPort2() */


/** Sets Port1.
  *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int SPAHeader::setPort1(u16 val){
  this->h.port1=htons(val);
  return OP_SUCCESS;
} /* End of setPort1() */


/** Returns value of attribute h.port1 */
u16 SPAHeader::getPort1(){
  return ntohs(this->h.port1);
} /* End of getPort1() */


/** Sets Port2.
  *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int SPAHeader::setPort2(u16 val){
  this->h.port2=htons(val);
  return OP_SUCCESS;
} /* End of setPort2() */


/** Returns value of attribute h.port2 */
u16 SPAHeader::getPort2(){
  return ntohs(this->h.port2);
} /* End of getPort2() */


/** Sets MagicNumber.
  *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int SPAHeader::setMagicNumber(u32 val){
  this->h.magic=htonl(val);
  return OP_SUCCESS;
} /* End of setMagicNumber() */


/** Returns value of attribute h.magic */
u32 SPAHeader::getMagicNumber(){
  return ntohl(this->h.magic);
} /* End of getMagicNumber() */


/** Sets Reserved.
  *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int SPAHeader::setReserved(u32 val){
  this->h.reserved=htonl(val);
  return OP_SUCCESS;
} /* End of setReserved() */


/** Returns value of attribute h.reserved */
u32 SPAHeader::getReserved(){
  return ntohl(this->h.reserved);
} /* End of getReserved() */


/** Sets Address.
  *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int SPAHeader::setAddress(struct in_addr addr){
  memset(this->h.address, 0, SPA_ADDR_LEN);
  memcpy(this->h.address, &addr.s_addr, 4);
  this->setIPVersion(0x04);
  return OP_SUCCESS;
} /* End of setAddress() */


/** Sets Address.
  *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int SPAHeader::setAddress(struct in6_addr addr){
  memcpy(this->h.address, addr.s6_addr, 16);
  this->setIPVersion(0x06);
  return OP_SUCCESS;
} /* End of setAddress() */


/** Returns value of attribute h.address */
IPAddress SPAHeader::getAddress(){
  IPAddress ip;
  struct in_addr i4;
  struct in6_addr i6;
  if(this->getIPVersion()==0x04){
      i4.s_addr= *((u32 *)this->h.address);
      ip.setAddress(i4);
  }else{
      memcpy(i6.s6_addr, this->h.address, 16);
      ip.setAddress(i6);
  }
  return ip;
} /* End of getAddress() */


/** Returns value of attribute h.address */
int SPAHeader::getAddress(struct in_addr *addr){
  struct in_addr *pnt=(struct in_addr*)this->h.address;
  if(addr!=NULL && this->getIPVersion()==0x04){
    *addr=*pnt;
    return OP_SUCCESS;
  }else{
    return OP_FAILURE;
  }
} /* End of getAddress() */


/** Returns value of attribute h.address */
int SPAHeader::getAddress(struct in6_addr *addr){
  struct in6_addr *pnt=(struct in6_addr*)this->h.address;
  if(addr!=NULL && this->getIPVersion()==0x06){
    *addr=*pnt;
    return OP_SUCCESS;
  }else{
    return OP_FAILURE;
  }
} /* End of getAddress() */


/** Sets Timestamp.
  *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int SPAHeader::setTimestamp(u32 val){
  this->h.timestamp=htonl(val);
  return OP_SUCCESS;
} /* End of setTimestamp() */


/** Returns value of attribute h.timestamp */
u32 SPAHeader::getTimestamp(){
  return ntohl(this->h.timestamp);
} /* End of getTimestamp() */


/** Sets Nonce.
  *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int SPAHeader::setNonce(u8 * val){
  assert(val);
  memcpy(this->h.nonce, val, SPA_NONCE_LEN);
  return OP_SUCCESS;
} /* End of setNonce() */


/** Returns value of attribute h.nonce */
u8 * SPAHeader::getNonce(){
  return this->h.nonce;
} /* End of getNonce() */


/** Sets Username.
  *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int SPAHeader::setUsername(const char *val){
  assert(val);
  memset(this->h.username, 0, SPA_USERNAME_LEN);
  strncpy(this->h.username, val, SPA_USERNAME_LEN);
  return OP_SUCCESS;
} /* End of setUsername() */


/** Returns value of attribute h.username.
  * @warning returned string may not be NULL terminated. The caller MUST make 
  * sure no more than SPA_USERNAME_LEN bytes are read. */
char *SPAHeader::getUsername(){
  return this->h.username;
} /* End of getUsername() */


/** Sets Userdata.
  *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int SPAHeader::setUserdata(u8 * val){
  assert(val);
  memcpy(this->h.userdata, val, SPA_USERDATA_LEN);
  return OP_SUCCESS;
} /* End of setUserdata() */


/** Returns value of attribute h.userdata */
u8 * SPAHeader::getUserdata(){
  return this->h.userdata;
} /* End of getUserdata() */


/** Sets MAC.
  *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int SPAHeader::setMAC(u8 * val){
  assert(val);
  memcpy(this->h.mac, val, SPA_MAC_LEN);
  return OP_SUCCESS;
} /* End of setMAC() */


int SPAHeader::setMAC(u8 *key, size_t keylen){
  u8 computedmac[SPA_MAC_LEN];
  assert(key!=NULL && keylen!=0);
  HMAC_SHA256::hmac_sha256(key, (unsigned int)keylen, (unsigned char*)&this->h, SPA_HEADER_LEN-SPA_MAC_LEN, computedmac, SPA_MAC_LEN);
  memcpy(this->h.mac, computedmac, SPA_MAC_LEN);
  return OP_SUCCESS;
} /* End of setMAC() */


/** Returns value of attribute h.mac */
u8 *SPAHeader::getMAC(){
  return this->h.mac;
} /* End of getMAC() */

int SPAHeader::verifyMAC(u8 *key, size_t keylen){
  u8 mac_backup[SPA_MAC_LEN];
  u8 *aux;

  /* Make a copy of the current MAC */
  if( (aux=this->getMAC())==NULL )
      return OP_FAILURE;
  memcpy(mac_backup, aux, SPA_MAC_LEN);

  /* Recompute the MAC */
  memset(aux, 0, SPA_MAC_LEN);
  this->setMAC(key, keylen);

  /* Try to match both MACs*/
  if( (aux=this->getMAC())==NULL )
      return OP_FAILURE;
  if( memcmp(mac_backup, aux, SPA_MAC_LEN)==0  ){
    return OP_SUCCESS;
  }else{
    /* Restore original MAC */
    memcpy(aux, mac_backup, SPA_MAC_LEN);
    return OP_FAILURE;
  }
} /* End of verifyMAC() */


int SPAHeader::encrypt(int cipher, int mode, u8 *key, size_t keylen){
  u8 ciphertext[SPA_HEADER_LEN];
  u8 *start=(u8 *)(&this->h.spa_version);
  u8 *iv=(u8 *)(&this->h);
  size_t len=SPA_HEADER_LEN-SPA_IV_LEN;

  if( encrypt_buffer(start, len, ciphertext, key, keylen, iv, cipher, mode)!=OP_SUCCESS )
      return OP_FAILURE;
  memcpy(start, ciphertext, len);
  return OP_SUCCESS;
} /* End of encrypt() */


int SPAHeader::decrypt(int cipher, int mode, u8 *key, size_t keylen){
  u8 plaintext[SPA_HEADER_LEN];
  u8 *start=(u8 *)(&this->h.spa_version);
  u8 *iv=(u8 *)(&this->h);
  size_t len=SPA_HEADER_LEN-SPA_IV_LEN;

  if( decrypt_buffer(start, len, plaintext, key, keylen, iv, cipher, mode)!=OP_SUCCESS )
      return OP_FAILURE;
  memcpy(start, plaintext, len);
  return OP_SUCCESS;
} /* End of decrypt() */



char *SPAHeader::toString(){
  return NULL;
} /* End of toString() */

