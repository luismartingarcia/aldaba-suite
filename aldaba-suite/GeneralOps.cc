
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

/** \file filename.ext
  * \brief Short description. */

#include "GeneralOps.h"
#include "output.h"
#include "Crypto.h"

/* Constructor */
GeneralOps::GeneralOps(){
  this->reset();
}

GeneralOps::~GeneralOps(){
  this->reset();
}

void GeneralOps::reset(){

    memset(iface, 0, MAX_IFACE_LEN+1);
    iface_set=false;

    memset(path_cfile, 0, MAX_PATH_LEN+1);
    path_cfile_set=false;

    memset(pkseq, 0, MAX_PKSEQ_PORTS * sizeof(tcp_port_t) );
    total_pkseq_ports=0;
    pkseq_set=false;

    mode=DEFAULT_MODE;
    mode_set=false;

    field=COVERT_IP_ID;
    field_set=false;
    
    auth_type=DEFAULT_AUTH;
    auth_type_set=false;

    cipher=0;
    cipher_set=false;

    cipher_mode=DEFAULT_BLOCK_MODE;
    cipher_mode_set=false;

    memset(passphrase, 0, MAX_PASSPHRASE_LEN+1);
    passphrase_set=false;

    memset(cipher_key, 0, MAX_CIPHER_KEY_LEN+1);
    cipher_key_len=0;
    cipher_key_set=false;

    memset(mac_key, 0, MAX_MAC_KEY_LEN+1);
    mac_key_len=0;
    mac_key_set=false;

    vb=0;
    vb_set=false;

    lg=0;
    lg_set=false;

    is_root=0;
    is_root_set=false;

    ip_version=AF_INET;
    ip_version_set=false;

    memset(path_cfile, 0, sizeof(path_cfile));
    path_cfile_set=false;

    ssh_cookie=false;

} /* End if reset() */


/** Sets Interface.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int GeneralOps::setInterface(const char *val){
  strncpy(iface,val, MAX_IFACE_LEN);
  iface_set=true;
  return OP_SUCCESS;
} /* End of setInterface() */


/** Returns value of attribute iface */
char * GeneralOps::getInterface(){
  return this->iface;
} /* End of getInterface() */


/* Returns true if option has been set */
bool GeneralOps::issetInterface(){
  return this->iface_set;
} /* End of issetInterface() */


/** Sets ConfigurationFile.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int GeneralOps::setConfigurationFile(const char * val){
  if(val==NULL){
    fatal(OUT_2, "setConfigurationFile(): NULL parameter supplied");
  }else{
    strncpy(path_cfile, val, MAX_PATH_LEN);
    path_cfile_set=true;
  }
  return OP_SUCCESS;
} /* End of setConfigurationFile() */


/** Returns value of attribute path_cfile */
char * GeneralOps::getConfigurationFile(){
  return this->path_cfile;
} /* End of getConfigurationFile() */


/* Returns true if option has been set */
bool GeneralOps::issetConfigurationFile(){
  return this->path_cfile_set;
} /* End of issetConfigurationFile() */


/** Sets SequencePort.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int GeneralOps::setSequencePort(tcp_port_t val){
  if(this->total_pkseq_ports >= MAX_PKSEQ_PORTS)
    fatal(OUT_2,"setSequencePort(): Max number of PK sequence port reached\n");
  this->pkseq[total_pkseq_ports++]=val;
  this->pkseq_set=true;
  return OP_SUCCESS;
} /* End of setSequencePort() */



/** Generate Port Sequence */
int GeneralOps::derivePortSequence(size_t ports_needed){
  Crypto::derive_port_sequence(this->passphrase, this->pkseq, ports_needed);
  this->total_pkseq_ports=ports_needed;
  this->pkseq_set=true;
  return OP_SUCCESS;
} /* End of setSequencePort() */



size_t GeneralOps::getNumberOfSequencePorts(){
  return this->total_pkseq_ports;
} /* End of getNumberOfSequencePorts() */


/** Returns value of attribute pkseq */
tcp_port_t GeneralOps::getSequencePort(size_t index){
  if(index >= this->total_pkseq_ports )
    fatal(OUT_2,"getSequencePort(): Array index out of range\n");
  return this->pkseq[index];
} /* End of getSequencePort() */


/** Returns the list of sequence ports as an array of tcp_port_t variable.
  * If "final_ports" is not NULL, the number of ports in the array will be stored
  * there.
  * @warning The returned buffer is a dinamically allocated chunk of memory that
  * the caller should free. */
tcp_port_t *GeneralOps::getSequencePortArray(size_t *final_ports){
  if(final_ports!=NULL)
      *final_ports=this->getNumberOfSequencePorts();
  return this->pkseq;
} /* End of getSequencePort() */
tcp_port_t *GeneralOps::getSequencePortArray(){
  return this->getSequencePortArray(NULL);
} /* End of getSequencePort() */


/* Returns true if option has been set */
bool GeneralOps::issetSequencePorts(){
  return this->pkseq_set;
} /* End of issetSequencePort() */


/* Returns true if the supplied port is one of the sequence ports. */
bool GeneralOps::isSequencePort(tcp_port_t n){
  if(this->issetSequencePorts()==false)
    fatal(OUT_2, "%s() Bad internal state.\n", __func__);
  for(u16 i=0; i<this->getNumberOfSequencePorts(); i++){
    if(this->getSequencePort(i)==n)
        return true;
  }
  return false;
} /* End of isSequencePort() */


/** Returns printable ASCII string */
const char *GeneralOps::getSequencePorts_str(){
  static char str[512];
  str[0]='\0';
  for(u16 i=0; i<this->total_pkseq_ports; i++)
    snprintf(str+strlen(str), sizeof(str)-strlen(str)-1, "%d,", this->pkseq[i]);
  str[ strlen(str)-1 ]='\0';
  return str;
} /* End of getSequencePort() */



/** Sets Mode.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int GeneralOps::setMode(int val){
  this->mode=val;
  this->mode_set=true;
  return OP_SUCCESS;
} /* End of setMode() */


/** Returns value of attribute technique */
int GeneralOps::getMode(){
  return this->mode;
} /* End of getMode() */


/* Returns true if option has been set */
bool GeneralOps::issetMode(){
  return this->mode_set;
} /* End of issetMode() */


/** Returns printable ASCII string */
const char *GeneralOps::getMode_str(){
  switch(this->mode){
      case MODE_PORTKNOCKING:
          return "PK";
      break;
      case MODE_SPA:
          return "SPA";
      break;
  }
  return "MODE_UNKNOWN";
} /* End of getMode_str() */



/** Sets AuthType.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int GeneralOps::setAuthType(int val){
  this->auth_type=val;
  this->auth_type_set=true;
  return OP_SUCCESS;
} /* End of setAuthType() */


/** Returns value of attribute technique */
int GeneralOps::getAuthType(){
  return this->auth_type;
} /* End of getAuthType() */


/* Returns true if option has been set */
bool GeneralOps::issetAuthType(){
  return this->auth_type_set;
} /* End of issetAuthType() */


/** Returns printable ASCII string */
const char *GeneralOps::getAuthType_str(){
  switch(this->auth_type){
      case AUTH_TYPE_LIGHT:
          return "Light";
      break;
      case AUTH_TYPE_STRONG:
          return "Strong";
      break;
  }
  return "AUTH_UNKNOWN";
} /* End of getAuthType_str() */



/** Sets Field.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int GeneralOps::setField(int val){
  this->field=val;
  this->field_set=true;
  return OP_SUCCESS;
} /* End of setField() */


/** Returns value of attribute field */
int GeneralOps::getField(){
  return this->field;
} /* End of getField() */

/* Returns true if option has been set */
bool GeneralOps::issetField(){
  return this->field_set;
} /* End of issetField() */


/** Returns printable ASCII string */
const char *GeneralOps::getField_str(){
  switch(this->field){
      case COVERT_IP_TOS:
          return "IP-TOS";
      break;
      case COVERT_IP_ID:
          return "IP-Id";
      break;
      case COVERT_TCP_ACK:
          return "TCP-Ack";
      break;
      case COVERT_TCP_SEQ:
          return "TCP-Seq";
      break;    
      case COVERT_TCP_SPORT:
          return "TCP-SPort";
      break;
      case COVERT_TCP_DPORT:
          return "TCP-DPort";
      break;
      case COVERT_TCP_WINDOW:
          return "TCP-Win";
      break;
      case COVERT_TCP_URP:
          return "TCP-UrP";
      break;
      case COVERT_TCP_CSUM:
          return "TCP-Sum";
      break;
  }
  return "FIELD_UNKNOWN";
} /* End of getField_str() */



/** Sets Cipher.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int GeneralOps::setCipher(int val){
  this->cipher=val;
  this->cipher_set=true;
  return OP_SUCCESS;
} /* End of setCipher() */


/** Returns value of attribute cipher */
int GeneralOps::getCipher(){
  return this->cipher;
} /* End of getCipher() */


/* Returns true if option has been set */
bool GeneralOps::issetCipher(){
  return this->cipher_set;
} /* End of issetCipher() */


/** Returns printable ASCII string */
const char *GeneralOps::getCipher_str(){
  switch(this->cipher){
      case ALG_BLOWFISH:
          return "Blowfish";
      break;
      case ALG_TWOFISH:
          return "Twofish";
      break;
      case ALG_RIJNDAEL:
          return "AES";
      break;
      case ALG_SERPENT:
          return "Serpent";
      break;
      case ALG_MD5:
          return "MD5";
      break;
      case ALG_SHA256:
          return "SHA256";
      break;
  }
  return "CIPHER_UNKNOWN";
} /* End of getCipher_str() */



/** Sets CipherMode.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int GeneralOps::setCipherMode(int val){
  this->cipher_mode=val;
  this->cipher_mode_set=true;
  return OP_SUCCESS;
} /* End of setCipherMode() */


/** Returns value of attribute cipher_mode */
int GeneralOps::getCipherMode(){
  return this->cipher_mode;
} /* End of getCipherMode() */


/* Returns true if option has been set */
bool GeneralOps::issetCipherMode(){
  return this->cipher_mode_set;
} /* End of issetCipherMode() */


/** Returns printable ASCII string */
const char *GeneralOps::getCipherMode_str(){
  switch(this->cipher_mode){
      case BLOCK_MODE_ECB:
          return "ECB";
      break;
      case BLOCK_MODE_CBC:
          return "CBC";
      break;
      case BLOCK_MODE_CFB:
          return "CFB";
      break;
      case BLOCK_MODE_OFB:
          return "OFB";
      break;
  }
  return "CIPHERMODE_UNKNOWN";
} /* End of getCipherMode_str() */




/** Sets user passphrase.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int GeneralOps::setPassphrase(const char *val){
  if(val==NULL)
    fatal(OUT_2,"setCipherKey(): NULL parameter supplied\n");
  else if(strlen(val)<MIN_PASSPHRASE_LEN )
    fatal(OUT_2,"Passphrases must have at least %d characters.\n", MIN_PASSPHRASE_LEN);
  else if(strlen(val)>MAX_PASSPHRASE_LEN )
    fatal(OUT_2,"Passphrases must have less than %d characters.\n", MAX_PASSPHRASE_LEN);
  strncpy(this->passphrase, val, MAX_PASSPHRASE_LEN);
  this->passphrase_set=true;
  return OP_SUCCESS;
} /* End of setPassphrase() */


/** Returns value of attribute passphrase */
const char *GeneralOps::getPassphrase(){
  return this->passphrase;
} /* End of getPassphrase() */


/* Returns true if option has been set */
bool GeneralOps::issetPassphrase(){
  return this->passphrase_set;
} /* End of issetPassphrase() */


/** Sets CipherKey.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int GeneralOps::computeCipherKey(){
  if(!this->issetPassphrase())
    fatal(OUT_2, "%s(): Cannot compute cipher key if no passphrase has been set", __func__);
  if( Crypto::derive_cipher_key_256(passphrase, this->cipher_key) != OP_SUCCESS ){
      return OP_FAILURE;
  }else{
      this->cipher_key_set=true;
      this->cipher_key_len=256/8;
  }
  return OP_SUCCESS;
} /* End of setCipherKey() */


/** Returns value of attribute e_key */
u8 * GeneralOps::getCipherKey(){
  return this->cipher_key;
} /* End of getCipherKey() */


/** Stores cipher key in the supplied buffer. The caller may find out
  * the number of bytes written to the buffer using getCipherKeyLength()
  */
int GeneralOps::getCipherKey(u8 *buff, int max_buff_len){
  if(buff==NULL)
    fatal(OUT_2,"getCipherKey(): NULL parameter supplied\n");
  if( this->cipher_key_set == false )
    return OP_FAILURE;
  if( max_buff_len < this->cipher_key_len )
    return OP_FAILURE;
  memcpy(buff, this->cipher_key, this->cipher_key_len);
  return OP_SUCCESS;
} /* End of getCipherKey() */


/** Returns length of the key or OP_FAILURE in case the key has not
  * been set yet. */
int GeneralOps::getCipherKeyLength(){
  if( this->cipher_key_set == false )
    return OP_FAILURE;
  else
    return this->cipher_key_len;
} /* End of getCipherKeyLength() */


/** Returns printable ASCII string */
const char *GeneralOps::getCipherKey_str(){
  static char str[512];
  str[0]='\0';
  for(u16 i=0; i<this->cipher_key_len; i++)
    snprintf(str+strlen(str), sizeof(str)-strlen(str)-1, "%02x", this->cipher_key[i]);
  str[ strlen(str)-1 ]='\0';
  return str;
} /* End of getSequencePort() */


/* Returns true if option has been set */
bool GeneralOps::issetCipherKey(){
  return this->cipher_key_set;
} /* End of issetCipherKey() */




/** Sets MacKey.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int GeneralOps::computeMacKey(){
  if(!this->issetPassphrase())
    fatal(OUT_2, "%s(): Cannot compute MAC key if no passphrase has been set", __func__);
  if( Crypto::derive_mac_key_256(passphrase, this->mac_key) != OP_SUCCESS ){
      return OP_FAILURE;
  }else{
      this->mac_key_set=true;
      this->mac_key_len=256/8;
  }
  return OP_SUCCESS;
} /* End of setMacKey() */


/** Returns value of attribute mac_key */
u8 * GeneralOps::getMacKey(){
  return this->mac_key;
} /* End of getMacKey() */


/** Stores cipher key in the supplied buffer. The caller may find out
  * the number of bytes written to the buffer using getMacKeyLength()
  */
int GeneralOps::getMacKey(u8 *buff, int max_buff_len){
  if(buff==NULL)
    fatal(OUT_2,"getMacKey(): NULL parameter supplied\n");
  if( this->mac_key_set == false )
    return OP_FAILURE;
  if( max_buff_len < this->mac_key_len )
    return OP_FAILURE;
  memcpy(buff, this->mac_key, this->mac_key_len);
  return OP_SUCCESS;
} /* End of getMacKey() */


/** Returns length of the key or OP_FAILURE in case the key has not
  * been set yet. */
int GeneralOps::getMacKeyLength(){
  if( this->mac_key_set == false )
    return OP_FAILURE;
  else
    return this->mac_key_len;
} /* End of getMacKeyLength() */


/** Returns printable ASCII string */
const char *GeneralOps::getMacKey_str(){
  static char str[512];
  str[0]='\0';
  for(u16 i=0; i<this->mac_key_len; i++)
    snprintf(str+strlen(str), sizeof(str)-strlen(str)-1, "%02x", this->mac_key[i]);
  str[ strlen(str)-1 ]='\0';
  return str;
} /* End of getSequencePort() */


/* Returns true if option has been set */
bool GeneralOps::issetMacKey(){
  return this->mac_key_set;
} /* End of issetMacKey() */


/** Sets VerbosityLevel.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int GeneralOps::setVerbosityLevel(int val){
  this->vb=val;
  this->vb_set=true;
  return OP_SUCCESS;
} /* End of setVerbosityLevel() */


/** Returns value of attribute vb */
int GeneralOps::getVerbosityLevel(){
  return this->vb;
} /* End of getVerbosityLevel() */


/* Returns true if option has been set */
bool GeneralOps::issetVerbosityLevel(){
  return this->vb_set;
} /* End of issetVerbosityLevel() */


/** Sets LoggingLevel.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int GeneralOps::setLoggingLevel(int val){
  this->lg=val;
  this->lg_set=true;
  return OP_SUCCESS;
} /* End of setLoggingLevel() */


/** Returns value of attribute db */
int GeneralOps::getLoggingLevel(){
  return this->lg;
} /* End of getLoggingLevel() */


/* Returns true if option has been set */
bool GeneralOps::issetLoggingLevel(){
  return this->lg_set;
} /* End of issetLoggingLevel() */


/** Sets IsRoot.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int GeneralOps::setIsRoot(bool val){
  this->is_root=val;
  this->is_root_set=true;
  return OP_SUCCESS;
} /* End of setIsRoot() */


/** Returns value of attribute is_root */
bool GeneralOps::isRoot(){
  return this->is_root;
} /* End of getIsRoot() */


/* Returns true if option has been set */
bool GeneralOps::issetIsRoot(){
  return this->is_root_set;
} /* End of issetIsRoot() */


/** Sets IPVersion.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int GeneralOps::setIPVersion(int val){
  if(val!=AF_INET && val!=AF_INET6){
    fatal(OUT_1, "setIPVersion(): Bogus version supplied");
  }else{
    this->ip_version=val;
    this->ip_version_set=true;
  }
  return OP_SUCCESS;
} /* End of setIPVersion() */


/** Returns value of attribute ip_version */
int GeneralOps::getIPVersion(){
  return this->ip_version;
} /* End of getIPVersion() */


/* Returns true if option has been set */
bool GeneralOps::issetIPVersion(){
  return this->ip_version_set;
} /* End of issetIPVersion() */


/** Returns printable ASCII string */
const char *GeneralOps::getIPVersion_str(){
  switch(this->ip_version){
      case AF_INET:
          return "IPv4";
      break;
      case AF_INET6:
          return "IPv6";
      break;
  }
  return "IPVERSION_UNKNOWN";
} /* End of getIPVersion_str() */


int GeneralOps::enableSSHCookie(){
  this->ssh_cookie=true;
  return OP_SUCCESS;
} /* End of enableSSHCookie() */

int GeneralOps::disableSSHCookie(){
  this->ssh_cookie=false;
  return OP_SUCCESS;
} /* End of disableSSHCookie() */


/* Returns true if option has been set */
bool GeneralOps::SSHCookie(){
  return this->ssh_cookie;
} /* End of SSHCookie() */