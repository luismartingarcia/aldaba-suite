
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
#include "ServerOps.h"
#include "output.h"
#include "tools.h"
#include "PKDataLight4.h"
#include "PKDataLight6.h"
#include "PKDataStrong4.h"
#include "PKDataStrong6.h"

/* Constructor */
ServerOps::ServerOps(){
  this->reset();
}

ServerOps::~ServerOps(){
  this->reset();
}

void ServerOps::reset(){

    promiscuous=false;
    promiscuous_set=false;

    daemonize=true;
    daemonize_set=false;

    data_link_header_len=14;
    data_link_header_len_set=false;

    open_time=60;
    open_time_set=false;

    memset(bpf_filter, 0, sizeof(bpf_filter));
    bpf_filter_set=false;

} /* End if reset() */


/** Sets Promiscuous.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ServerOps::setPromiscuous(bool val){
  this->promiscuous=val;
  this->promiscuous_set=true;
  return OP_SUCCESS;
} /* End of setPromiscuous() */


/** Returns value of attribute promiscuous */
bool ServerOps::getPromiscuous(){
  return this->promiscuous;
} /* End of getPromiscuous() */


/* Returns true if option has been set */
bool ServerOps::issetPromiscuous(){
  return this->promiscuous_set;
} /* End of issetPromiscuous() */


/** Sets open time in seconds.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ServerOps::setOpenTime(int val){
  printf("ServerOPs time set: %i \n", val);
  this->open_time=val;
  this->open_time_set=true;
  return OP_SUCCESS;
} /* End of setOpenTime() */

/** Returns value of attribute open_time */
int ServerOps::getOpenTime(){
  return this->open_time;
} /* End of getLoggingLevel() */

/* Returns true if option has been set */
bool ServerOps::issetOpenTime(){
  return this->open_time_set;
} 


/** Sets Daemonize.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ServerOps::setDaemonize(bool val){
  this->daemonize=val;
  this->daemonize_set=true;
  return OP_SUCCESS;
} /* End of setDaemonize() */


/** Returns value of attribute daemonize */
bool ServerOps::getDaemonize(){
  return this->daemonize;
} /* End of getDaemonize() */


/* Returns true if option has been set */
bool ServerOps::issetDaemonize(){
  return this->daemonize_set;
} /* End of issetDaemonize() */


/** Sets LinkHeaderLength.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ServerOps::setLinkHeaderLength(u16 val){
  this->data_link_header_len=val;
  this->data_link_header_len_set=true;
  return OP_SUCCESS;
} /* End of setLinkHeaderLength() */


/** Returns value of attribute data_link_header_len */
u16 ServerOps::getLinkHeaderLength(){
  return this->data_link_header_len;
} /* End of getLinkHeaderLength() */


/* Returns true if option has been set */
bool ServerOps::issetLinkHeaderLength(){
  return this->data_link_header_len_set;
} /* End of issetLinkHeaderLength() */


/** Sets BPF.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ServerOps::setBPF(const char * val){
  strncpy(this->bpf_filter, val, sizeof(this->bpf_filter)-1);
  this->bpf_filter_set=true;
  return OP_SUCCESS;
} /* End of setBPF() */


/** Returns value of attribute bpf_filter */
char * ServerOps::getBPF(){
  return this->bpf_filter;
} /* End of getBPF() */


/* Returns true if option has been set */
bool ServerOps::issetBPF(){
  return this->bpf_filter_set;
} /* End of issetBPF() */


int ServerOps::validateConfiguration(){

 /* -> If no IP version is set, go with IP version 4 */
 if( !this->issetIPVersion() )
    this->setIPVersion(AF_INET);

 /*----------------------------*
  * OPERATION MODE (PK or SPA) *
  *----------------------------*/

  /* If no mode was specified, but only one port was supplied -> SPA */
  if( !this->issetMode() && this->getNumberOfSequencePorts() == 1)
      this->setMode(MODE_SPA);

  /* If no mode was specified, but many ports were supplied -> PK */
  if( !this->issetMode() && this->getNumberOfSequencePorts() > 1)
      this->setMode(MODE_PORTKNOCKING);

  /* If no mode was specified, set default */
  if( !this->issetMode() )
      this->setMode(DEFAULT_MODE);

 /*---------------------------------*
  * AUTHENTICATION & COVERT CHANNEL *
  *---------------------------------*/
  if( this->getMode()==MODE_PORTKNOCKING ){

    /* If no auth was set, set default */
    if( !this->issetAuthType() )
        this->setAuthType(DEFAULT_AUTH);

    /* If no cover channel heder field was set, set default */
     if(!this->issetField() )
        this->setField(DEFAULT_COVERT_FIELD);
  }

 /*-------------------*
  *   PORT SEQUENCE   *
  *-------------------*/
  if( this->getMode()==MODE_PORTKNOCKING ){

    /* Determine how many ports form the knocking port sequence */
    u32 flen=field2len(this->getField());
    size_t ports_needed;
    if(this->getAuthType()==AUTH_TYPE_LIGHT && this->getIPVersion()==AF_INET){
        ports_needed = PK_LIGHT_IPv4_DATA_LEN/flen;
    }else if(this->getAuthType()==AUTH_TYPE_LIGHT && this->getIPVersion()==AF_INET6){
        ports_needed = PK_LIGHT_IPv6_DATA_LEN/flen;
    }else if(this->getAuthType()==AUTH_TYPE_STRONG && this->getIPVersion()==AF_INET){
        ports_needed = PK_STRONG_IPv4_DATA_LEN/flen;
    }else{ /* AUTH_TYPE_STRONG && AF_INET6 */
        ports_needed = PK_STRONG_IPv6_DATA_LEN/flen;
    }

    /* Check user supplied the correct number of ports */
    if( !this->issetSequencePorts()){
        this->derivePortSequence(ports_needed);
    }else if(this->getNumberOfSequencePorts() < ports_needed)
        fatal(OUT_2, "Not enough target ports. %lu port numbers expected.", (unsigned long)ports_needed);
    else if (this->getNumberOfSequencePorts() > ports_needed)
        fatal(OUT_2, "Too many target ports. %lu port numbers expected.", (unsigned long)ports_needed);

  }else{ /* MODE_SPA */
     /*  If no target port was supplied in SPA mode, use the default */
    if( this->getNumberOfSequencePorts()==0 ){
        this->derivePortSequence(1);
    }else if( this->getNumberOfSequencePorts()>1 ){
        fatal(OUT_2, "Too many target ports. SPA mode requires a single port number.");
    }
 }

 /*----------------------------------*
  *   VERBOSITY AND LOGGING LEVELS   *
  *----------------------------------*/

  /* -> If verbosity level was not specified, set default */
  if ( !this->issetVerbosityLevel() ){
      this->setVerbosityLevel(DEFAULT_VERBOSITY_SERVER);
  }

  /* -> If logging level was not specified, set default */
  if ( !this->issetLoggingLevel() ){
     this->setLoggingLevel(DEFAULT_LOGGING_SERVER);
  }

 /*--------------------------------*
  *   PRIVILEGES AND PERMISSIONS   *
  *--------------------------------*/

  /* Determine if user is root */
  this->setIsRoot((geteuid()==0) ? true : false);

  /* For PK, user must be root */
  if (!this->isRoot()){
    fatal(OUT_2, "ERROR: You need to be root to run Aldaba Server.\n");
  }


 /*------------------*
  *   CRYPTOGRAPHY   *
  *------------------*/

  /* If no encryption algorithm was specified, set default */
  if (!this->issetCipher()){
    if( this->getMode()==MODE_PORTKNOCKING)
        this->setCipher(DEFAULT_ALG_PK);
    else
        this->setCipher(DEFAULT_ALG_SPA);
  }else {
    if( this->getMode()==MODE_PORTKNOCKING && this->getCipher()!=ALG_BLOWFISH )
        fatal(OUT_2, "Sorry but use of Port Knocking is restricted to the Blowfish cipher");
  }

  /* If no cipher block mode was specified, set default */
  if( !this->issetCipherMode() ){
    if( this->getMode()==MODE_PORTKNOCKING)
        this->setCipherMode(BLOCK_MODE_ECB);
    else
        this->setCipherMode(DEFAULT_BLOCK_MODE);
  }else {
    if( this->getMode()==MODE_PORTKNOCKING && this->getCipherMode()!=BLOCK_MODE_ECB )
        fatal(OUT_2, "Sorry but use of Port Knocking is restricted to the ECB block cipher mode.");
  }
 
  /* Select a network interface */
  if (!this->issetInterface()){
    char *iface=NULL;
    if( (iface=select_iface( this->getIPVersion() ))==NULL )
        fatal(OUT_2, "Couldn't select network interface for capture. Please use option -i <iface>");
    else
        this->setInterface(iface);
    }
  /* If no passphrase was supplied, ask interactively if possible */
  if(!this->issetPassphrase()){
    if( this->getDaemonize()==false){
        size_t read_bytes=0;
        char buffer[MAX_PASSPHRASE_LEN];
        memset(buffer, 0, MAX_PASSPHRASE_LEN);
        printf("Please enter the passphrase: ");
        read_password(buffer, MAX_PASSPHRASE_LEN-1, &read_bytes);
        printf("\n");
        if( strlen(buffer) < MIN_PASSPHRASE_LEN ){
            fatal(OUT_2, "Supplied passphrase is too short. Passphrases need to contain at least %d characters", MIN_PASSPHRASE_LEN );
        }else{
            this->setPassphrase(buffer);
        }
      }else{
          fatal(OUT_2, "Aldaba Server cannot be run in daemon mode without supplying a passphrase through the command line.");
      }
  }
  this->computeCipherKey();
  this->computeMacKey();

  return OP_SUCCESS;
} /* End of validateConfiguration() */
