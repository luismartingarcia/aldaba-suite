
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
#include "ClientOps.h"
#include "output.h"
#include "tools.h"
#include "PKDataLight4.h"
#include "PKDataLight6.h"
#include "PKDataStrong4.h"
#include "PKDataStrong6.h"
#include "AddressResolver.h"
#include "IPAddress.h"

/* Constructor */
ClientOps::ClientOps(){
  this->reset();
}

ClientOps::~ClientOps(){
  if(this->noise_ports!=NULL)
    free(noise_ports);
}

void ClientOps::reset(){

    memset(hostname, 0, MAX_HOSTNAME_LEN+1);
    hostname_set=false;

    dst_ip.reset();
    dst_ip_set=false;

    src_ip.reset();
    src_ip_set=false;

    do_resolution=false;
    address_resolver.reset();
    address_resolver_set=false;

    knock_ip.reset();
    knock_ip_set=false;

    forward_ip.reset();
    forward_ip_set=false;

    memset(knock_ports, 0, sizeof(knock_ports));
    knock_ports_set=0;

    decoys.clear();
    decoys_set=false;

    memset(knock_actions, 0, sizeof(knock_actions));
    knock_actions_set=0;

    noise=0;
    noise_set=false;
    noise_ports=NULL;
    
    delay=0;
    delay_set=false;

} /* End if reset() */


/** Sets Hostname.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ClientOps::setHostname(const char * val){
    strncpy(this->hostname, val, MAX_HOSTNAME_LEN);
    hostname_set=true;
    return this->setDestinationIP(val);
} /* End of setHostname() */


/** Returns value of attribute hostname */
char * ClientOps::getHostname(){
  return this->hostname;
} /* End of getHostname() */


/* Returns true if option has been set */
bool ClientOps::issetHostname(){
  return this->hostname_set;
} /* End of issetHostname() */


/** Sets DestinationIP.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ClientOps::setDestinationIP(IPAddress val){
  this->dst_ip=val;
  this->dst_ip_set=true;
  return OP_SUCCESS;
} /* End of setDestinationIP() */


/** Sets DestinationIP.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ClientOps::setDestinationIP(const char *val){

  if(this->getIPVersion()==AF_INET6){
    if( this->dst_ip.setIPv6Address(val) != OP_SUCCESS ){
        return OP_FAILURE;
    }
  }else{
    if( this->dst_ip.setIPv4Address(val) != OP_SUCCESS ){
        return OP_FAILURE;
    }
  }
  this->dst_ip_set=true;
  return OP_SUCCESS;
} /* End of setDestinationIP() */


/** Returns value of attribute dst_ip */
IPAddress ClientOps::getDestinationIP(){
  return this->dst_ip;
} /* End of getDestinationIP() */


/* Returns true if option has been set */
bool ClientOps::issetDestinationIP(){
  return this->dst_ip_set;
} /* End of issetDestinationIP() */


/** Sets SourceIP.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ClientOps::setSourceIP(IPAddress val){
  this->src_ip=val;
  this->src_ip_set=true;
  return OP_SUCCESS;
} /* End of setSourceIP() */


/** Sets SourceIP.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ClientOps::setSourceIP(const char *val){
  // TODO: This function should convert from a IP in decimal dot
    // notation into an IPAddress object.
  if( this->src_ip.setAddress(val) != OP_SUCCESS ){
    return OP_FAILURE;
  }
  this->src_ip_set=true;
  return OP_SUCCESS;
} /* End of setSourceIP() */


/** Returns value of attribute src_ip */
IPAddress ClientOps::getSourceIP(){
  return this->src_ip;
} /* End of getSourceIP() */


/* Returns true if option has been set */
bool ClientOps::issetSourceIP(){
  return this->src_ip_set;
} /* End of issetSourceIP() */



int ClientOps::resolve(bool val){
  this->do_resolution=val;
  return OP_SUCCESS;
}


bool ClientOps::resolve(){
  return this->do_resolution;
}


/** Sets AddressResolver.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ClientOps::setAddressResolver(IPAddress val){
  this->address_resolver=val;
  this->address_resolver_set=true;
  return OP_SUCCESS;
} /* End of setAddressResolver() */


/** Sets AddressResolver.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ClientOps::setAddressResolver(const char *val){
  if(this->address_resolver.setAddress(val)!=OP_SUCCESS)
    return OP_FAILURE;
  else
    this->address_resolver_set=true;
  return OP_SUCCESS;
} /* End of setAddressResolver() */


/** Returns value of attribute address_resolver */
IPAddress ClientOps::getAddressResolver(){
  return this->address_resolver;
} /* End of getAddressResolver() */


/* Returns true if option has been set */
bool ClientOps::issetAddressResolver(){
  return this->address_resolver_set;
} /* End of issetAddressResolver() */


int ClientOps::resolveIP(IPAddress *val){
  if(val==NULL){
    fatal(OUT_2, "resolveIP(): NULL parameter supplied.");
  }
  /** TODO: Finish this!!!! @todo This!! */
  return OP_SUCCESS;
} /* End of resolveIP() */


/** Sets KnockIP.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ClientOps::setKnockIP(IPAddress val){
  this->knock_ip=val;
  this->knock_ip_set=true;
  return OP_SUCCESS;
} /* End of setKnockIP() */


/** Sets Knock IP address.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ClientOps::setKnockIP(const char *val){
  if( this->knock_ip.setAddress(val) != OP_SUCCESS ){
    return OP_FAILURE;
  }
  this->knock_ip_set=true;
  return OP_SUCCESS;
} /* End of setKnockIP() */


/** Returns value of attribute knock_ip */
IPAddress ClientOps::getKnockIP(){
  return this->knock_ip;
} /* End of getKnockIP() */


/* Returns true if option has been set */
bool ClientOps::issetKnockIP(){
  return this->knock_ip_set;
} /* End of issetKnockIP() */


/** Sets ForwardIP.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ClientOps::setForwardIP(IPAddress val){
  this->forward_ip=val;
  this->forward_ip_set=true;
  return OP_SUCCESS;
} /* End of setForwardIP() */


/** Sets Knock IP address.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ClientOps::setForwardIP(const char *val){
  if( this->forward_ip.setAddress(val) != OP_SUCCESS ){
    return OP_FAILURE;
  }
  this->forward_ip_set=true;
  return OP_SUCCESS;
} /* End of setForwardIP() */


/** Returns value of attribute forward_ip */
IPAddress ClientOps::getForwardIP(){
  return this->forward_ip;
} /* End of getForwardIP() */


/* Returns true if option has been set */
bool ClientOps::issetForwardIP(){
  return this->forward_ip_set;
} /* End of issetForwardIP() */


/** Sets KnockPort.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ClientOps::setKnockPort(tcp_port_t val){
  output(OUT_9, "%s(%u)\n", __func__, val);
  if(this->knock_ports_set>=MAX_KNOCK_PORTS || val==0)
    fatal(OUT_2, "Too many knock ports supplied.");
  this->knock_ports[this->knock_ports_set]=val;
  this->knock_ports_set++;
  return OP_SUCCESS;
} /* End of setKnockPort() */


/** Returns value of attribute knock_port */
tcp_port_t ClientOps::getKnockPort(size_t index){
  output(OUT_9, "%s()\n", __func__);
  if(index>=MAX_KNOCK_PORTS)
    fatal(OUT_2, "Knock port index is out of bounds. Please report a bug.");
  return this->knock_ports[index];
} /* End of getKnockPort() */


/* Returns true if option has been set */
bool ClientOps::issetKnockPort(){
  output(OUT_9, "%s()\n", __func__);
  return (this->knock_ports_set<=0) ? false : true;
} /* End of issetKnockPort() */


/* Returns true if option has been set */
bool ClientOps::issetKnockPort(size_t index){
  output(OUT_9, "%s()\n", __func__);
  if( this->knock_ports_set >= (index+1) )
    return true;
  else
    return false;
} /* End of issetKnockPort() */


/** Sets Decoys.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ClientOps::addDecoy(IPAddress val){
  this->decoys.push_back(val);
  this->decoys_set=true;
  return OP_SUCCESS;
} /* End of setDecoys() */


/** Returns value of attribute decoys */
IPAddress *ClientOps::getDecoy(size_t index){
  if(index >= this->decoys.size() )
    fatal(OUT_2,"getSequencePort(): Array index out of range\n");
  return &(this->decoys[index]);
} /* End of getDecoys() */


/* Returns true if option has been set */
bool ClientOps::issetDecoys(){
  return this->decoys_set;
} /* End of issetDecoys() */


/* Returns the number of decoys stored */
size_t ClientOps::getNumberOfDecoys(){ 
  return this->decoys.size();
} /* End of getNumberOfDecoys() */


/** Sets Action.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ClientOps::setAction(int val){
  output(OUT_9, "%s()\n", __func__);
  if(val!=ACTION_OPEN && val!=ACTION_CLOSE && val!=ACTION_FORWARD)
    fatal(OUT_2, "setAction(): Invalid action supplied");
  if(this->knock_actions_set>=MAX_KNOCK_PORTS)
    fatal(OUT_2, "Too many knock actions supplied.");
  this->knock_actions[this->knock_actions_set]=val;
  this->knock_actions_set++;
  return OP_SUCCESS;
} /* End of setAction() */


/** Returns value of attribute action */
int ClientOps::getAction(size_t index){
  output(OUT_9, "%s()\n", __func__);
  return this->knock_actions[index];
} /* End of getAction() */


/* Returns true if option has been set */
bool ClientOps::issetAction(size_t index){
  output(OUT_9, "%s()\n", __func__);
  if( this->knock_actions_set >= (index+1) )
    return true;
  else
    return false;
} /* End of issetAction() */


/** Sets KnockPortProto.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ClientOps::setKnockPortProto(u8 val){
  output(OUT_9, "%s(%u)\n", __func__, val);
  if(val!=KNOCK_PORT_PROTO_ANY && val!=KNOCK_PORT_PROTO_TCP && val!=KNOCK_PORT_PROTO_UDP && val!=KNOCK_PORT_PROTO_SCTP)
    fatal(OUT_2, "setKnockPortProto(): Invalid action supplied");
  if(this->knock_port_protos_set>=MAX_KNOCK_PORTS)
    fatal(OUT_2, "Too many knock port protocols supplied.");
  this->knock_port_protos[this->knock_port_protos_set]=val;
  this->knock_port_protos_set++;
  return OP_SUCCESS;
} /* End of setKnockPortProto() */


/** Returns value of attribute action */
u8 ClientOps::getKnockPortProto(size_t index){
  output(OUT_9, "%s()\n", __func__);
  return this->knock_port_protos[index];
} /* End of getKnockPortProto() */


/* Returns true if option has been set */
bool ClientOps::issetKnockPortProto(size_t index){
  output(OUT_9, "%s()\n", __func__);
  if( this->knock_port_protos_set >= (index+1) )
    return true;
  else
    return false;
} /* End of issetKnockPortProto() */



/** Sets NoisePackets.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ClientOps::setNoisePackets(u16 val){
  this->noise=val;
  this->noise_set=true;
  return OP_SUCCESS;
} /* End of setNoisePackets() */


/** Returns value of attribute noise */
u16 ClientOps::getNoisePackets(){
  return this->noise;
} /* End of getNoisePackets() */


/* Returns true if option has been set */
bool ClientOps::issetNoisePackets(){
  return this->noise_set;
} /* End of issetNoisePackets() */


/** Returns value of attribute noise */
int ClientOps::generateNoisePorts(){
  tcp_port_t *exclude_list=NULL;
  size_t exclude_number;
  if(this->issetNoisePackets()==false)
    return OP_FAILURE;

  /* Free previously allocated list of ports */
  if(this->noise_ports!=NULL)
      free(noise_ports);

  exclude_list=this->getSequencePortArray(&exclude_number);
  if((this->noise_ports=generate_random_portlist(this->getNoisePackets(), exclude_list, exclude_number))==NULL)
    fatal(OUT_2, "Couldn't allocate space for %d noise packets.", this->getNoisePackets());
  else
    this->setNoisePackets( this->getNoisePackets() + exclude_number );
    
  return OP_SUCCESS;
} /* End of generateNoisePorts() */


tcp_port_t *ClientOps::getNoisePortList(){
  return this->noise_ports;
} /* End of getNoisePortList() */


/** Sets Delay.
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.           */
int ClientOps::setDelay(u32 val){
  this->delay=val;
  this->delay_set=true;

  return OP_SUCCESS;
} /* End of setDelay() */


/** Returns value of attribute delay */
u32 ClientOps::getDelay(){
  return this->delay;
} /* End of getDelay() */


/* Returns true if option has been set */
bool ClientOps::issetDelay(){
  return this->delay_set;
} /* End of issetDelay() */


int ClientOps::validateConfiguration(){
  const char *iface=NULL;
  struct sockaddr_storage iface_ss;
  IPAddress knock_addr;
  IPAddress source_addr;

 /*-------------------------*
  *  MANDATORY PARAMETERS   *
  *-------------------------*/
  if(!this->issetPassphrase()){
    fatal(OUT_2,"No passphrase supplied. Please supply one.");
  }else{
      this->computeCipherKey();
      this->computeMacKey();
  }

  /* -> If no IP version is set, go with IP version 4 */
  if( !this->issetIPVersion() )
    this->setIPVersion(AF_INET);

  if(!this->issetHostname())
    fatal(OUT_2, "No target host was specified. Please supply one.");



//   /* If no encryption key was supplied, ask interactively for a passphrase */
//  char buffer[MAX_PASSPHRASE_LEN +1];
//  if( !this->issetCipherKey() ){
//    memset(buffer, 0, MAX_PASSPHRASE_LEN +1);
//    printf("Please enter your passphrase key: ");
//    gets_noecho_stars(buffer, MAX_PASSPHRASE_LEN+1);
//    printf("\n\n");
//
//    if( strlen(buffer) < MIN_PASSPHRASE_LEN )
//        fatal(OUT_2, "Supplied passphrase is too short. Passphrases need to contain at least %d characters", MIN_PASSPHRASE_LEN );
//    else{
//        if ( this->setCipherKey(buffer)!=OP_SUCCESS )
//           fatal(OUT_2, "Failed to derive encryption key from passphrase");
//    }
//  }


  /* Time for contraints! */


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
    }else if(this->getNumberOfSequencePorts() < ports_needed){
        fatal(OUT_2, "Not enough target ports. %lu port numbers expected.", (unsigned long)ports_needed);
    }else if (this->getNumberOfSequencePorts() > ports_needed){
        fatal(OUT_2, "Too many target ports. %lu port numbers expected.", (unsigned long)ports_needed);
    }
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
      this->setVerbosityLevel(DEFAULT_VERBOSITY_CLIENT);
  }

  /* -> If logging level was not specified, set default */
  if ( !this->issetLoggingLevel() ){
     this->setLoggingLevel(DEFAULT_LOGGING_CLIENT);
  }

 /*--------------------------------*
  *   PRIVILEGES AND PERMISSIONS   *
  *--------------------------------*/

  /* Determine if user is root */
  this->setIsRoot( (geteuid()==0) ? true : false );

  /* For PK, user must be root */
  if (this->getMode()==MODE_PORTKNOCKING && !this->isRoot()){
    fatal(OUT_2, "ERROR: You need to be root to run Port Knocking mode.\n");
  }


 /*------------------*
  *   CRYPTOGRAPHY   *
  *------------------*/

  /* If no encryption algorithm was specified, set default */
  if (!this->issetCipher()){
    if( this->getMode()==MODE_PORTKNOCKING )
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


 /*--------------------------*
  *   KNOCKING INFORMATION   *
  *--------------------------*/

  /* Authorized port number */
  if(!this->issetKnockPort()){
    warning(OUT_2, "WARNING: No knocking port was specified. Using default port %d\n", DEFAULT_AUTH_PORT);
    this->setKnockPort(DEFAULT_AUTH_PORT);
  }

  if( this->resolve() ){
      IPAddress addr;
      indent(OUT_6, 1, "Trying to resolve IP Address\n");
      if( AddressResolver::resolve(&addr, this->getIPVersion())!=OP_SUCCESS ){
        fatal(OUT_2, "Failed to perform IP address resolution using external service.");
      }else{
          indent(OUT_6, 1, "Resolved IP Address: %s\n", addr.toString());
          this->setKnockIP(addr);
      }
  }

  if( this->getMode()==MODE_PORTKNOCKING ){

    /* Case 1: No knocking address or source address supplied */
    if( !this->issetSourceIP() && !this->issetKnockIP() ){
        if( (iface=this->select_interface())==NULL )
            fatal(OUT_2, "Unable to determine source and knock IP addresses (no interface found). Please use option -S <addr> or -K <addr>");
        if( get_iface_addr(iface, &iface_ss, this->getIPVersion() )!=OP_SUCCESS )
            fatal(OUT_2, "Unable to determine source and knock IP addresses (no address for interface %s). Please use option -S <addr> or -K <addr>", iface);
        knock_addr.setAddress(iface_ss);
        source_addr.setAddress(iface_ss);
        this->setKnockIP(knock_addr);
        this->setSourceIP(source_addr);   
    /* Case 2: Knocking address supplied but no source address */
    }else if( this->issetKnockIP() && !this->issetSourceIP() ){
        /* Try to obtain a proper source address */
        bool success=false;
        if( (iface=this->select_interface())!=NULL ){
            if( get_iface_addr(iface, &iface_ss, this->getIPVersion() )==OP_SUCCESS )
                success=true;
        }
        /* If we managed to obtain a nice source address, set it */
        if(success){
            source_addr.setAddress(iface_ss);
            this->setSourceIP(source_addr);
        /* Otherwise, use the knock IP as the source address */
        }else{
            this->setSourceIP( this->knock_ip );
        }
    /* Case 3: Source address supplied but no knocking address */
    }else if( this->issetSourceIP() && !this->issetKnockIP() ){
        /* Use the source IP as the knock IP */
        this->setKnockIP(this->src_ip);
    /* Case 4: Both addresses supplied. Good! */
    }else{
          // All set up. Do nothing.
    }
  }else{ /* MODE_SPA */
    /* Case 1: No knocking address supplied but source IP was */
    if( this->issetSourceIP() && !this->issetKnockIP() ){
        /* Use source address as knock IP */
        this->setKnockIP(this->src_ip);
    /* Case 2: No knocking address and no source supplied */
    }else if( !this->issetKnockIP() ){
        if( (iface=this->select_interface())==NULL )
            fatal(OUT_2, "Unable to determine knock IP addresses (no interface found). Please use option -K <addr>");
        if( get_iface_addr(iface, &iface_ss, this->getIPVersion() )!=OP_SUCCESS )
            fatal(OUT_2, "Unable to determine knock IP addresses (no address for interface %s). Please use option -K <addr>", iface);
        knock_addr.setAddress(iface_ss);
        this->setKnockIP(knock_addr);
    }
  }

  /* Check user is using the forward-ip parameter correctly */
  if( this->issetForwardIP() ){
      if( this->getMode()==MODE_PORTKNOCKING )
          fatal(OUT_2, "Forwarding can only be used in SPA mode.");
      if(!this->issetKnockPort(KNOCK_PORT_1) || !this->issetKnockPort(KNOCK_PORT_2))
          fatal(OUT_2, "Forwarding requires two ports to be specified.");
      /* If user supplied a forward IP but no action, just set the forward action automatically */
      if(!this->issetAction(KNOCK_PORT_1) && !this->issetAction(KNOCK_PORT_2) ){
           this->setAction(ACTION_FORWARD); /* Set action p1 */
           this->setAction(ACTION_FORWARD); /* Set action p2 */
      }
  }

  /* if no action was specified, default to ACTION_OPEN */
  if (!this->issetAction(KNOCK_PORT_1)){
    this->setAction(DEFAULT_ACTION);
  }
  if (this->issetKnockPort(KNOCK_PORT_2) && !this->issetAction(KNOCK_PORT_2) && this->getMode()==MODE_SPA){
    this->setAction( this->getAction(KNOCK_PORT_1) );
  }

  /* Make sure no forwarding or use of port #2 in Port Knocking */
  if( this->getMode()==MODE_PORTKNOCKING ){
      if(this->getAction(KNOCK_PORT_1)==ACTION_FORWARD)
          fatal(OUT_2, "Port forwarding can only be used in SPA mode.");
      if(this->issetKnockPort(KNOCK_PORT_2))
          fatal(OUT_2, "Port #2 can only be used in SPA mode.");
  }else{
      /* Make sure that if one port has a forwarding action, the other does as well */
      if(this->issetAction(KNOCK_PORT_1) && this->issetAction(KNOCK_PORT_2)){
          if(this->getAction(KNOCK_PORT_1)==ACTION_FORWARD || this->getAction(KNOCK_PORT_2)==ACTION_FORWARD){
              if(this->getAction(KNOCK_PORT_1)!=this->getAction(KNOCK_PORT_2))
                  fatal(OUT_2, "When using forwarding, both knock ports must be configured with --action forward");
          }
      }
      /* Make sure that if forwarding was enabled, the user supplied a forward IP address */
      if(this->getAction(KNOCK_PORT_1)==ACTION_FORWARD && this->issetForwardIP()==false){
        fatal(OUT_2, "When using forwarding, you need to supply a forward IP address");
      }
  }

  /* If user requested noise, generate some random port numbers */
  if(this->issetNoisePackets() )
    this->generateNoisePorts();

  return OP_SUCCESS;
} /* End of validateConfiguration() */


const char *ClientOps::select_interface(){
  const char *iface=NULL;
  if ( this->issetInterface() ){
    iface=this->getInterface();
  }else{
    iface=select_iface(this->getIPVersion());
  }
  return iface;
} /* End of select_interface() */

