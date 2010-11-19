
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
#include "ArgParser.h"
#include "tools.h"
#include "output.h"
#include <string.h>
#include "IPAddress.h"
#include <unistd.h>
#include <getopt.h>

/* getopt() globals */
extern char *optarg;
extern int optind, opterr, optopt;

ArgParser::ArgParser() {
    return;
} /* End of ArgParser constructor */


ArgParser::~ArgParser() {
    return;
} /* End of ArgParser destructor */


/** Parses a list of comma separated port numbers and stores them in the
  * array op->pkseq. It checks if portlist matches the following pattern:
  * "numer{comma}number{comma}...{number} It detects whether the string starts
  * with a comma, ends with a comma or has two consecutive commas. The function
  * returns PARSING_SUCCESS on success and <0 in case of error.               */
int ArgParser::parse_portlist(const char *portlist, GeneralOps *opt ){

 int listlen = 0;     /* Lenght of the portlist string     */
 int i=0, commas=0;   /* Loop counter and comma counter    */
 int lastwascomma=0;  /* Flag to detect consecutive commas */
 long port=0;
 char auxbuff[STD_BUFF_LEN];
 memset(auxbuff, 0, STD_BUFF_LEN);

 if (portlist == NULL || opt==NULL) /* Invalid list of ports or GeneralOps struct */
    fatal(OUT_2, "%s(): NULL parameter supplied", __func__);
 else{
    if ( (listlen=strlen(portlist))==0)   /* It must have at least one port number */
        return OP_FAILURE;
 }

 for( i=0; i<listlen; i++ ){ /* Validate string */
    /* Check it only has allowed characters */
    if ( portlist[i] != ',' && !isdigit( portlist[i] ) ){
        return OP_FAILURE;
    }else if (portlist[i] == ','){  /* If it's a comma */
        commas++; /* Number of commas will tell the number of specified ports */
        if (i==0 || i==listlen -1){
            return OP_FAILURE; /* No commas at the beginning or end */
        }else if (lastwascomma == 1){ /* No consecutive commas allowed */
            return OP_FAILURE;
        }else{
            lastwascomma = 1;
        }
    }else{
        lastwascomma = 0;
    }
  }

 /* If we get here it means that we have a valid string containing port */
 /* numbers separated by commas. Let's extract each port and store it   */
 strncpy(auxbuff, portlist, STD_BUFF_LEN); /* Backup input */

 /* The first call to strtok must include the pointer to the string.    */
 /* Then we should call it with a NULL pointer                          */
 port = strtol( strtok(auxbuff, ","), NULL, 10);
 if ( !istcpport(port) ){ /* Check port range 1-65535 */
    return OP_FAILURE;
 }else{
     opt->setSequencePort((tcp_port_t)port);
 }

 for(i=0; i<commas && i<MAX_KNOCKS-1; i++){
    port = strtol( strtok(NULL, ","), NULL, 10 );
    /* No need to check for strtol or strtok errors because if they return */
    /* 0, negative, LONG_MIN or LONG_MAX, the istcpport() function will    */
    /* catch it and we'll return TPORTS_INVALID */
    if ( !istcpport(port) ) /* Check port range 1-65535 */
        return OP_FAILURE;
    else
        opt->setSequencePort((tcp_port_t)port);
 }
 return OP_SUCCESS;
} /* End of  parse_portlist(); */


/** Processes argument -P, --passphrase. */
int ArgParser::process_arg_passphrase(GeneralOps *opt, const char * arg){
  if(opt==NULL || arg==NULL)
    fatal(OUT_2, "%s(): NULL parameter supplied", __func__);
  if( opt->setPassphrase(arg) != OP_SUCCESS )
    fatal(OUT_2, "Invalid passphrase supplied.");
  return OP_SUCCESS;
} /* End of process_arg_passphrase() */


/** Processes argument -t, --target-ports. The function takes a string
  * containing a list of TCP/UDP port numbers and converts them into 16-bit
  * integers. */
int ArgParser::process_arg_port_sequence(GeneralOps *opt, const char * arg){
  if(opt==NULL || arg==NULL)
    fatal(OUT_2, "%s(): NULL parameter supplied", __func__);
  if ( parse_portlist(arg, opt) != OP_SUCCESS )
    fatal(OUT_2, "Invalid port sequence supplied (%s).", arg);
  return OP_SUCCESS;
} /* End of process_arg_target_ports() */


/** Processes argument -i, --interface. The function takes a string
  * containing a network interface name and stores it in member opt->iface of
  * the supplied GeneralOps structure.                                     */
int ArgParser::process_arg_interface(GeneralOps *opt, const char * arg){
  if(opt==NULL || arg==NULL)
      fatal(OUT_2, "%s(): NULL parameter supplied", __func__);
  if( strlen(arg)<= 0)
      fatal(OUT_2, "Invalid network interface name supplied.");
  else
     opt->setInterface(arg); /* We'll check if the interface exist later */
  return OP_SUCCESS;
} /* End of process_arg_interface() */


/** Processes argument -v, --verbosity. The function takes a string
  * containing a verbosity level, coverts it into a integer and stores it in
  * global variable "vb".                                                     */
int ArgParser::process_arg_verbosity(GeneralOps *opt, const char * arg){
  int vbs=0;
  if(opt==NULL || arg==NULL)
      fatal(OUT_2, "%s(): NULL parameter supplied", __func__);

  vbs = strtol( arg, NULL, 10);

  if ( (vbs==0) && (arg[0] != '0') )
    fatal(OUT_2, "Bogus verbosity level supplied (%s).", arg);
  if ( vbs < MIN_VERBOSITY_LEVEL || vbs > MAX_VERBOSITY_LEVEL)
    fatal(OUT_2, "Supplied verbosity level is out of range (%s).", arg);
  else
    opt->setVerbosityLevel(vbs);
  return OP_SUCCESS;
} /* End of process_arg_verbosity() */


/** Processes argument -T, --technique. The function takes a string containing
  * the technique name and sets the appropriate value in member opt->technique
  * of the supplied GeneralOps structure                                   */
int ArgParser::process_arg_technique(GeneralOps *opt, const char * arg){
  if(opt==NULL || arg==NULL)
      fatal(OUT_2, "%s(): NULL parameter supplied", __func__);
  if( !strcasecmp("portknocking", arg ) || !strcasecmp("PK", arg ) ){
    opt->setMode(MODE_PORTKNOCKING);
  }else if(!strcasecmp("SPA", arg ) || !strcasecmp("single-packet-authorization", arg ) ){
    opt->setMode(MODE_SPA);
  }else{
    fatal(OUT_2, "Invalid technique supplied (%s).", arg);
  }
  return OP_SUCCESS;
} /* End of process_arg_technique() */


/** Processes argument --quiet. This function sets verbosity level and log
  * level to zero.                                                            */
int ArgParser::process_arg_quiet(GeneralOps *opt){
  if(opt==NULL)
    return OP_FAILURE;
  opt->setVerbosityLevel(MIN_VERBOSITY_LEVEL);
  opt->setLoggingLevel(MIN_LOGGING_LEVEL);
  return OP_SUCCESS;
}


/** Processes argument --debug. This function sets verbosity level and log
  * level to their maximum values.                                            */
int ArgParser::process_arg_debug(GeneralOps *opt){
  if(opt==NULL)
    return OP_FAILURE;
  opt->setVerbosityLevel(MAX_VERBOSITY_LEVEL);
  opt->setLoggingLevel(MAX_LOGGING_LEVEL);
  return OP_SUCCESS;
}


/** Processes argument -c, --cipher. This function takes a string containing
  * a cipher name and sets the appropriate value in members opt->cipher and
  * opt->cipher_mode of the supplied GeneralOps structure.                 */
int ArgParser::process_arg_cipher(GeneralOps *opt, const char * arg){
  int cipher=-1;
  int cipher_mode=-1;

  if(opt==NULL || arg==NULL)
      fatal(OUT_2, "%s(): NULL parameter supplied", __func__);

  /* Blowfish Cipher */
  if( !strcasecmp("blowfish", arg ) || !strcasecmp("bfish", arg ) ||  !strcasecmp("BF", arg ) ){
        cipher = ALG_BLOWFISH;
        cipher_mode = DEFAULT_BLOCK_MODE;
  }else if( !strcasecmp("blowfish-ecb", arg ) || !strcasecmp("bfish-ecb", arg ) ||  !strcasecmp("BF-ecb", arg ) ){
        cipher = ALG_BLOWFISH;
        cipher_mode = BLOCK_MODE_ECB;
  }else if( !strcasecmp("blowfish-cbc", arg ) || !strcasecmp("bfish-cbc", arg ) ||  !strcasecmp("BF-cbc", arg ) ){
        cipher = ALG_BLOWFISH;
        cipher_mode = BLOCK_MODE_CBC;
  }else if( !strcasecmp("blowfish-cfb", arg ) || !strcasecmp("bfish-cfb", arg ) ||  !strcasecmp("BF-cfb", arg ) ){
        cipher = ALG_BLOWFISH;
        cipher_mode = BLOCK_MODE_CFB;
  }else if( !strcasecmp("blowfish-ofb", arg ) || !strcasecmp("bfish-ofb", arg ) ||  !strcasecmp("BF-ofb", arg ) ){
        cipher = ALG_BLOWFISH;
        cipher_mode = BLOCK_MODE_OFB;
  }
  /* Twofish cipher */
  else if ( !strcasecmp("twofish", arg) || !strcasecmp("tfish", arg ) || !strcasecmp("TF", arg ) ){
        cipher = ALG_TWOFISH;
        cipher_mode = DEFAULT_BLOCK_MODE;
  }else if( !strcasecmp("twofish-ecb", arg ) || !strcasecmp("tfish-ecb", arg ) ||  !strcasecmp("TF-ecb", arg ) ){
        cipher = ALG_TWOFISH;
        cipher_mode = BLOCK_MODE_ECB;
  }else if( !strcasecmp("twofish-cbc", arg ) || !strcasecmp("tfish-cbc", arg ) ||  !strcasecmp("TF-cbc", arg ) ){
        cipher = ALG_TWOFISH;
        cipher_mode = BLOCK_MODE_CBC;
  }else if( !strcasecmp("twofish-cfb", arg ) || !strcasecmp("tfish-cfb", arg ) ||  !strcasecmp("TF-cfb", arg ) ){
        cipher = ALG_TWOFISH;
        cipher_mode = BLOCK_MODE_CFB;
  }else if( !strcasecmp("twofish-ofb", arg ) || !strcasecmp("tfish-ofb", arg ) ||  !strcasecmp("TF-ofb", arg ) ){
        cipher = ALG_TWOFISH;
        cipher_mode = BLOCK_MODE_OFB;
  }
  /* Serpent Cipher */
  else if ( !strcasecmp("serpent", arg) || !strcasecmp("serp", arg ) || !strcasecmp("SP", arg ) ){
        cipher = ALG_SERPENT;
        cipher_mode = DEFAULT_BLOCK_MODE;
  }else if( !strcasecmp("serpent-ecb", arg ) || !strcasecmp("serp-ecb", arg ) ||  !strcasecmp("SP-ecb", arg ) ){
        cipher = ALG_SERPENT;
        cipher_mode = BLOCK_MODE_ECB;
  }else if( !strcasecmp("serpent-cbc", arg ) || !strcasecmp("serp-cbc", arg ) ||  !strcasecmp("SP-cbc", arg ) ){
        cipher = ALG_SERPENT;
        cipher_mode = BLOCK_MODE_CBC;
  }else if( !strcasecmp("serpent-cfb", arg ) || !strcasecmp("serp-cfb", arg ) ||  !strcasecmp("SP-cfb", arg ) ){
        cipher = ALG_SERPENT;
        cipher_mode = BLOCK_MODE_CFB;
  }else if( !strcasecmp("serpent-ofb", arg ) || !strcasecmp("serp-ofb", arg ) ||  !strcasecmp("SP-ofb", arg ) ){
        cipher = ALG_SERPENT;
        cipher_mode = BLOCK_MODE_OFB;
  }
  /* Rijndael/AES cipher */
  else if ( !strcasecmp("rijndael", arg) || !strcasecmp("rij", arg ) || !strcasecmp("RJ", arg )|| !strcasecmp("AES", arg ) ){
        cipher = ALG_RIJNDAEL;
        cipher_mode = DEFAULT_BLOCK_MODE;
  }else if ( !strcasecmp("rijndael-ecb", arg) || !strcasecmp("rij-ecb", arg ) || !strcasecmp("RJ-ecb", arg )|| !strcasecmp("AES-ecb", arg ) ){
        cipher = ALG_RIJNDAEL;
        cipher_mode = BLOCK_MODE_ECB;
  }else if ( !strcasecmp("rijndael-cbc", arg) || !strcasecmp("rij-cbc", arg ) || !strcasecmp("RJ-cbc", arg )|| !strcasecmp("AES-cbc", arg ) ){
        cipher = ALG_RIJNDAEL;
        cipher_mode = BLOCK_MODE_CBC;
  }else if ( !strcasecmp("rijndael-cfb", arg) || !strcasecmp("rij-cfb", arg ) || !strcasecmp("RJ-cfb", arg )|| !strcasecmp("AES-cfb", arg ) ){
        cipher = ALG_RIJNDAEL;
        cipher_mode = BLOCK_MODE_CFB;
  }else if ( !strcasecmp("rijndael-ofb", arg) || !strcasecmp("rij-ofb", arg ) || !strcasecmp("RJ-ofb", arg )|| !strcasecmp("AES-ofb", arg ) ){
        cipher = ALG_RIJNDAEL;
        cipher_mode = BLOCK_MODE_OFB;
  }else{
        fatal(OUT_2, "Invalid encryption algorithm supplied (%s).", arg);
  }
  /* If we get here, then we have a valid cipher alg and block mode to set */
  opt->setCipher(cipher);
  opt->setCipherMode(cipher_mode);
  return OP_SUCCESS;
} /* End of process_arg_cipher() */



/** Processes argument -c, --field. This function takes a string containing
  * a field name and sets the appropriate value in members opt->field of the
  * supplied GeneralOps structure.                 */
int ArgParser::process_arg_field(GeneralOps *opt, const char * arg){
  int field=-1;
  if(opt==NULL || arg==NULL)
      fatal(OUT_2, "%s(): NULL parameter supplied", __func__);

  if( !strcasecmp("tos", arg ) || !strcasecmp("ip-tos", arg ) ){
        field = COVERT_IP_TOS;
  }else if( !strcasecmp("id", arg ) || !strcasecmp("ip-id", arg )){
        field = COVERT_IP_ID;
  }else if( !strcasecmp("ack", arg ) || !strcasecmp("tcp-ack", arg )){
        field = COVERT_TCP_ACK;
  }else if( !strcasecmp("seq", arg ) || !strcasecmp("tcp-seq", arg )){
        field = COVERT_TCP_SEQ;
  }else if( !strcasecmp("sport", arg ) || !strcasecmp("source-port", arg ) ){
        field = COVERT_TCP_SPORT;
  //}else if ( !strcasecmp("dport", arg) || !strcasecmp("destination-port", arg ) ){
  //      field = COVERT_TCP_DPORT;
  }else if( !strcasecmp("win", arg ) || !strcasecmp("tcp-win", arg ) ||  !strcasecmp("window", arg ) ){
        field = COVERT_TCP_WINDOW;
  }else if( !strcasecmp("urp", arg ) || !strcasecmp("tcp-urp", arg )){
        field = COVERT_TCP_URP;
  //}else if( !strcasecmp("csum", arg ) || !strcasecmp("checksum", arg ) ){
  //      field = COVERT_TCP_CSUM;
  }else{
        fatal(OUT_2, "Invalid header field supplied (%s).", arg);
  }
  /* If we get here, then we have a valid field alg and block mode to set */
  opt->setField(field);
  return OP_SUCCESS;
} /* End of process_arg_field() */


/** Processes argument --auth. */
int ArgParser::process_arg_auth(GeneralOps *opt, const char * arg){
  int auth=-1;
  if(opt==NULL || arg==NULL)
      fatal(OUT_2, "%s(): NULL parameter supplied", __func__);

  if( !strcasecmp("light", arg ) || !strcasecmp("l", arg ) ){
        auth = AUTH_TYPE_LIGHT;
  }else if( !strcasecmp("strong", arg ) || !strcasecmp("s", arg )){
        auth = AUTH_TYPE_STRONG;
  }else{
        fatal(OUT_2, "Invalid authentication type supplied (%s).", arg);
  }
  opt->setAuthType(auth);
  return OP_SUCCESS;
} /* End of process_arg_field() */


/** Processes argument ssh-cookie. This function takes a string containing
  * "4", "ipv4", "6" or "ipv6" and sets the appropriate version of the IP
  * protocol in the supplied ClientOps structure                       */
int ArgParser::process_arg_ssh_cookie(GeneralOps *opt, const char * arg){
  if(opt==NULL || arg==NULL)
      fatal(OUT_2, "%s(): NULL parameter supplied", __func__);
  if ( !strcasecmp(arg, "no" ) || !strcasecmp(arg, "0") || !strcasecmp(arg, "disable") )
    opt->disableSSHCookie();
  else  if ( !strcasecmp(arg, "yes" ) || !strcasecmp(arg, "1") || !strcasecmp(arg, "enable") )
    opt->enableSSHCookie();
  else
    fatal(OUT_2, "Invalid ssh-cookie parameter supplied (%s).", arg);
  return OP_SUCCESS;
} /* End of process_arg_ssh_cookie() */
