
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
#include "ArgParserServer.h"
#include "client.h"
#include "tools.h"
#include "GeneralOps.h"
#include "ServerOps.h"
#include "output.h"
#include "Crypto.h"
#include "blowfish.h"
#include "twofish.h"
#include "rijndael.h"
#include "serpent.h"
#include "sha256.h"
#include "md5.h"
#include "Random.h"
#include "PKServer.h"
#include "SPAServer.h"
#include "Server.h"
#include "post_auth.h"

ServerOps o;
PKServer pk_srv;
SPAServer spa_srv;

/** Servers's main method. Calls command-line argument parser, registers
  * cleanup functions, tests cryptographic tools, and calls the appropriate
  * handler for the authentication technique requested by the user.           */
int main(int argc, char *argv[]){
  int i=0;

  o.setVerbosityLevel(DEFAULT_VERBOSITY_SERVER);
  o.setLoggingLevel(DEFAULT_LOGGING_SERVER);

  /* Called early and used for testing purposes only */
  Server::test_stuff(argc, argv);

 /* Register cleanup function to be called on exit                            */
 if (atexit(server_cleanup)!=0)
    warning( OUT_6, "|_ Failed to register cleanup function with atexit()");

 /* Register cleanup function to be called on signal delivery                 */
 if ( signal(SIGINT, server_cleanup_signal) == SIG_ERR )
    warning(OUT_6, "|_ Failed to register cleanup function with signal()");

 /* Set options for syslog daemon */
 openlog("aldabad", LOG_PID, LOG_USER);

 /* Parse command line arguments */
 if ( (i=ArgParserServer::parse_arguments(argc, argv, &o)) != OP_SUCCESS )
    return -i;

 /* Validate resulting configuration */
 if ( (i=o.validateConfiguration()) != OP_SUCCESS )
    return -i;

 /* Test crypto functions against known correct values                        */
 if ( Crypto::test() != OP_SUCCESS ){
    fatal(OUT_2, "Some cryptographic function is corrupted. Please report a bug.");
 }

 /* Init our PRNG */
 if(o.rand.init()!=OP_SUCCESS){
    warning(OUT_2, "Failed to init PRNG. Generated random data may not be cryptographically secure.\n");
 }

  
 /* Turn current process into a system daemon */
 if( o.getDaemonize() )
    daemonize();

  /* Run the appropriate instance of the server */
  switch (o.getMode() ){
    case MODE_PORTKNOCKING:
        pk_srv.init();
        pk_srv.run();
    break;
    case MODE_SPA:
        spa_srv.init();
        spa_srv.run();
    break;
    default:
        fatal(OUT_2, "Unknown technique (%d). Please report a bug", o.getMode());
        return EXIT_FAILURE;
    break;
  }  
  return EXIT_SUCCESS;
} /* End of main() */


Server::Server(){
  this->reset();
}

Server::~Server(){

}

void Server::reset(){

}


int Server::init(){
 script_init();
 print_banner();
 print_conf();
 return OP_SUCCESS;
} /* End of run() */


void Server::print_banner(){
  char time_str[128];
  time_t curr_time=time(NULL);
  struct tm *curr_tm=localtime(&curr_time);
  output(OUT_4, "\n =======================================================================\n");
  output(OUT_4, "           _     _       _              _____                          \n");
  output(OUT_4, "     /\\   | |   | |     | |            / ____|                         \n");
  output(OUT_4, "    /  \\  | | __| | __ _| |__   __ _  | (___   ___ _ ____   _____ _ __ \n");
  output(OUT_4, "   / /\\ \\ | |/ _` |/ _` |  _ \\ / _` |  \\___ \\ / _ \\ `__\\ \\ / / _ \\ `__|\n");
  output(OUT_4, "  / ____ \\| | (_| | (_| | |_) | (_| |  ____) |  __/ |   \\ V /  __/ |   \n");
  output(OUT_4, " /_/    \\_\\_|\\____|\\__._|____/ \\__._| |_____/ \\___|_|    \\_/ \\___|_|   \n");
  output(OUT_4, "\n =======================================================================\n");
  output(OUT_4, "[+]\n");
  if ( strftime(time_str, sizeof(time_str)-1, "%Y-%m-%d %H:%M %Z", curr_tm) >0 )
    indent(OUT_4, 1, "Aldaba Server %s started at %s.\n", CURRENT_VERSION, time_str);
  return;
} /* End of print_banner() */


void Server::print_conf(){
  indent(OUT_6, 1, "Server Configuration:\n" );
  if(o.getMode()==MODE_SPA){
    indent(OUT_6, 2, "Mode=           %s-%s\n", o.getMode_str(), o.getIPVersion_str());
    indent(OUT_6, 2, "Accepted Ports= %s\n", o.getSequencePorts_str());
  }else{
    indent(OUT_6, 2, "Mode=           %s-%s-%s\n", o.getMode_str(), o.getIPVersion_str(), o.getAuthType_str() );
    indent(OUT_6, 2, "Covert Field=   %s\n", o.getField_str() );
    indent(OUT_6, 2, "Port Sequence=  %s\n", o.getSequencePorts_str());
  }
  indent(OUT_6, 2, "Cipher=         %s-%s\n", o.getCipher_str(), o.getCipherMode_str() );

  /* These two are only displayed when verbosity is very high */
  indent(OUT_8, 2, "Cipher Key=     %s\n", o.getCipherKey_str() );
  indent(OUT_8, 2, "HMAC Key=       %s\n", o.getMacKey_str() );

  indent(OUT_6, 2, "Cap Interface=  %s\n", o.getInterface() );
  return;
} /* End of print_conf() */


void Server::test_stuff(int argc __attribute__((unused)), char *argv[] __attribute__((unused))) {

} /* End of test_stuff() */


AuthRecord *Server::auth_record_new(u32 time, u8 *nonce, size_t nonce_len){
  output(OUT_9, "%s()\n", __func__);
  AuthRecord *record = new AuthRecord(time, nonce, nonce_len);
  return record;
} /* End of auth_record_new() */


int Server::auth_record_insert(AuthRecord *x){
  static u32 completed_auths=0;
  output(OUT_9, "%s(%u, %02x)\n", __func__, x->getTimestamp(), *x->getNonce());

  /* Every once in a while purge the list of stored authentication (this only
   * deletes the ones that have already expired */
  if(((++completed_auths)%AUTH_RECORD_PURGE_INTERVAL)==0)
    auth_record_purge();

  /* Insert the new authentication record */
  this->auth_record.push_back(x);

  return OP_SUCCESS;
} /* End of auth_record_insert() */


int Server::auth_record_purge(){
  output(OUT_9, "%s()\n", __func__);
  int removed=0;

  size_t j=0;
  for (size_t i=0; i< this->auth_record.size(); ++i) {
    if (!this->auth_record[i]->expired((u32)time(NULL)) )
        this->auth_record[j++] = this->auth_record[i];
    else
        removed++;
  }
  /* trim vector to its new size */
  this->auth_record.resize(j);

  printf("Removed %d\n",removed);
  return removed;


  for (vector<AuthRecord *>::iterator it = this->auth_record.begin(); it!=this->auth_record.end(); ++it) {
    if( (*it)->expired((u32)time(NULL))){
        this->auth_record.erase(it);
        delete *it;
        removed++;
    }
  }
  return removed;
} /* End of auth_record_remove() */



int Server::auth_record_insert_new(u32 time, u8 *nonce, size_t nonce_len){
  output(OUT_9, "%s()\n", __func__);
  AuthRecord *x=auth_record_new(time, nonce, nonce_len);
  if(x==NULL)
      return OP_FAILURE;
  else
      return auth_record_insert(x);
} /* End of auth_record_insert() */


int Server::auth_record_remove(AuthRecord x){
    return auth_record_remove(&x);
} /* End of auth_record_remove() */


int Server::auth_record_remove(AuthRecord *x){
  output(OUT_9, "%s()\n", __func__);
  for (vector<AuthRecord *>::iterator it = this->auth_record.begin(); it!=this->auth_record.end(); ++it) {
    if( *(*it)==*x){
        this->auth_record.erase(it);
        delete *it;
        return OP_SUCCESS;
    }
  }
  return OP_FAILURE;
} /* End of auth_record_remove() */


AuthRecord *Server::auth_record_lookup(u32 time, u8 *nonce, size_t nonce_len){
  output(OUT_9, "%s()\n", __func__);
  for(size_t i=0; i<this->auth_record.size(); i++){
    if( this->auth_record[i]->matches(time, nonce, nonce_len) )
       return this->auth_record[i];
  }
  return NULL;
} /* End of auth_record_lookup() */








/*****************************************************************************
 * SSH Authentication records                                                *
 *****************************************************************************/
AuthRecord *Server::ssh_auth_new(u32 time, u8 *nonce, size_t nonce_len){
  output(OUT_9, "%s()\n", __func__);
  AuthRecord *record = new AuthRecord(time, nonce, nonce_len);
  return record;
} /* End of ssh_auth_new() */


int Server::ssh_auth_insert(AuthRecord *x){
  static u32 completed_auths=0;
  output(OUT_9, "%s(%u, %02x)\n", __func__, x->getTimestamp(), *x->getNonce());

  /* Every once in a while purge the list of stored authentication (this only
   * deletes the ones that have already expired */
  if(((++completed_auths)%AUTH_RECORD_PURGE_INTERVAL)==0)
    ssh_auth_purge();

  /* Insert the new authentication record */
  this->ssh_auth.push_back(x);

  return OP_SUCCESS;
} /* End of ssh_auth_insert() */


int Server::ssh_auth_purge(){
  output(OUT_9, "%s()\n", __func__);
  int removed=0;

  size_t j=0;
  for (size_t i=0; i< this->ssh_auth.size(); ++i) {
    if (!this->ssh_auth[i]->expired((u32)time(NULL)) )
        this->ssh_auth[j++] = this->ssh_auth[i];
    else
        removed++;
  }
  /* trim vector to its new size */
  this->ssh_auth.resize(j);

  printf("Removed %d\n",removed);
  return removed;


  for (vector<AuthRecord *>::iterator it = this->ssh_auth.begin(); it!=this->ssh_auth.end(); ++it) {
    if( (*it)->expired((u32)time(NULL))){
        this->ssh_auth.erase(it);
        delete *it;
        removed++;
    }
  }
  return removed;
} /* End of ssh_auth_remove() */



int Server::ssh_auth_insert_new(u32 time, u8 *nonce, size_t nonce_len){
  output(OUT_9, "%s()\n", __func__);
  AuthRecord *x=ssh_auth_new(time, nonce, nonce_len);
  if(x==NULL)
      return OP_FAILURE;
  else
      return ssh_auth_insert(x);
} /* End of ssh_auth_insert() */


int Server::ssh_auth_remove(AuthRecord x){
    return ssh_auth_remove(&x);
} /* End of ssh_auth_remove() */


int Server::ssh_auth_remove(AuthRecord *x){
  output(OUT_9, "%s()\n", __func__);
  for (vector<AuthRecord *>::iterator it = this->ssh_auth.begin(); it!=this->ssh_auth.end(); ++it) {
    if( *(*it)==*x){
        this->ssh_auth.erase(it);
        delete *it;
        return OP_SUCCESS;
    }
  }
  return OP_FAILURE;
} /* End of ssh_auth_remove() */


AuthRecord *Server::ssh_auth_lookup(u32 time, u8 *nonce, size_t nonce_len){
  output(OUT_9, "%s()\n", __func__);
  for(size_t i=0; i<this->ssh_auth.size(); i++){
    if( this->ssh_auth[i]->matches(time, nonce, nonce_len) )
       return this->ssh_auth[i];
  }
  return NULL;
} /* End of ssh_auth_lookup() */


/** This function is called either by atexit() on normal program termination or
  * when a SIGINT signal is received. The function tries to wipe all sensitive
  * data before exiting the application.                                      */
void server_cleanup(void){

 unsigned char dummytext[512]; /* These buffers are used to call crypto functions    */
 unsigned char dummypass[512]; /* with the intent of overwriting their internal vars */

 indent(OUT_7, 1, "Performing sensitive data wiping.\n");

 /* Flush encryption buffers */
  for (int i=0; i<512; i++){
        dummytext[i] = (unsigned char)random()%256;
        dummypass[i] = (unsigned char)random()%256;
  }

  /* We could certainly check which algorithm was used and optimize the cleanup  */
  /* calling only the necessary functions but the cost of calling every crypto   */
  /* function isn't too high so we do the cleanup for all of them.               */

  /* I've tried to declare variables in crypto functions as "static" so we      */
  /* actually use the same memory space for keys in every call. Since Aldaba is */
  /* single-threaded there should be no problem with it. The reason for using   */
  /* static vars is to be able to wipe previously used data more easily.        */

  /* First of all we encrypt dummy texts. In most cases, this should overwrite   */
  /* internal values that were used in previous calls. It is not guaranteed      */
  /* that these calls do something actually useful but we've got nothing to lose.*/

  blowfish_encrypt_buffer(dummytext, dummytext, dummypass, 512);
  rijndael_decrypt_buffer(dummytext, dummytext, dummytext, 512);
  twofish_encrypt_buffer(dummytext, dummytext, dummytext, 512);
  serpent_decrypt_buffer(dummytext, dummytext, dummytext, 512);

  blowfish_decrypt_buffer(dummytext, dummytext, dummytext, 512);
  rijndael_encrypt_buffer(dummytext, dummytext, dummytext, 512);
  twofish_decrypt_buffer(dummytext, dummytext, dummytext, 512);
  serpent_encrypt_buffer(dummytext, dummytext, dummytext, 512);

  SHA256::sha256sum(dummytext, 512, dummypass);
  md5sum(dummypass, 512, dummytext);

  /* If encryption functions are called with NULL args, they zero their internal buffers */
  serpent_encrypt_buffer(NULL, NULL, NULL, 0);
  twofish_encrypt_buffer(NULL, NULL, NULL, 0);
  blowfish_encrypt_buffer(NULL, NULL, NULL, 0);
  rijndael_encrypt_buffer(NULL, NULL, NULL, 0);

  indent(OUT_7, 1, "Sensitive data wiping done.\n");

  fflush(stdin);
  fflush(stdout);
  fflush(stderr);

  script_cleanup();

  _exit(0);

} /* End of cleanup() */


/** Wrapper for server_cleanup to be passed to signal. */
void server_cleanup_signal(int signo){
  output(OUT_7, "Received signal %d\n", signo);
  server_cleanup();
} /* End of server_cleanup_signal() */


int script_init(){
  char msg[2001];
  memset(msg, 0, sizeof(msg));
  snprintf(msg, 2000, "%s/%s %s &", SCRIPTSDIR, INIT_SCRIPT_NAME, SCRIPTSDIR);
  if( system(msg)==-1 )
      return -1;
  return 0;
} /* End of server_init() */

int script_cleanup(){
  char msg[2001];
  memset(msg, 0, sizeof(msg));
  snprintf(msg, 2000, "%s/%s %s", SCRIPTSDIR, CLEANUP_SCRIPT_NAME, SCRIPTSDIR);
  if( system(msg)==-1 )
      return -1;
  return 0;

  
} /* End of server_init() */



