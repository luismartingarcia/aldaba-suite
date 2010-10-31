
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
#include "ArgParserClient.h"
#include "client.h"
#include "tools.h"
#include "ClientOps.h"
#include "output.h"
#include "client.h"
#include "blowfish.h"
#include "twofish.h"
#include "rijndael.h"
#include "serpent.h"
#include "sha256.h"
#include "md5.h"
#include "Random.h"
#include "PKClient.h"
#include "SPAClient.h"
#include "Crypto.h"

ClientOps o;

/** Client's main function. Calls command-line argument parser, registers
  * cleanup functions, tests cryptographic tools, and calls the appropriate
  * handler for the authentication technique requested by the user.           */
int main(int argc, char *argv[]){
   int i=0;
   PKClient pk;
   SPAClient spa;

   o.setVerbosityLevel(DEFAULT_VERBOSITY_CLIENT);
   o.setLoggingLevel(DEFAULT_LOGGING_CLIENT);

   /* Called early and used for testing purposes only */
   test_stuff(argc, argv);

  /* Register cleanup function to be called on exit                            */
  if (atexit(client_cleanup)!=0)
    warning( OUT_6, "|_ Failed to register cleanup function with atexit()");

  /* Register cleanup function to be called on signal delivery                 */
  if ( signal(SIGINT, client_cleanup_signal) == SIG_ERR )
    warning(OUT_6, "|_ Failed to register cleanup function with signal()");
  signal(SIGPIPE, SIG_IGN);       /* Ignore TCP Resets */

  /* Parse command line arguments */
  if ( (i=ArgParserClient::parse_arguments(argc, argv, &o)) != OP_SUCCESS )
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

  print_client_banner();
  print_client_conf();
  switch (o.getMode() ){

    case MODE_PORTKNOCKING:
        pk.run();
        return EXIT_SUCCESS;
    break;

    case MODE_SPA:
        spa.run();
        return EXIT_SUCCESS;
    break;

    default:
        fatal(OUT_2, "Unknown technique (%d). Please report a bug", o.getMode());
        return EXIT_FAILURE;
    break;
  }
  return EXIT_SUCCESS;
} /* End of main() function */


void test_stuff(int argc __attribute__((unused)), char *argv[] __attribute__((unused))) {

} /* End of test_stuff() */


/** This function is called either by atexit() on normal program termination or
  * when a SIGINT signal is received. The function tries to wipe all sensitive
  * data before exiting the application.                                      */
void client_cleanup(void){

 unsigned char dummytext[512]; /* These buffers are used to call crypto functions    */
 unsigned char dummypass[512]; /* with the intent of overwriting their internal vars */

  /* Flush encryption buffers */
  for (int i=0; i<512; i++){
        dummytext[i] = (unsigned char)random()%256; /** @todo Do this with nice random data */
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

  indent(OUT_8, 1,"Sensitive data wipe: All crypto function buffers were overwritten successfully.\n");

  fflush(stdin);
  fflush(stdout);
  fflush(stderr);

  _exit(0);

} /* End of cleanup() */

/** Wrapper for client_cleanup to be passed to signal. */
void client_cleanup_signal(int signo){
  output(OUT_7, "Received signal %d\n", signo);
  client_cleanup();
} /* End of client_cleanup_signal() */



void print_client_banner(){
  char time_str[128];
  time_t curr_time=time(NULL);
  struct tm *curr_tm=localtime(&curr_time);
  output(OUT_4, "\n ===================================================================\n");
  output(OUT_4, "            _     _       _                    _              _   \n");
  output(OUT_4, "      /\\   | |   | |     | |            _____ | |_           | |  \n");
  output(OUT_4, "     /  \\  | | __| | __ _| |__   __ _  |  ___|| {_} ___ _ __ | |_ \n");
  output(OUT_4, "    / /\\ \\ | |/ _` |/ _` |  _ \\ / _` | | |    | | |/ _ \\ `_ \\| __|\n");
  output(OUT_4, "   / ____ \\| | (_| | (_| | |_) | (_| | | |___ | | |  __/ | | | |_ \n");
  output(OUT_4, "  /_/    \\_\\_|\\____|\\__._|____/ \\__._| |_____||_|_|\\___|_| |_|\\__|\n");
  output(OUT_4, "\n ===================================================================\n");
  output(OUT_4, "[+]\n");
  if ( strftime(time_str, sizeof(time_str)-1, "%Y-%m-%d %H:%M %Z", curr_tm) >0 )
    indent(OUT_4, 1, "Aldaba Client %s started at %s.\n", CURRENT_VERSION, time_str);
  return;
}


void print_client_conf(){
  indent(OUT_6, 1, "Client Configuration\n" );
  indent(OUT_6, 2, "Target=         %s\n", o.getDestinationIP().toString() );
  if(o.getMode()==MODE_SPA){
    indent(OUT_6, 2, "Mode=           %s-%s\n", o.getMode_str(), o.getIPVersion_str());
    indent(OUT_6, 2, "Target Port=    %d\n", o.getSequencePort(0));
  }else{
    indent(OUT_6, 2, "Mode=           %s-%s-%s\n", o.getMode_str(), o.getIPVersion_str(), o.getAuthType_str() );
    indent(OUT_6, 2, "Covert Field=   %s\n", o.getField_str() );
    indent(OUT_6, 2, "Port Sequence=  %s\n", o.getSequencePorts_str());
  }
  indent(OUT_6, 2, "Cipher=         %s-%s\n", o.getCipher_str(), o.getCipherMode_str() );

  /* These two are only displayed when verbosity is very high */
  indent(OUT_8, 2, "Cipher Key=     %s\n", o.getCipherKey_str() );
  indent(OUT_8, 2, "HMAC Key=       %s\n", o.getMacKey_str() );
  
  if( o.issetNoisePackets() )
      indent(OUT_6, 2, "Noise Packets=  %d\n", o.getNoisePackets()-(int)o.getNumberOfSequencePorts());
  return;
}