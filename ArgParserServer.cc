
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
#include "tools.h"
#include "output.h"
#include <string.h>
#include "IPAddress.h"
#include <unistd.h>
#include <getopt.h>
#include "ServerOps.h"


extern char *optarg;
extern int optind, opterr, optopt;

ArgParserServer::ArgParserServer() {
  return;
} /* End of ArgParserServer constructor */


ArgParserServer::~ArgParserServer() {
  return;
} /* End of ArgParserServer destructor */


int ArgParserServer::parse_arguments(int argc, char *argv[], ServerOps *opt) {
  int option_index=0;
  u8 aux8=0;
  u16 aux16=0;
  u32 aux32=0;
  IPAddress auxIP;
  int arg=NULL;

  if(opt==NULL)
    fatal(OUT_2, "%s(): NULL parameter supplied", __func__);
  
  /* SPECIAL CASE: "$ aldabad start" reads default config file */
  if( argc==2 ){
      if( !strcasecmp(argv[1], "start")){
        char config_file[1024];
        sprintf(config_file, "%s/%s", SERVER_CONF_DIR, SERVER_CONF_FILE_NAME);
        ArgParserServer::config_file_parser(opt, config_file);
        return OP_SUCCESS;
      }
  }

 struct option long_options[] ={
  {"ipv4",              no_argument,            0,      '4'},
  {"ipv6",              no_argument,            0,      '6'},
  {"auth",              required_argument,      0,      'A'},
  {"config",            required_argument,      0,      'C'},
  {"cipher",            required_argument,      0,      'c'},
  {"field",             required_argument,      0,      'f'},
  {"help",              no_argument,            0,      'h'},
  {"interface",         required_argument,      0,      'i'},
  {"logging",           optional_argument,      0,      'l'},
  {"passphrase",        required_argument,      0,      'P'},
  {"pass",              required_argument,      0,      'P'},
  {"quiet",             optional_argument,      0,      'q'},
  {"target-ports",      required_argument,      0,      't'},
  {"ports",             required_argument,      0,      't'},
  {"verbosity",         optional_argument,      0,      'v'},
  {"version",           no_argument,            0,      'V'},
  {"interactive",       no_argument,            0,      'I'},
  {"daemonize",         no_argument,            0,        0},
  {"promiscuous",       no_argument,            0,        0},
  {"promisc",           no_argument,            0,        0},
  {"portknocking",      no_argument,            0,        0},
  {"pk",                no_argument,            0,        0},
  {"spa",               no_argument,            0,        0},
  {"udp",               no_argument,            0,        0},
  {"open",              no_argument,            0,        0},
  {"close",             no_argument,            0,        0},
  {"debug",             no_argument,            0,        0},
  {"blowfish",          no_argument,            0,        0},
  {"BF",                no_argument,            0,        0},
  {"twofish",           no_argument,            0,        0},
  {"TF",                no_argument,            0,        0},
  {"rijndael",          no_argument,            0,        0},
  {"RJ",                no_argument,            0,        0},
  {"AES",               no_argument,            0,        0},
  {"serpent",           no_argument,            0,        0},
  {"SP",                no_argument,            0,        0},
  {"bpf-filter",        required_argument,      0,        0},
  {"ssh-cookie",        no_argument,            0,        0},
  {0, 0, 0, 0}
 };

 /* Iterate over the paramter list and parse those args  */
 while((arg = getopt_long_only(argc,argv,"46a:A:c:C:d:f:hIi:l::P:q::t:Vv::", long_options, &option_index)) != EOF) {

  aux8=aux16=aux32=0;

  switch(arg) {

   case 0: /* Parameters that do not have a single letter abbreviation */

    if ( !strcasecmp(long_options[option_index].name, "portknocking") ||
         !strcasecmp(long_options[option_index].name, "pk") ) {
        ArgParserServer::process_arg_technique(opt, "PK");
    } else if ( !strcasecmp(long_options[option_index].name, "spa") ) {
        ArgParserServer::process_arg_technique(opt, "SPA");
    } else if (!strcasecmp(long_options[option_index].name, "debug")){
        opt->setVerbosityLevel(MAX_VERBOSITY_LEVEL);
        opt->setLoggingLevel(MAX_LOGGING_LEVEL);
        ArgParserServer::process_arg_daemonize(opt, "disable");
    } else if (!strcasecmp(long_options[option_index].name, "blowfish") ||
               !strcasecmp(long_options[option_index].name, "BF")){
        ArgParserServer::process_arg_cipher(opt, "blowfish");
    } else if (!strcasecmp(long_options[option_index].name, "twofish") ||
               !strcasecmp(long_options[option_index].name, "TF")){
        ArgParserServer::process_arg_cipher(opt, "twofish");
    } else if (!strcasecmp(long_options[option_index].name, "rijndael") ||
               !strcasecmp(long_options[option_index].name, "RJ") ||
               !strcasecmp(long_options[option_index].name, "AES") ){
        ArgParserServer::process_arg_cipher(opt, "aes");
    } else if (!strcasecmp(long_options[option_index].name, "serpent") ||
               !strcasecmp(long_options[option_index].name, "SP")){
        ArgParserServer::process_arg_cipher(opt, "serpent");
    } else if (!strcasecmp(long_options[option_index].name, "bpf-filter") ){
       ArgParserServer::process_arg_bpf(opt, optarg);
    } else if (!strcasecmp(long_options[option_index].name, "promiscuous") ||
               !strcasecmp(long_options[option_index].name, "promisc")){
        ArgParserServer::process_arg_promiscuous(opt, "enable");
    } else if (strcasecmp(long_options[option_index].name, "ssh-cookie") == 0 ){
        opt->enableSSHCookie();
    } else if (strcasecmp(long_options[option_index].name, "daemonize") == 0 ){
        ArgParserServer::process_arg_daemonize(opt, "enable");
    }
 // } else if (strcasecmp(long_options[option_index].name, "") == 0 ){

    break; /* case 0 */

    /* Single char Opts */
    case '4': /* IPv4 */
        opt->setIPVersion(AF_INET);
    break;

    case '6': /* IPv6 */
        opt->setIPVersion(AF_INET6);
    break;

    case 'A': /* Authenticaton Type */
        ArgParserServer::process_arg_auth(opt, optarg);
    break;

    case 'c': /* Cipher */
        ArgParserServer::process_arg_cipher(opt, optarg);
    break;

    case 'C': /* Config file */
        ArgParserServer::config_file_parser(opt, optarg);
    break;

    case 'f': /* Field */
        ArgParserServer::process_arg_field(opt, optarg);
    break;

    case 'h': /* Help  */
        ArgParserServer::display_help();
        exit(0);
    break;

    case 'I': /* Interactive mode (don't daemonize) */
        ArgParserServer::process_arg_daemonize(opt, "disable");
    break;

    case 'i': /* Network interface */
        ArgParserServer::process_arg_interface(opt, optarg);
    break;

    case 'l': /* Logging level */
        ArgParserServer::process_arg_verbosity(opt, optarg);
    break;

    case 'P': /* Passphrase */
        ArgParserServer::process_arg_passphrase(opt, optarg);
    break;

    case 'q': /* Reduce verbosity */
        ArgParserServer::process_arg_quiet(opt);
    break;

    case 'T': /* Mode */
        ArgParserServer::process_arg_technique(opt, optarg);
    break;

    case 't': /* Target port sequence */
        ArgParserServer::process_arg_port_sequence(opt, optarg);
    break;

    case 'V': /* Version */
        ArgParserServer::display_version();
        exit(0);
    break;

    case 'v': /* Verbosity */
        ArgParserServer::process_arg_verbosity(opt, optarg);
    break;

    case '?':
        ArgParserServer::display_help();
        exit(1);
    break;

  } /* End of switch */
 } /* End of getopt() while */
 return OP_SUCCESS;
} /* End of parseArguments() */


/** Displays help information. */
int ArgParserServer::display_help(){

  const char *msg="\
  Aldaba Knocking Server %s - (C) Luis MartinGarcia, 2010.\n\
  http://www.aldabaknocking.com || aldabaknocking@gmail.com\n\
\n\
  Usage: aldabad [Options]\n\
\n\
  Parameters:\n\
     -P, --passphrase <pass>  : Passphrase used to generate the crypto keys.\n\
  Options:\n\
     --pk, --spa              : Technique [\"PK\", \"SPA\"(default)].\n\
     -t, --target-ports <seq> : Sequence of dest ports [comma separated list].\n\
     -f, --field <field>      : Covert channel protocol header field.\n\
     -c  --cipher <algorithm> : Encryption algorithm [\"Twofish\", \"AES\", ...]\n\
     -i, --interface <name>   : Network interface to listen on.\n\
     -v, --verbosity <level>  : Level of verbosity [0-9 (Default)].\n\
     -l, --logging <level>    : Logging level [0-9].\n\
     -4, --ipv4               : Use IP version 4 addresses\n\
     -6, --ipv6               : Use IP version 6 addresses\n\
     -C, --config <path>      : Read configuration from file.\n\
     -I, --interactive        : Run interactively, not as a system daemon.\n\
     -h, --help               : Display usage information.\n\
     -V, --version            : Display current version.\n\
     --promiscuous            : Put network interface intro promiscuous mode\n\
\n\
   \n\
  Examples:\n\
     aldabad -P \"Squeamish Ossifrage\"\n\
     aldabad -t 3,14,159,2653 -v9 -i eth1\n\
     aldabad -6 --cipher twofish --promisc\n\
  For more information please refer to manual page aldabad(8).\n\n";
printf(msg, CURRENT_VERSION);
return OP_SUCCESS;
} /* End of display_help() */





/* This function was originally generated by GNU gengetopt.*/
#ifndef CONFIG_FILE_LINE_SIZE
#define CONFIG_FILE_LINE_SIZE 2048
#endif

#define CONFIG_FILE_LINE_BUFFER_SIZE (CONFIG_FILE_LINE_SIZE+3)

/** Parses server's configuration file and sets the appropriate values in
  * structure ServerOps.                                                  */
int ArgParserServer::config_file_parser(ServerOps *opt, const char * filename){
  FILE* file;
  char linebuf[CONFIG_FILE_LINE_SIZE];
  char *fopt=NULL;
  char *farg=NULL;
  char *str_index=NULL;
  char delimiter='\0';
  int line_num = 0;
  int i=0;
  int result = OP_SUCCESS;
  int equal=0;
  u32 len=0;
  u32 next_token=0;

  if(opt==NULL)
    fatal(OUT_2, "%s(): NULL parameter supplied", __func__);

  if ((file = fopen(filename, "r")) == NULL){
      fatal(OUT_1, "Couldn't open configuration file '%s'\n", filename);
      return OP_FAILURE;
  }

  while ((fgets(linebuf, CONFIG_FILE_LINE_SIZE, file)) != NULL)
    {
      ++line_num;
      len = strlen(linebuf);
      if (len > (CONFIG_FILE_LINE_SIZE-1))
        {
          warning(OUT_1, "ERROR : %s : line %d : Line too long in configuration file\n", filename, line_num);
          result = OP_FAILURE;
          break;
        }

      /* find first non-whitespace character in the line */
      next_token = strspn (linebuf, " \t\r\n");
      str_index  = linebuf + next_token;

      if ( str_index[0] == '\0' || str_index[0] == '#')
        continue; /* empty line or comment line is skipped */

      fopt = str_index;

      /* truncate fopt at the end of the first non-valid character */
      next_token = strcspn (fopt, " \t\r\n=");

      if (fopt[next_token] == '\0') /* the line is over */
        {
          farg  = NULL;
          equal = 0;
          goto noarg;
        }

      /* remember if equal sign is present */
      equal = (fopt[next_token] == '=');
      fopt[next_token++] = '\0';

      /* advance pointers to the next token after the end of fopt */
      next_token += strspn (fopt + next_token, " \t\r\n");

      /* check for the presence of equal sign, and if so, skip it */
      if ( !equal )
        if ((equal = (fopt[next_token] == '=')))
          {
            next_token++;
            next_token += strspn (fopt + next_token, " \t\r\n");
          }
      str_index  += next_token;

      /* find argument */
      farg = str_index;
      if ( farg[0] == '\"' || farg[0] == '\'' )
        { /* quoted argument */
          str_index = strchr (++farg, str_index[0] ); /* skip opening quote */
          if (! str_index)
            {
              warning(OUT_1, "ERROR : %s : line %d : Unterminated string in configuration file\n",filename, line_num);
              result =OP_FAILURE;
              break;
            }
        }
      else
        { /* read up the remaining part up to a delimiter */
          next_token = strcspn (farg, " \t\r\n#\'\"");
          str_index += next_token;
        }

      /* truncate farg at the delimiter and store it for further check */
      delimiter = *str_index, *str_index++ = '\0';

      /* everything but comment is illegal at the end of line */
      if (delimiter != '\0' && delimiter != '#')
        {
          str_index += strspn(str_index, " \t\r\n");
          if (*str_index != '\0' && *str_index != '#')
            {
              warning(OUT_1, "ERROR : %s : line %d : Malformed string in configuration file\n",filename, line_num);
              result = OP_FAILURE;
              break;
            }
        }

    noarg:


        if (!strcasecmp("passphrase", fopt)){
            if( (i = process_arg_passphrase(opt, farg)) != OP_SUCCESS)
                return i;
            else
                continue;
        }else if (!strcasecmp("technique", fopt)){
            if( (i = process_arg_technique(opt, farg)) != OP_SUCCESS)
                return i;
            else
                continue;
        }else if (!strcasecmp("target-ports", fopt)){
            if( (i = process_arg_port_sequence(opt, farg)) != OP_SUCCESS)
                return i;
            else
                continue;
        }else if (!strcasecmp("field", fopt)){
            if( (i = process_arg_field(opt, farg)) != OP_SUCCESS)
                return i;
            else
                continue;
        }else if (!strcasecmp("auth", fopt)){
            if( (i = process_arg_auth(opt, farg)) != OP_SUCCESS)
                return i;
            else
                continue;
        }else if (!strcasecmp("verbosity", fopt)){
            if( (i = process_arg_verbosity(opt, farg)) != OP_SUCCESS)
                return i;
            else
                continue;
        }else if (!strcasecmp("interface", fopt)){
            if( (i = process_arg_interface(opt, farg)) != OP_SUCCESS)
                return i;
            else
                continue;
        }else if (!strcasecmp("cipher", fopt)){
            if( (i = process_arg_cipher(opt, farg)) != OP_SUCCESS)
                return i;
            else
                continue;
        }else if (!strcasecmp("ip-version", fopt)){
            if( (i = process_arg_ip_version(opt, farg)) != OP_SUCCESS)
                return i;
            else
                continue;
        }else if (!strcasecmp("ssh-cookie", fopt)){
            if( (i = process_arg_ssh_cookie(opt, farg)) != OP_SUCCESS)
                return i;
            else
                continue;
        }else if (!strcasecmp("promiscuous", fopt)){
            if( (i = process_arg_promiscuous(opt, farg)) != OP_SUCCESS)
                return i;
            else
                continue;
        }else if (!strcasecmp("daemonize", fopt)){
            if( (i = process_arg_daemonize(opt, farg)) != OP_SUCCESS)
                return i;
            else
                continue;
        }else if (!strcasecmp("bpf-filter", fopt)){
            if( (i = process_arg_bpf(opt, farg)) != OP_SUCCESS)
                return i;
            else
                continue;
        }else{
            warning(OUT_1, "WARNING : %s : line %d : Unknown option '%s'\n", filename, line_num, fopt);
                continue;
        }


/*        if (!strcasecmp("", fopt)){
            if( (i = process_arg_e(opt, farg)) != 0)
                return i;
            else
                continue;
        }
*/
    } /* while */

  if (file)
    fclose(file);
  return result;
}



/** Prints current version number to stdout */
void ArgParserServer::display_version(){
  output(OUT_1, "\nAldaba Server %s. ( http://www.aldabaknocking.com )\n\n", CURRENT_VERSION);
}


/** Prints app usage to stdout */
void ArgParserServer::display_usage(){
  output(OUT_1, "Usage: aldaba -P passphrase [options]\n");
}


int ArgParserServer::process_arg_promiscuous(ServerOps *opt, const char * arg){
  if(opt==NULL || arg==NULL)
      fatal(OUT_2, "%s(): NULL parameter supplied", __func__);
  if ( !strcasecmp(arg, "yes" ) || !strcasecmp(arg, "1") || !strcasecmp(arg, "enable"))
    opt->setPromiscuous(true);
  else  if ( !strcmp(arg, "0" ) || !strcasecmp(arg, "close") || !strcasecmp(arg, "disable") )
    opt->setPromiscuous(false);
  else
    fatal(OUT_2, "Invalid --promiscuous parameter supplied (%s).", arg);
  return OP_SUCCESS;
} /* End of process_arg_promiscuous() */


int ArgParserServer::process_arg_daemonize(ServerOps *opt, const char * arg){
  if(opt==NULL || arg==NULL)
      fatal(OUT_2, "%s(): NULL parameter supplied", __func__);
  if ( !strcasecmp(arg, "yes" ) || !strcasecmp(arg, "1") || !strcasecmp(arg, "enable"))
    opt->setDaemonize(true);
  else  if ( !strcmp(arg, "0" ) || !strcasecmp(arg, "close") || !strcasecmp(arg, "disable") )
    opt->setDaemonize(false);
  else
    fatal(OUT_2, "Invalid --daemonize parameter supplied (%s).", arg);
  return OP_SUCCESS;
} /* End of process_arg_daemonize() */


int ArgParserServer::process_arg_linkhdrlen(ServerOps *opt, const char * arg){
  u16 aux16;
  if(opt==NULL || arg==NULL)
    fatal(OUT_2, "%s(): NULL parameter supplied", __func__);
  if( parse_u16(arg, &aux16)!=OP_SUCCESS)
    fatal(OUT_2, "Invalid link layer header length supplied.");
  else
    opt->setLinkHeaderLength(aux16);
  return OP_SUCCESS;
} /* End of process_arg_linkhdrlen() */


int ArgParserServer::process_arg_bpf(ServerOps *opt, const char * arg){
  if(opt==NULL || arg==NULL)
    fatal(OUT_2, "%s(): NULL parameter supplied", __func__);
  else
    opt->setBPF(arg);
  return OP_SUCCESS;
} /* End of process_arg_bpf() */
