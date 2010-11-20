
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
#include "tools.h"
#include "output.h"
#include <string.h>
#include "IPAddress.h"
#include "ArgParserServer.h"
#include <unistd.h>
#include <getopt.h>

extern char *optarg;
extern int optind, opterr, optopt;

ArgParserClient::ArgParserClient() {
  return;
} /* End of ArgParserClient constructor */


ArgParserClient::~ArgParserClient() {
  return;
} /* End of ArgParserClient destructor */


int ArgParserClient::parse_arguments(int argc, char *argv[], ClientOps *opt) {
  int option_index=0;
  u8 aux8=0;
  u16 aux16=0;
  u32 aux32=0;
  IPAddress auxIP;
  int arg=NULL;

  if(opt==NULL)
    fatal(OUT_2, "%s(): NULL parameter supplied", __func__);

  /* If no args supplied, print usage and quit */
  if(argc<=1){
    ArgParserClient::display_usage();
    exit(1);
  }else if( argc==2 ){ /* SPECIAL CASE: "$ aldaba start" reads default config file */
      if( !strcasecmp(argv[1], "start")){
        char config_file[1024];
        sprintf(config_file, "%s/%s", CLIENT_CONF_DIR, CLIENT_CONF_FILE_NAME);
        ArgParserClient::config_file_parser(opt, config_file);
        return OP_SUCCESS;
      }
  }

 struct option long_options[] ={
  {"version",           no_argument,            0,      'V'},

  {"knock-ip",          required_argument,      0,      'K'},
  {"spa-ip",            required_argument,      0,      'K'},
  {"authorized-ip",     required_argument,      0,      'K'},

  {"forward-ip",        required_argument,      0,      'F'},
  {"fwd-ip",            required_argument,      0,      'F'},

  {"source-ip",         required_argument,      0,      'S'},
  {"src-ip",            required_argument,      0,      'S'},
  {"src",               required_argument,      0,      'S'},
  {"bind-ip",           required_argument,      0,      'S'},

  {"port",              required_argument,      0,      'p'},
  {"knock-port",        required_argument,      0,      'p'},
  {"spa-port",          required_argument,      0,      'p'},

  {"passphrase",        required_argument,      0,      'P'},
  {"pass",              required_argument,      0,      'P'},

  {"target-port",       required_argument,      0,      't'},
  {"target-ports",      required_argument,      0,      't'},
  {"ports",             required_argument,      0,      't'},

  {"verbosity",         optional_argument,      0,      'v'},
  {"logging",           optional_argument,      0,      'l'},
  {"quiet",             optional_argument,      0,      'q'},
  {"interface",         required_argument,      0,      'i'},
  {"action",            required_argument,      0,      'a'},
  {"noise",             required_argument,      0,      'n'},
  {"decoys",            required_argument,      0,      'd'},
  {"cipher",            required_argument,      0,      'c'},
  {"ipv4",              no_argument,            0,      '4'},
  {"ipv6",              no_argument,            0,      '6'},
  {"help",              no_argument,            0,      'h'},
  {"config",            required_argument,      0,      'C'},
  {"field",             required_argument,      0,      'f'},
  {"auth",              required_argument,      0,      'A'},
  {"ip-version",        required_argument,      0,        0},
  {"portknocking",      no_argument,            0,        0},
  {"pk",                no_argument,            0,        0},
  {"spa",               no_argument,            0,        0},
  {"udp",               no_argument,            0,        0},
  {"open",              no_argument,            0,        0},
  {"close",             no_argument,            0,        0},
  {"forward",           no_argument,            0,        0},
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
  {"resolve-IP",        no_argument,            0,        0},
  {"resolve-ip",        no_argument,            0,        0},
  {"resolve",           no_argument,            0,        0},
  {"ssh-cookie",        no_argument,            0,        0},
  {0, 0, 0, 0}
 };

 /* Iterate over the paramter list and parse those args  */
 while((arg = getopt_long_only(argc,argv,"46A:a:c:C:d:f:F:hi:K:l::n:P:p:q::S:t:t:Vv::", long_options, &option_index)) != EOF) {

  aux8=aux16=aux32=0;

  switch(arg) {

   case 0: /* Parameters that do not have a single letter abbreviation */
    if ( !strcasecmp(long_options[option_index].name, "portknocking") ||
         !strcasecmp(long_options[option_index].name, "pk") ) {
        ArgParserClient::process_arg_technique(opt, "PK");
    } else if ( !strcasecmp(long_options[option_index].name, "spa") ) {
        ArgParserClient::process_arg_technique(opt, "SPA");
    } else if (!strcasecmp(long_options[option_index].name, "open")){
        ArgParserClient::process_arg_action(opt, "open");
    } else if (!strcasecmp(long_options[option_index].name, "close")){
        ArgParserClient::process_arg_action(opt, "close");
    } else if (!strcasecmp(long_options[option_index].name, "forward")){
        ArgParserClient::process_arg_action(opt, "forward");
    } else if (!strcasecmp(long_options[option_index].name, "debug")){
        opt->setVerbosityLevel(MAX_VERBOSITY_LEVEL);
        opt->setLoggingLevel(MAX_LOGGING_LEVEL);
    } else if (!strcasecmp(long_options[option_index].name, "blowfish") ||
               !strcasecmp(long_options[option_index].name, "bf")){
        ArgParserClient::process_arg_cipher(opt, "blowfish");
    } else if (!strcasecmp(long_options[option_index].name, "twofish") ||
               !strcasecmp(long_options[option_index].name, "tf")){
        ArgParserClient::process_arg_cipher(opt, "twofish");
    } else if (!strcasecmp(long_options[option_index].name, "rijndael") ||
               !strcasecmp(long_options[option_index].name, "rj") ||
               !strcasecmp(long_options[option_index].name, "aes") ){
        ArgParserClient::process_arg_cipher(opt, "aes");
    } else if (!strcasecmp(long_options[option_index].name, "serpent") ||
               !strcasecmp(long_options[option_index].name, "sp")){
        ArgParserClient::process_arg_cipher(opt, "serpent");
    } else if (!strcasecmp(long_options[option_index].name, "resolve-ip") ||
               !strcasecmp(long_options[option_index].name, "resolve")){
        ArgParserClient::process_arg_resolve_ip(opt, "enable");
    } else if (strcasecmp(long_options[option_index].name, "ssh-cookie") == 0 ){
        ArgParserClient::process_arg_ssh_cookie(opt, "enable");
    } else if (strcasecmp(long_options[option_index].name, "ip-version") == 0 ){
        ArgParserClient::process_arg_ip_version(opt, optarg);
    }
 // } else if (strcasecmp(long_options[option_index].name, "") == 0 ){

    break; /* case 0 */

    /* Single char Opts */
    case '4': /* IPv4 */
        ArgParserClient::process_arg_ip_version(opt, "4");
    break;

    case '6': /* IPv6 */
        ArgParserClient::process_arg_ip_version(opt, "6");
    break;

    case 'a': /* Action */
        ArgParserClient::process_arg_action(opt, optarg);
    break;

    case 'A': /* Authenticaton Type */
        ArgParserClient::process_arg_auth(opt, optarg);
    break;

    case 'c': /* Cipher */
        ArgParserClient::process_arg_cipher(opt, optarg);
    break;

    case 'C': /* Config file */
        ArgParserClient::config_file_parser(opt, optarg);
    break;

    case 'd': /* Decoys */
        ArgParserClient::process_arg_decoys(opt, optarg);
    break;

    case 'f': /* Field */
        ArgParserClient::process_arg_field(opt, optarg);
    break;

    case 'F': /* Forward IP address */
        ArgParserClient::process_arg_forward_ip(opt, optarg);
    break;

    case 'h': /* Help  */
        ArgParserClient::display_help();
        exit(0);
    break;

    case 'i': /* Network interface */
        ArgParserClient::process_arg_interface(opt, optarg);
    break;

    case 'l': /* Logging level */
        ArgParserClient::process_arg_verbosity(opt, optarg);
    break;

    case 'n': /* Noise packets */
        ArgParserClient::process_arg_noise(opt, optarg);
    break;

    case 'p': /* Knocking port */
        ArgParserClient::process_arg_knock_port(opt, optarg);
    break;

    case 'P': /* Passphrase */
        ArgParserClient::process_arg_passphrase(opt, optarg);
    break;

    case 'q': /* Reduce verbosity */
        ArgParserClient::process_arg_quiet(opt);
    break; /* case 'q': */

    case 'S': /* Source IP */
        ArgParserClient::process_arg_src_ip(opt, optarg);
    break;

    case 'K': /* Knock IP */
        ArgParserClient::process_arg_knock_ip(opt, optarg);
    break;

    case 't': /* Target port sequence */
        ArgParserClient::process_arg_port_sequence(opt, optarg);
    break;

    case 'V': /* Version */
        ArgParserClient::display_version();
        exit(0);
    break;

    case 'v': /* Verbosity */
        ArgParserClient::process_arg_verbosity(opt, optarg);
    break;

    case '?':
        ArgParserClient::display_help();
        exit(1);
    break;

  } /* End of switch */

 } /* End of getopt() while */


 /* Time for target host specifications. Everything that cannot be parsed as
  * a regular opt is treated as a target hostname. The "optind" var should be
  * pointing to the argv[] position that contains the first unparsed argument.
  * So we'll just check if value in "optind" makes sense, and try to use it
  * as our target host. */
 if(optind<argc){
    if (opt->setHostname(argv[optind])!=OP_SUCCESS )
        fatal(OUT_2, "Couldn't resolve supplied target host (%s)", argv[optind]);
 }

 return OP_SUCCESS;
} /* End of parseArguments() */


/** Displays help information. */
int ArgParserClient::display_help(){

const char *msg="\
  Aldaba Knocking Client %s - (C) Luis MartinGarcia, 2010.\n\
  http://www.aldabaknocking.com || aldabaknocking@gmail.com\n\
\n\
  Usage: aldaba <-P passphrase> <target_host> [Options]]\n\
\n\
  Parameters:\n\
     <target_host>            : Name or address of the target server\n\
     -P, --passphrase <pass>  : Passphrase used to generate the crypto keys.\n\
  Options:\n\
     --pk, --spa              : Technique [\"PK\", \"SPA\"(default)].\n\
     -p, --port <port>        : Port to open/close on the remote host [integer].\n\
     -S, --knock-ip <addr>    : IP to authorize on the remote host [IP or host].\n\
     -f, --field <field>      : Covert channel protocol header field.\n\
     -a, --action <type>      : Action taken by Aldaba server [\"Open\", \"Close\"].\n\
     -t, --target-ports <seq> : Sequence of dest ports [comma separated list].\n\
     -c  --cipher <algorithm> : Encryption algorithm [\"Twofish\", \"AES\", ...]\n\
     -i, --interface <name>   : Network interface to obtain IP address from.\n\
     -s, --source-ip <addr>   : Source IP address [IP or hostname].\n\
     -d, --decoys <addr>      : List of decoys [comma separated list of IPs].\n\
     -n  --noise <level>      : Number of extra packets to be sent [integer].\n\
     -v, --verbosity <level>  : Level of verbosity [0-9].\n\
     -4, --ipv4               : Use IP version 4 addresses.\n\
     -6, --ipv6               : Use IP version 6 addresses.\n\
     -C, --config <path>      : Read configuration from file.\n\
     -h, --help               : Display usage information.\n\
     -V, --version            : Display current version.\n\
\n\
   \n\
  Examples:\n\
     aldaba -P \"Squeamish Ossifrage\" server.org\n\
     aldaba -p 23 -a close -t 3,14,159,2653 -v 9 -i eth1 205.206.231.13\n\
     aldaba -6 fe80::235:c3ac:f1a6:4f1bc --noise 100 --cipher twofish\n\
  For more information please refer to manual page aldaba(8).\n";
printf(msg, CURRENT_VERSION);
return OP_SUCCESS;
} /* End of display_help() */





/* This function was originally generated by GNU gengetopt.*/
#ifndef CONFIG_FILE_LINE_SIZE
#define CONFIG_FILE_LINE_SIZE 2048
#endif

#define CONFIG_FILE_LINE_BUFFER_SIZE (CONFIG_FILE_LINE_SIZE+3)

/** Parses client's configuration file and sets the appropriate values in
  * structure ClientOps.                                                  */
int ArgParserClient::config_file_parser(ClientOps *opt, const char * filename){

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

        if (!strcasecmp("hostname", fopt) ){
            if( (i = process_arg_hostname(opt, farg)) != OP_SUCCESS)
                return i;
            else
                continue;
        }else if (!strcasecmp("authorized-ip", fopt) ){
            if( (i = process_arg_knock_ip(opt, farg)) != OP_SUCCESS)
                return i;
            else
                continue;
        }else if (!strcasecmp("source-ip", fopt)){
            if( (i = process_arg_src_ip(opt, farg)) != OP_SUCCESS)
                return i;
            else
                continue;
        }else if (!strcasecmp("port", fopt)){
            if( (i = process_arg_knock_port(opt, farg)) != OP_SUCCESS)
                return i;
            else
                continue;
        }else if (!strcasecmp("passphrase", fopt)){
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
        }else if (!strcasecmp("action", fopt)){
            if( (i = process_arg_action(opt, farg)) != OP_SUCCESS)
                return i;
            else
                continue;
        }else if (!strcasecmp("noise", fopt)){
            if( (i = process_arg_noise(opt, farg)) != OP_SUCCESS)
                return i;
            else
                continue;
        }else if (!strcasecmp("decoys", fopt)){
            if( (i = process_arg_decoys(opt, farg)) != OP_SUCCESS)
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
        }else if (!strcasecmp("resolve-ip", fopt)){
            if( (i = process_arg_resolve_ip(opt, farg)) != OP_SUCCESS)
                return i;
            else
                continue;
        }else if (!strcasecmp("forward-ip", fopt)){
            if( (i = process_arg_forward_ip(opt, farg)) != OP_SUCCESS)
                return i;
            else
                continue;
        }else{
            warning(OUT_1, "WARNING : %s : line %d : Unknown option '%s'\n", filename, line_num, fopt);
                continue;
        }

/*        if (!strcasecmp("", fopt)){
            if( (i = process_arg_e(opt, farg)) != OP_SUCCESS)
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


/** Processes argument -h, --host. The function takes a string containing a
  * host name, resolves it's associated IP address and fills members
  * opt->hostname and opt->dst_ip of the supplied ClientOps structure.    */
int ArgParserClient::process_arg_hostname(ClientOps *opt, const char * arg){
  if(opt==NULL || arg==NULL)
      fatal(OUT_2, "%s(): NULL parameter supplied", __func__);

  /* Try to resolve it */
  if ( opt->setDestinationIP(arg) == OP_FAILURE )
      fatal(OUT_2, "Unable to resolve destination host (%s)", arg);
  else
    opt->setHostname(arg);
  return 0;
} /* End of process_arg_hostname() */


/** Processes argument -s, --source-IP. The function takes a string containing
  * a host name, resolves it's associated IP address and fills member
  * opt->src_ip of the supplied ClientOps structure.                      */
int ArgParserClient::process_arg_src_ip(ClientOps *opt, const char * arg){
  if(opt==NULL || arg==NULL)
      fatal(OUT_2, "%s(): NULL parameter supplied", __func__);
  /* Store supplied IP or hostname */
  if( opt->setSourceIP(arg) == OP_FAILURE )
    fatal(OUT_2, "Unable to resolve source IP address (%s)", arg);
  return OP_SUCCESS;
} /* End of process_arg_src_ip() */


/** Processes argument -S, --knock-IP. The function takes a string containing
  * a host name, resolves it's associated IP address and fills member
  * opt->knock_ip of the supplied ClientOps structure.                    */
int ArgParserClient::process_arg_knock_ip(ClientOps *opt, const char * arg){
  if(opt==NULL || arg==NULL)
      fatal(OUT_2, "%s(): NULL parameter supplied", __func__);
  /* Store supplied IP or hostname */
  if( opt->setKnockIP(arg) == OP_FAILURE )
      fatal(OUT_2, "Unable to resolve supplied Knock IP address (%s)", arg);
  return OP_SUCCESS;
} /* End of process_arg_knock_ip */


/** Processes argument -F, --forward-ip. The function takes a string containing
  * a host name, resolves it's associated IP address and fills member
  * opt->forward_ip of the supplied ClientOps structure.                    */
int ArgParserClient::process_arg_forward_ip(ClientOps *opt, const char * arg){
  if(opt==NULL || arg==NULL)
      fatal(OUT_2, "%s(): NULL parameter supplied", __func__);
  /* Store supplied IP or hostname */
  if( opt->setForwardIP(arg) == OP_FAILURE )
      fatal(OUT_2, "Unable to resolve supplied Forward IP address (%s)", arg);
  return OP_SUCCESS;
} /* End of process_arg_forward_ip */


/** Processes argument -p, --port. The function takes a string containing a
  * TCP por number, converts it to a 16-bit integer and stores it in member
  * opt->port of the supplied ClientOps structure.                        */
int ArgParserClient::process_arg_knock_port(ClientOps *opt, const char * arg){
  output(OUT_9, "%s()\n", __func__);
  int port=0;
  int total_tokens=0;
  char *aux=NULL;
  char *tokens[3]={NULL, NULL, NULL};
  if(opt==NULL || arg==NULL)
      fatal(OUT_2, "%s(): NULL parameter supplied", __func__);

  aux=strdup(arg);
  if( (total_tokens=tokenize_single_tokens("/", aux, tokens, 3))>2 )
    fatal(OUT_2, "Invalid knock port supplied (%s).", arg);

  port=(int)strtol(tokens[0], (char **)NULL, 10); /* convert to integer */
  if ( !istcpport(port) || port==0)
    fatal(OUT_2, "Invalid knock port supplied (%s).", arg);

  if(total_tokens>1){
    if( !strcasecmp(tokens[1], "any") ){
        opt->setKnockPortProto(KNOCK_PORT_PROTO_ANY);
    }else if( !strcasecmp(tokens[1], "tcp") ){
        opt->setKnockPortProto(KNOCK_PORT_PROTO_TCP);
    }else if( !strcasecmp(tokens[1], "udp") ){
        opt->setKnockPortProto(KNOCK_PORT_PROTO_UDP);
    }else if( !strcasecmp(tokens[1], "sctp") ){
        opt->setKnockPortProto(KNOCK_PORT_PROTO_SCTP);
    }else{
        fatal(OUT_2, "Invalid knock port supplied (%s). Protocol unknown", arg);
    }
  }else{
    opt->setKnockPortProto(DEFAULT_KNOCK_PORT_PROTO);
  }
  opt->setKnockPort(port);
  free(aux);
  return OP_SUCCESS;
} /* End of process_arg_port() */



/** Processes argument -a, --action. The function takes a string containing
  * "1", "open", "0" or "close" and sets the appropriate value in member
  * opt->action of the supplied ClientOps structure                       */
int ArgParserClient::process_arg_action(ClientOps *opt, const char * arg){
  if(opt==NULL || arg==NULL)
      fatal(OUT_2, "%s(): NULL parameter supplied", __func__);
  if ( !strcmp(arg, "1" ) || !strcasecmp(arg, "open") )
    opt->setAction(ACTION_OPEN);
  else  if ( !strcmp(arg, "0" ) || !strcasecmp(arg, "close") )
    opt->setAction(ACTION_CLOSE);
  else  if ( !strcmp(arg, "2" ) || !strcasecmp(arg, "forward") )
    opt->setAction(ACTION_FORWARD);
  else
    fatal(OUT_2, "Invalid action supplied (%s).", arg);
  return OP_SUCCESS;
} /* End of process_arg_action() */


/** Processes argument -n, --noise. The function takes a string containing
  * the number of noise packets, converts it to an integer and stores it
  * in member opt->action of the supplied ClientOps structure.            */
int ArgParserClient::process_arg_noise(ClientOps *opt, const char * arg){
  int noise=0;
  if(opt==NULL || arg==NULL)
      fatal(OUT_2, "%s(): NULL parameter supplied", __func__);

  noise = strtol( arg, NULL, 10);

  if ( (noise==0) && (arg[0] != '0') )
    fatal(OUT_2, "Bogus noise value supplied (%s).", arg);
  if ( noise < 0 )
    fatal(OUT_2, "Bogus noise value supplied (%s). Noise must be a positive integer.", arg);
  else
    opt->setNoisePackets(noise);
  return OP_SUCCESS;
} /* End of process_arg_noise() */


/** Processes argument -d, --decoys. The function takes a string containing
  * a comma-separated list of IP addresses, converts each into a 32-bit value,
  * stores the list in a dinamically allocated buffer and links it to pointer
  * opt->decoys, member of the supplied ClientOps structure.              */
int ArgParserClient::process_arg_decoys(ClientOps *opt, const char *arg){
  if(opt==NULL || arg==NULL)
      fatal(OUT_2, "%s(): NULL parameter supplied", __func__);
  vector<IPAddress> iplist;
  iplist.clear();
  if(parse_hostname_list(arg, &iplist)!=OP_SUCCESS){
    fatal(OUT_2, "Supplied list of decoys is not valid (%s). Please make sure all specified hosts are DNS-resolvable.", arg);
  }
  for(unsigned int i=0; i< iplist.size(); i++){
    opt->addDecoy(iplist[i]);
    output(OUT_6, "Parsed decoy #%d : %s\n", i, iplist[i].toString());
  }  
  return OP_SUCCESS;
} /* End of process_arg_decoys() */


/** Processes argument --resolve-ip. */
int ArgParserClient::process_arg_resolve_ip(ClientOps *opt, const char *arg){
  if(opt==NULL || arg==NULL)
      fatal(OUT_2, "%s(): NULL parameter supplied", __func__);
  if ( !strcasecmp(arg, "yes" ) || !strcasecmp(arg, "1") || !strcasecmp(arg, "enable"))
    opt->resolve(true);
  else  if ( !strcmp(arg, "0" ) || !strcasecmp(arg, "close") || !strcasecmp(arg, "disable") )
    opt->resolve(false);
  else
    fatal(OUT_2, "Invalid resolve-ip parameter supplied (%s).", arg);
  return OP_SUCCESS;
} /* End of process_arg_resolve_ip() */


int ArgParserClient::parse_hostname_list(const char *list, vector<IPAddress> *targetvector){
  char *tokens[STD_TOKENS];
  memset(tokens, 0, STD_TOKENS * sizeof(char *));
  int total_tokens=0;
  IPAddress addr;
  char *list_backup=NULL;

  if(list==NULL || targetvector==NULL)
    fatal(OUT_2,"parse_hostname_list(): NULL parameter supplied\n");
  if(strlen(list)==0)
      return OP_FAILURE;

  /* Duplicate supplied parameter because tokenize() changes it */
  if((list_backup=strdup(list))==NULL)
    fatal(OUT_2,"parse_hostname_list(): Not enough memory.\n");

  /* Let's parse this host spec */
  if( (total_tokens=tokenize(",", list_backup, strlen(list_backup), tokens, STD_TOKENS))<= 0){
    free(list_backup);
    return OP_FAILURE;
  }

  for(int i=0; i<total_tokens; i++){
    addr.reset();
    if ( addr.setAddress(tokens[i]) != OP_SUCCESS ){
        free(list_backup);
        return OP_FAILURE;
    }else{
        targetvector->push_back(addr);
    }
  }

  free(list_backup);
  return OP_SUCCESS;
} /* End of parse_hostname_list() */


/** Prints current version number to stdout */
void ArgParserClient::display_version(){
  output(OUT_1, "\nAldaba Client %s. ( http://www.aldabaknocking.com )\n\n", CURRENT_VERSION);
}


/** Prints app usage to stdout */
void ArgParserClient::display_usage(){
  output(OUT_1, "Usage: aldaba target_host -P passphrase [Options]\n");
}
