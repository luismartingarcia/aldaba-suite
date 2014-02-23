
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
#ifndef _ALDABA_H_
#define _ALDABA_H_ 1

/***********************************************************************
 *  COMMON LIBRARY REQUIREMENTS                                        *
 ***********************************************************************/
#define __USE_BSD         /* Using BSD IP header                              */
#include <sys/socket.h>	  /* Sockets                                          */
#include <netinet/in.h>	  /* Internet Protocol family                         */
#include <netinet/ip.h>   /* Internet Protocol                                */
#define __FAVOR_BSD       /* Using BSD TCP header                             */
#include <netinet/tcp.h>  /* Transmission Control Protocol                    */
#include <netinet/udp.h>  /* User Datagram Protocol                           */
#include <arpa/inet.h>    /* Definitions for internet operations              */
#include <sys/types.h>    /* Data types                                       */
#include <sys/ioctl.h>    /* I/O control                                      */
#include <net/ethernet.h> /* Fundamental constants relating to ethernet       */
#include <netinet/ether.h>/* Manipulating and printing Ethernet MAC addresses */
#include <sys/stat.h>     /* For umask()                                      */
#include <time.h>         /* Time defintions for timestamping                 */
#include <sys/time.h>     /* Time defintions for timestamping                 */ 
#include <netdb.h>        /* Definitions for network database operations      */
#include <stdio.h>        /* Standard buffered input/output                   */
#include <string.h>       /* String operations                                */
#include <unistd.h>       /* Standard symbolic constants and types for UNIX   */
#include <ctype.h>        /* Character classification functions.              */
#include <stdlib.h>       /* Standard library definitions                     */
#include <net/if.h>       /* Sockets local interfaces                         */
#include <time.h>         /* We need the time to seed the randomizer          */
#include <syslog.h>       /* System logs                                      */
#include <stdarg.h>       /* Handle variable argument lists                   */
#include <termio.h>       /* Terminal operations                              */
#include <linux/sockios.h>/* For ioctl() args. WARNING: Linux dependant!      */
#include <fcntl.h>        /* File control options                             */
#include <stdint.h>       /* C99 definitions for types int32_t, uint_32_t,etc */
#include <signal.h>       /* Signal handling                                  */
#include <iostream>       /* C++ standard I/O streams                         */
#include <vector>         /* STL vector data type                             */
using namespace std;


#ifdef UNUSED
#elif defined(__GNUC__)
#define UNUSED(x) UNUSED_ ## x __attribute__((unused))
#elif defined(__LCLINT__)
#define UNUSED(x) /*@unused@*/ x
#else
#define UNUSED(x) x
#endif

#ifndef MIN
#define MIN(x,y) (((x)<(y))?(x):(y))
#endif
#ifndef MAX
#define MAX(x,y) (((x)>(y))?(x):(y))
#endif
#ifndef ABS
#define ABS(x) (((x) >= 0)?(x):-(x))
#endif


/***********************************************************************
 *                                                                     *
 * GENERAL, USER-TUNABLE, DEFINES                                      *
 *                                                                     *
 ***********************************************************************/
#define CURRENT_VERSION "0.2.1"  /**< Current version number                  */

/* General values                                                             */
#define MAX_PASSPHRASE_LEN 256   /**< Max length of a passphrase              */
#define MIN_PASSPHRASE_LEN 8     /**< Min length of a passphrase              */
#define MAX_CIPHER_KEY_LEN 32    /**< Encryption key length (SHA256 hash len) */
#define MAX_MAC_KEY_LEN 32       /**< Encryption key length (SHA256 hash len) */
#define MAX_IP_LEN 15            /**< Max length of an IPv4 address in ASCII  */
#define MIN_IP_LEN 7             /**< Min length of an IP address in ASCII    */
#define MAX_PORT_LEN 5           /**< Lenght of string "65535"                */
#define MAX_HOSTNAME_LEN 256     /**< Max length of a host name               */
#define MAX_PATH_LEN 1024        /**< Max length of a file path               */
#define MAX_IFACE_LEN 32         /**< Max network interface name length       */
#define MAX_ERR_STR_LEN 1024     /**< Max length of error messages            */
#define MAX_BPF_FILTER_LEN 1024  /**< Max length of a BPF filter              */

/* Default size of many function internal buffers (functions that need
 * to backup input for any reason will be able to hold STD_BUFF_LEN bytes.
 * Value should be high enough to fit more than one SPA packet */
#define STD_BUFF_LEN 8192

/* Functions that tokenize input allocate space for a number of STD_TOKENS tokens.
 * This sets the limit of things like, number of parseable ports in port list,
 * number of parseable IPs in an list of IPsm etc. */
#define STD_TOKENS 256

/* External IP address resolution */
#define DEFAULT_IP_RESOLVER_SITE "whatismyip.aldabaknocking.com"
#define DEFAULT_IP_RESOLVER_PATH "/"
#define DEFAULT_IP_RESOLVER_USERAGENT "Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)"
#define DEFAULT_IP_RESOLVER_PORT 80
#define DEFAULT_IP_RESOLVER_RESULT_MAX_LENGTH 2048
#define DEFAULT_IP_RESOLVER_OPEN_TAG "<IP_ADDR>"
#define DEFAULT_IP_RESOLVER_CLOSE_TAG "</IP_ADDR>"

/***********************************************************************
 *                                                                     *
 * SOME OTHER, NOT-SO-TUNABLE DEFINES. Do NOT play with these unless   *
 * you know what you're doing.                                         *
 *                                                                     *
 ***********************************************************************/
/* Protocol constants */
#define ETHERNET_HEADER_LEN 14   /**< Length of the Ethernet header           */
#define TCP_PSEUDOHEADER_LEN 12  /**< Length of TCP pseudoheader              */
#define TCP_HEADER_LEN 20        /**< Length of TCP header with no options    */
#define UDP_HEADER_LEN 8         /**< Lenght of UDP header                    */
#define UDP_PSEUDOHEADER_LEN 12  /**< Length of UDP pseudoheader              */
#define UDP_IP_PACKET_LEN 20+8   /**< Lenght of IP header + UDP header        */
#define TCP_IP_PACKET_LEN 20+20  /**< Lenght of IP header + TCP header        */
#define IP_HEADER_LEN  20        /**< Lenght of IP header with no options     */
#define IPv6_HEADER_LEN  40      /**< Lenght of IPv6 header                   */
#define IPv4_ADDRESS_LEN 4       /**< Lenght of an IPv4 address               */
#define IPv6_ADDRESS_LEN 16      /**< Lenght of an IPv6 address               */
#define TCP_PORT_LEN 2           /**< Lenght of a TCP port                    */

/* Encryption and hashing algorithms */
#define ALG_BLOWFISH     0x11       /**< Blowfish cipher                      */
#define ALG_TWOFISH      0x22       /**< Twofish cipher                       */
#define ALG_RIJNDAEL     0x33       /**< Rijndael/AES cipher                  */
#define ALG_SERPENT      0x44       /**< Serpent cipher                       */
#define ALG_MD5          0x55       /**< MD5 hashing algorithm                */
#define ALG_SHA256       0x66       /**< SHA-256 hashing algorithm            */
#define DEFAULT_ALG_PK (ALG_BLOWFISH)
#define DEFAULT_ALG_SPA (ALG_RIJNDAEL)

/* Cipher block modes of operation */
#define BLOCK_MODE_ECB 1         /**< Mode Electronic Code Book               */
#define BLOCK_MODE_CBC 2         /**< Mode Cipher-block Chaining              */
#define BLOCK_MODE_CFB 3         /**< Mode Cipher Feedback                    */
#define BLOCK_MODE_OFB 4         /**< Mode Output Feedback                    */
#define DEFAULT_BLOCK_MODE BLOCK_MODE_CBC  /**< Default mode: CBC             */

/* General modes of operation */
#define MODE_PORTKNOCKING 1      /**< Port Knocking                           */
#define MODE_SPA 2               /**< Single Packet Authorization protocol    */
#define DEFAULT_MODE MODE_SPA

/* Actions to be taken upon successful authentication */
#define ACTION_OPEN 1              /**< Action "Open Port"                    */
#define ACTION_CLOSE 0             /**< Action "Close Port"                   */
#define ACTION_FORWARD 2           /**< Action "Close Port"                   */
#define DEFAULT_ACTION (ACTION_OPEN)

/* Default port numbers */
#define SPA_TOTAL_PORTS 1
#define DEFAULT_SPA_PORT 7177
#define DEFAULT_AUTH_PORT 22  /**< Default port, included in the knocks (SSH) */
#define MAX_KNOCK_PORTS 2
#define KNOCK_PORT_1 0
#define KNOCK_PORT_2 1
#define KNOCK_PORT_PROTO_ANY 0x0
#define KNOCK_PORT_PROTO_TCP 0x1
#define KNOCK_PORT_PROTO_UDP 0x2
#define KNOCK_PORT_PROTO_SCTP 0x3
#define DEFAULT_KNOCK_PORT_PROTO (KNOCK_PORT_PROTO_ANY)

/* Authentication types (Port Knocking) */
#define AUTH_TYPE_LIGHT     0x18
#define AUTH_TYPE_STRONG    0x31
#define DEFAULT_AUTH AUTH_TYPE_LIGHT

/* Port Knocking modes (base on auth and address family) */
#define PK_MODE_LIGHT_IPv4  0x01
#define PK_MODE_LIGHT_IPv6  0x02
#define PK_MODE_MEDIUM_IPv4 0x03
#define PK_MODE_MEDIUM_IPv6 0x04

/* Protocol header fields for the covert channel */
#define COVERT_IP_TOS       0x00
#define COVERT_IP_ID        0x01
#define COVERT_TCP_ACK      0x02
#define COVERT_TCP_SEQ      0x03
#define COVERT_TCP_SPORT    0x04
#define COVERT_TCP_DPORT    0x05
#define COVERT_TCP_WINDOW   0x06
#define COVERT_TCP_URP      0x07
#define COVERT_TCP_CSUM     0x08
#define DEFAULT_COVERT_FIELD COVERT_TCP_SEQ
/* Protocol header field lengths */
#define COVERT_IP_TOS_LEN       1
#define COVERT_IP_ID_LEN        2
#define COVERT_TCP_ACK_LEN      4
#define COVERT_TCP_SEQ_LEN      4
#define COVERT_TCP_SPORT_LEN    2
#define COVERT_TCP_DPORT_LEN    2
#define COVERT_TCP_WINDOW_LEN   2
#define COVERT_TCP_URP_LEN      2
#define COVERT_TCP_CSUM_LEN     2
#define MAX_COVERT_PAYLOAD_LEN  4

/* Replay protection */
#define MAX_CLOCK_SKEW_SECONDS 10 //(86400) /* Acceptable clock skew: 24 hours */
#define AUTH_RECORD_PURGE_INTERVAL 10

/* Exit codes for the main() function. */
/* UNIX standard: exit codes have to be small positive integers [0-255]       */
#define EXIT_SUCCESS 0           /**< Normal termination                      */
#define EXIT_FAILURE 1           /**< Program termination with errors         */

/* Exit codes for the rest of functions */
#define OP_SUCCESS 0             /**< Operation carried out successfully      */
#define OP_FAILURE -1            /**< Errors encountered during operation     */
#define OP_TRUNCATED -2          /**< Buffer was smaller than data. Truncation*/
#define LOW_RANDOMNESS -3        /**< Low quality random numbers in use       */

/** OUTPUT (VERBOSITY AND LOGGING LEVELS) */
                  /*+--------------------------------------------+-------------------------------------------------+ */
                  /*+  CLIENT MSG OUTPUT LEVELS                  | SERVER MSG OUTPUT LEVELS                        | */
                  /*+--------------------------------------------+-------------------------------------------------+ */
#define OUT_0 0   /* No output at all                            | No output at all                                | */
#define OUT_1 1   /* Cmdline Argument Parsing Errors             | Cmdline Argument Parsing Errors                 | */
#define OUT_2 2   /* Fatal error messages                        | Fatal error messages. (DEFAULT)                 | */
#define OUT_3 3   /* Warnings                                    | Warnings                                        | */
#define OUT_4 4   /* Info about current authentication (DEFAULT) | Information about client authentication attempts| */
#define OUT_5 5   /* Information about current mode of operation | Information about current mode of operation     | */
#define OUT_6 6   /* Important debug information                 | Important debug information                     | */
#define OUT_7 7   /* Any debug information                       | More specific debug information                 | */
#define OUT_8 8   /* Reserved for future use                     | Really detailed debug information               | */
#define OUT_9 9   /* Reserved for future use                     | Reserved for future use                         | */
                  /*+--------------------------------------------+-------------------------------------------------+ */
                  /*+  CLIENT LOG LEVELS                         | SERVER LOG LEVELS                               | */
                  /*+--------------------------------------------+-------------------------------------------------+ */
#define LOG_0 10  /* No logging. (DEFAULT)                       | No logging.                                     | */
#define LOG_1 11  /* Fatal error messages (including parsing)    | Successful authentication attempts              | */
#define LOG_2 12  /* Knocks sent successfully                    | Failed authentication attempts (DEFAULT)        | */
#define LOG_3 13  /* Warnings                                    | Fatal error messages                            | */
#define LOG_4 14  /* Information about current configuration     | Warnings                                        | */
#define LOG_5 15  /* Important debug information                 | Information about current configuration         | */
#define LOG_6 16  /* Any debug information                       | Important debug information                     | */
#define LOG_7 17  /* Reserved for future use                     | Any debug information                           | */
#define LOG_8 18  /* Reserved for future use                     | Reserved for future use                         | */
#define LOG_9 19  /* Reserved for future use                     | Reserved for future use                         | */
                  /*+--------------------------------------------+-------------------------------------------------+ */
                  /*+  CLIENT PERROR() OUTPUT LEVELS             | SERVER PERROR() OUTPUT LEVELS                   | */
                  /*+--------------------------------------------+-------------------------------------------------+ */
#define PERR_0 20 /* No output at all                            | No output at all                                | */
#define PERR_1 21 /* Cmdline Argument Parsing Errors             | Cmdline Argument Parsing Errors                 | */
#define PERR_2 22 /* Fatal error messages                        | Fatal error messages.                           | */
#define PERR_3 23 /* Warnings                                    | Warnings                                        | */
#define PERR_4 24 /* Info about current authentication           | Information about client authentication attempts| */
#define PERR_5 25 /* Information about current mode of operation | Information about current mode of operation     | */
#define PERR_6 26 /* Important debug information                 | Important debug information                     | */
#define PERR_7 27 /* Any debug information                       | Any debug information                           | */
#define PERR_8 28 /* Reserved for future use                     | Reserved for future use                         | */
#define PERR_9 29 /* Reserved for future use                     | Reserved for future use                         | */
/*+--------------------------------------------+-------------------------------------------------+ */
#define ALL 30    /* Log via syslog() and call perror() */

#define MIN_VERBOSITY_LEVEL 0
#define MAX_VERBOSITY_LEVEL 9
#define MIN_LOGGING_LEVEL 0
#define MAX_LOGGING_LEVEL 9


/* SERVER SPECIFIC VALUES                                                     */
/* Better NOT to play with the following ones:                                */
#define MAX_KNOCKS 128
#define MAX_SPA_PORTS 10
#define PCAP_BUFSIZE_SPA 512       /**< Max number of bytes to capture (SPA)  */
#define PCAP_BUFSIZE_PK 128        /**< Max number of bytes to capture (SPA)  */




/* These are safe to play with:                                               */
#define PCAP_OPTIMIZE 1                 /**< Optimize BPF filter code?        */
#define DEFAULT_LOGGING_SERVER LOG_3    /**< Default level of logging         */
#define DEFAULT_VERBOSITY_SERVER OUT_2  /**< Default level of verbosity       */
#define KNOCKATTEMPT_TTL_SECS 10        /**< Min number of seconds before discarding a knock in progress */
#define KNOCKATTEMPT_TTL_USECS 0        /**< Min number of microseconds before discarding a knock in progress.(Must be less than 999 999!)*/
#define SERVER_CONF_FILE_NAME "aldabad.conf"
/* Number of seconds we allow incoming connections after a successful
 * authentication (firewall opens a hole for a period of time and then 
 * only allows traffic that belongs to establish connections) */
#define DEFAULT_PORT_OPEN_WINDOW 120



/* CLIENT SPECIFIC VALUES */
/* General values */
#define DEFAULT_VERBOSITY_CLIENT 4 /**< Default verbosity level               */
#define DEFAULT_LOGGING_CLIENT 0   /**< Default logging level                 */
#define MAX_PKSEQ_PORTS MAX_KNOCKS /**< Max number of ports in the PK sequence */
#define CLIENT_CONF_FILE_NAME "aldaba.conf"

/* This is provided just in case someone wants to continue execution
   after a fatal error. However, as fatal() is normally called when
   NULL pointers are detected or invalid values are passed to a function,
   preventing exit() will probably cause the application to segfault or
   behave in an unpredictable way.
   Do NOT uncomment this line unless you really know what you're doing!
*/
/* #define DO_NOT_EXIT_ON_FATAL_ERRORS */


/* SOME DATA TYPES */

/* These represent unsigned integers of a fixed length. They are mainly
 * abbreviations of other typedefs and are extensively used throughout the code
 * for portability reasons */
#undef u8
typedef uint8_t u8;

#undef u16
typedef uint16_t u16;

#undef u32
typedef uint32_t u32;

#undef u64
typedef uint64_t u64;

/** \brief TCP and UDP port numbers                                           */
typedef uint16_t tcp_port_t;

/** \brief TCP pseudoheader, used in checksum computation. @todo Change the name to struct tcp_pseudoheader*/
struct tcp_pseudoheader {
    struct in_addr src;
    struct in_addr dst;
    u8 zero;
    u8 protocol;
    u16 tcplen;
} __attribute__((__packed__));
typedef struct tcp_pseudoheader tcp_phdr_t;

/**\brief UDP pseudoheader, used in checksum computation.                    */
struct udp_pseudoheader {
    struct in_addr src;
    struct in_addr dst;
    u8 zero;
    u8 protocol;
    u16 udplen;
} __attribute__((__packed__));
typedef struct udp_pseudoheader udp_phdr_t;

#endif
/* EOF */
