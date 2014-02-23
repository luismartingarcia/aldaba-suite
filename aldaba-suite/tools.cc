
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
#include "output.h"
#include "tools.h"
#include "md5.h"
#include "sha256.h"
#include "blowfish.h"
#include "twofish.h"
#include "rijndael.h"
#include "serpent.h"
#include "IPAddress.h"
#include <string.h>
#include <assert.h>
#include "IPv6Header.h"
#include "errno.h"
#include "math.h"
#include <pcap.h>
#include "Random.h"
#include "GeneralOps.h"

extern GeneralOps o;

/** Returns true if ipaddr is valid IP4 address in dot-notation */
int isipaddr(const char *ipaddr){
    return IPAddress::isIPAddress(ipaddr);
} /* End of isipaddr() */


/** Returns true if portn is valid TCP Port */
int istcpport(long int portn){
    return (portn>=0 && portn<=65535) ? 1 : 0;
} /* End of istcpport() */


/** Returns true if portn is valid TCP Port */
int istcpport(int portn){
    return istcpport( (long int)portn );
} /* End of istcpport() */


/** Computes the Internet Checksum of the supplied buffer. See RFC 1071 for
  * more information.                                                         */
/*  This piece of code has been used many times in a lot of differents tools.
 *  I haven't been able to determine the author of the code but it looks like
 *  this is a public domain implementation of the checksum algorithm          */
unsigned short in_cksum(unsigned short *addr,int len){

register int sum = 0;
u_short answer = 0;
register u_short *w = addr;
register int nleft = len;

/*
* Our algorithm is simple, using a 32-bit accumulator (sum),
* we add sequential 16-bit words to it, and at the end, fold back
* all the carry bits from the top 16 bits into the lower 16 bits.
*/

while (nleft > 1) {
sum += *w++;
nleft -= 2;
}

/* mop up an odd byte, if necessary */
if (nleft == 1) {
*(u_char *)(&answer) = *(u_char *)w ;
sum += answer;
}

/* add back carry outs from top 16 bits to low 16 bits */
sum = (sum >> 16) + (sum &0xffff); /* add hi 16 to low 16 */
sum += (sum >> 16); /* add carry */
answer = ~sum; /* truncate to 16 bits */
return(answer);

} /* End of in_cksum() */


/** Transforms the calling process into a daemon process.
  * This code was written by Doug Potter and is published in his website:
  * http://www-theorie.physik.unizh.ch/~dpotter/howto/daemonize
  * There is no copyright notice or license information so I assume it's OK to
  * use the code.                                                             */
int daemonize(void){
  pid_t pid, sid;
  FILE *dummy=NULL;

  /* already a daemon */
  if ( getppid() == 1 )
    return -1;

  /* Fork off the parent process */
  pid = fork();
  if (pid < 0) {
    exit(-1);
  }
  /* If we got a good PID, then we can exit the parent process. */
  if (pid > 0) {
    exit(EXIT_SUCCESS);
  }

  /* At this point we are executing as the child process */

  /* Change the file mode mask */
  umask(0);

  /* Create a new SID for the child process */
  sid = setsid();
  if (sid < 0) {
    exit(-1);
  }

  /* Change the current working directory.  This prevents the current
   directory from being locked; hence not being able to remove it. */
  if ((chdir("/")) < 0) {
    exit(-1);
  }

  /* Redirect standard files to /dev/null */
  if((dummy=freopen( "/dev/null", "r", stdin))==NULL)
    output(OUT_7,"Failed to redirect stdin");
  if((dummy=freopen( "/dev/null", "w", stdout))==NULL)
    output(OUT_7,"Failed to redirect stdout");
  if((dummy=freopen( "/dev/null", "w", stderr))==NULL)
    output(OUT_7,"Failed to redirect stderr");
  return OP_SUCCESS;
} /* End of daemonize() */


/** Grab user input with terminal echo disabled. This is useful for requesting
  * passwords or other sensitive information. Some of this code was extracted 
  * from http://web.mit.edu/answers/c/c_terminal_echo.html                    */
int gets_noecho(char *buffer, int buflen){
 int i=0;
 struct termio tty, oldtty;
 char *dummy=NULL;
 memset(buffer, 0, buflen);

  /* Save the old tty settings, and get rid of echo for the new tty settings */
  ioctl(0, TCGETA, &oldtty);
  tty = oldtty;
  tty.c_lflag    &= ~(ICANON|ECHO|ECHOE|ECHOK|ECHONL);
  tty.c_cc[VMIN]  = 1;
  tty.c_cc[VTIME] = 0;
  ioctl(0, TCSETA, &tty); /* TODO: Error checking here? */

  fflush(stdin);
  if((dummy=fgets(buffer, buflen, stdin))==NULL)
    output(OUT_7,"fgets() failed");
  fflush(stdin);

  /* fgets() stores the newline character so we have to get rid of it */
  for (i=0; i<buflen; i++)
      if (buffer[i] == '\n'){
          buffer[i] = '\0';
          break;
      }

  /* Now go back to the old settings */
  ioctl(0, TCSETA, &oldtty); /* TODO: Error checking here? */
  return OP_SUCCESS;
} /* End of get_noecho() */


/** Turns terminal echo off and displays a '*' everytime the user enters a
 * character. The function reads at most buflen-1 characters and stores them
 * in the supplied buffer. I've tried to add suport for backspace. It works
 * on my linux box but I'm sure this needs tuning in other systems. Please
 * report a bug if it doesn't work in your system.                            */
int gets_noecho_stars(char *buffer, int buflen){
 int i=0;
 char c=0;
 struct termio tty, oldtty;
 memset(buffer, 0, buflen);

  /* Save the old tty settings, and get rid of echo for the new tty settings */
  ioctl(0, TCGETA, &oldtty);
  tty = oldtty;
  tty.c_lflag    &= ~(ICANON|ECHO|ECHOE|ECHOK|ECHONL);
  tty.c_cc[VMIN]  = 1;
  tty.c_cc[VTIME] = 0;
  ioctl(0, TCSETA, &tty); /* TODO: Error checking here? */
  fflush(stdin);

  for(i=0; (c != '\n') && (c!=EOF) && (i<buflen-1) && (i>=0); i++){
    c=getchar();
    if (c != 0x7F){ /* Backspace. This for sure is gonna be buggy in many OS */
        if( c!='\n' ){
            buffer[i] = c;
            printf("*");
        }
    }else{ /* If user pressed backspace go back and update array index */
        if(i>0){
            i--;
            buffer[i--]='\0';
            printf("\b");
            continue;
        }
        else if (i==0)
            i--; /* Don't worry, the for loop will set it to 0 */
    }
    fflush(stdout);
  }
  fflush(stdin);
  /* Now reset the old settings */
  ioctl(0, TCSETA, &oldtty); /* TODO: Error checking here? */
  return OP_SUCCESS;
} /* End of get_noecho_stars() */




/** Fills the supplied buffer with regular crappy random numbers generated by
  * the standard and cryptographically NOT secure random() function.          */
int fill_buffer_with_unsecure_random_data(char *buffer, int buffer_len){
 int i=0;
 if(buffer==NULL)
    return -1;
 srandom( (unsigned)time(NULL) ^ getpid() );
 for (i=0; i<buffer_len; i++)
    buffer[i]=random()%256;
 return 0;
} /* End of fill_buffer_with_unsecure_random_data() */








/** When decoys or noise packets are used, Aldaba may display a list of every
  * packet that is sent. This function displays the header of this list. This
  * is basically some ASCII output that paints a table row with columns that
  * contain strings "Source IP", "Destination IP", "Source Port", etc.        */
int display_table_header(int mode, int family){

 switch (mode){

    case MODE_PORTKNOCKING:
        switch(family){
            case AF_INET:
                output(OUT_4," +-----------------+-----------------+-------+----------+-------+\n");
                output(OUT_4," |    SOURCE IP    | DESTINATION IP  | DPORT |   DATA   | TYPE  |\n" );
                output(OUT_4," +-----------------+-----------------+-------+----------+-------+\n");
            break;
            case AF_INET6:
                output(OUT_4," +-----------------+-----------------+-------+----------+-------+\n");
                output(OUT_4," |    SOURCE IP    | DESTINATION IP  | DPORT |   DATA   | TYPE  |\n" );
                output(OUT_4," +-----------------+-----------------+-------+----------+-------+\n");
            break;
        }
   break;

   case MODE_SPA:
        switch(family){
            case AF_INET:
                output(OUT_4," +-----------------+-----------------+-------+-------+-------+-------+--------+\n");
                output(OUT_4," |    SOURCE IP    | DESTINATION IP  | SRC.P | DST.P | PROTO | TYPE  | STATUS |\n" );
                output(OUT_4," +-----------------+-----------------+-------+-------+-------+-------+--------+\n");
            break;
            case AF_INET6:
                output(OUT_4," +-----------------+-----------------+-------+-------+-------+-------+--------+\n");
                output(OUT_4," |    SOURCE IP    | DESTINATION IP  | SRC.P | DST.P | PROTO | TYPE  | STATUS |\n" );
                output(OUT_4," +-----------------+-----------------+-------+-------+-------+-------+--------+\n");
            break;
        }

   break;

   default:
    return OP_FAILURE;
   break;

 }
 return OP_SUCCESS;
} /* End of display_table_header() */


/** Displays row delimiters. Check display_table_header() for more details    */
int display_table_delimiter(int mode){

 switch (mode){

   case MODE_PORTKNOCKING:
    output(OUT_4," +-----------------+-----------------+-------+----------+-------+\n");
   break;

   case MODE_SPA:
    output(OUT_4," +-----------------+-----------------+-------+-------+-------+-------+--------+\n");
   break;

   default:
    return OP_FAILURE;
   break;

 }
 return OP_SUCCESS;
} /* End of display_table_delimiter() */


/** Prints the Source and Destination MAC address of the supplied ethernet frame.*/
int print_Ethernet_header(int vblevel, char *packet){
 if (packet==NULL)
    return OP_FAILURE;
 struct ether_header *ethheader = (struct ether_header *)packet;
 output(vblevel, "   <!> Src MAC:  %s\n", ether_ntoa(( struct ether_addr *)ethheader->ether_shost));
 output(vblevel, "   <!> Dst MAC:  %s\n", ether_ntoa(( struct ether_addr *)ethheader->ether_dhost));
 return OP_SUCCESS;
} /* End of print_Ethernet_header() */


/** Prints Source IP, Dest IP, Source Port and Dest Port of the supplied UDP
  * packet. WARNING: IP header is assumed to begin at packet[0].              */
int print_UDP_IP_header(int vblevel, char *packet){
 if (packet == NULL)
    return OP_FAILURE;
 struct ip *ipheader = (struct ip *)packet;
 struct udphdr *udpheader = (struct udphdr *) (packet + sizeof(struct ip) );
 output(vblevel, "   <!> Src IP:   %s\n", inet_ntoa(ipheader->ip_src));
 output(vblevel, "   <!> Dst IP:   %s\n", inet_ntoa(ipheader->ip_dst));
 output(vblevel, "   <!> Src Port: %d\n", ntohs(udpheader->uh_sport) );
 output(vblevel, "   <!> Dst Port: %d\n", ntohs(udpheader->uh_dport) );
 return OP_SUCCESS;
} /* End of print_UDP_IP_header() */


/** Prints Source IP, Dest IP, Source Port, Dest Port and IP-Id value of the
  * supplied TCP packet. WARNING: IP header is assumed to begin at packet[0]  */
int print_TCP_IP_header(int vblevel, char *packet){
 if (packet == NULL || vblevel<=0)
    return OP_FAILURE;
 struct ip *ipheader = (struct ip *)packet;
 struct tcphdr *tcpheader = (struct tcphdr *)(packet + sizeof(struct ip));
 output(vblevel, "   <!> Src IP: %s\n", inet_ntoa(ipheader->ip_src));
 output(vblevel, "   <!> Dst IP: %s\n", inet_ntoa(ipheader->ip_dst));
 output(vblevel, "   <!> Src PORT: %d\n", ntohs(tcpheader->th_sport));
 output(vblevel, "   <!> Dst PORT: %d\n", ntohs(tcpheader->th_dport));
 output(vblevel, "   <!> IP Id: %X\n", ipheader->ip_id);
 return OP_SUCCESS;
} /* End of print_TCP_IP_header() */

//
///** Wipes out the supplied buffer overwritting it an unespecified number of
//  * times. It is first overwritten with nice random data obtained from device
//  * urandom and then it is overwritten several times with crappy random data
//  * produced by random().                                                     */
//int wipe_buffer(unsigned char *buffer, int len){
//
// int retcode=OP_SUCCESS;      /* Return value */
// int times = 0;               /* Number of times buffer will be overwritten */
// int i=0, j=0;
// unsigned char entropy[128]; /* Buffer to store some decent random numbers */
//
// if (buffer == NULL || len <= 0)
//    return OP_FAILURE;
//
// /* Fill our little entropy buffer with some nice random data */
// if ( get_urandom_bytes( entropy, 128 ) != 0 )
//        retcode=LOW_RANDOMNESS;
//
// /* Seed crappy randomizer */
// srandom( (*((unsigned int *)entropy) ^ ((unsigned int)time(NULL))) + getpid() );
//
// /* Overwrite user supplied buffer with nice random data */
// if ( get_urandom_bytes( buffer, len ) != 0 )
//        retcode=LOW_RANDOMNESS;
//
// /* So far we have overwritten the buffer with nice random data, now we fill  */
// /* it with regular crappy random data.                                       */
//
// /* Overwrite an unespecified number of times (at least 50). All this should  */
// /* make data recovery a bit complicated.                                     */
// times = 50 + entropy[ sizeof(int) + 1 ];
//
// for ( j=0; j<times; j++){
//    for ( i=0; i<len; i++){
//        buffer[i] = ((unsigned char)random()%256) ^ (entropy[ i % 128 ]) ;
//    }
// }
// return retcode;
//} /* End of wipe_buffer() */

/** @todo: Finish this! */
/** This function is called either by atexit() on normal program termination or
  * when a SIGINT signal is received. The function tries to wipe all sensitive
  * data before exiting the application.                                      */
void cleanup(void){

 int i=33, j=33;
 unsigned char dummytext[512]; /* These buffers are used to call crypto functions    */
 unsigned char dummypass[512]; /* with the intent of overwriting their internal vars */

  if (i==1||j==1)
      warning(OUT_7, "<!> Could't obtain high quality random data for varible cleanup. Using only regular random data.\n");
  else if ( i == OP_FAILURE || j == OP_FAILURE)
      warning(OUT_7, "<E> Some sensitive data may not have been safely wiped out.\n");
  else
      output(OUT_7,  "<-> Cleaning up: User supplied data overwritten successfully.\n");

  /* Flush encryption buffers */
  for ( i=0; i<512; i++){
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

  output(OUT_7,  "<-> Cleaning up: buffers of crypto functions overwritten successfully.\n");

  fflush(stdin);
  fflush(stdout);
  fflush(stderr);

  _exit(0);

} /* End of cleanup() */


char *select_iface_pcap(){
  static char devname[128];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *pcap_ifaces=NULL;

  /* Vars for the current interface in the loop */
  pcap_if_t *curr=NULL;             /* Current pcap pcap_if_t element   */
  bool current_has_address=false;   /* Does it have an addr of any type? */
  bool current_has_ipv6=false;      /* Does it have an IPv6 address?     */
  bool current_has_ipv4=false;      /* Does it have an IPv4 address?     */
  bool current_is_loopback=false;   /* Is it a loopback interface?       */
  bool select_current=false;        /* Is current better than candidate? */
  struct sockaddr_in6 devaddr6;     /* We store iface's IPv6 address     */
  struct sockaddr_in devaddr4;      /* And also its IPv4 address         */

  /* Vars for our candidate interface */
  pcap_if_t *candidate=NULL;
  bool candidate_has_address=false;
  bool candidate_has_ipv6=false;
  bool candidate_has_ipv4=false;
  bool candidate_is_loopback=false;

  /* Ask libpcap for a list of network interfaces */
  if( pcap_findalldevs(&pcap_ifaces, errbuf) != 0 )
      fatal(OUT_2, "%s", errbuf);

  /* Iterate over the interface list and select the best one */
  for(curr=pcap_ifaces; curr!=NULL; curr=curr->next){
      current_has_address=false;   candidate_has_ipv6=false;
      candidate_is_loopback=false; candidate_has_ipv4=false;
      select_current=false;

      if( curr->flags==PCAP_IF_LOOPBACK)
          current_is_loopback=true;

      /* Loop through the list of addresses */
      for(pcap_addr_t *curraddr=curr->addresses; curraddr!=NULL; curraddr=curraddr->next){
          current_has_address=true;
          if( curraddr->addr->sa_family==AF_INET){
              current_has_ipv4=true;
              memcpy( &devaddr4, curraddr->addr, sizeof(struct sockaddr_in));
          } else if( curraddr->addr->sa_family==AF_INET6){
              current_has_ipv6=true;
              memcpy( &devaddr6, curraddr->addr, sizeof(struct sockaddr_in6));
          }
       }

      /* If we still have no candidate, take the first one we find */
      if( candidate==NULL){
          select_current=true;
      }
      /* If we already have a candidate, check if the one we are
       * processing right now is better than the one we've already got */
      else{
          /* If our candidate does not have an IPv6 address but this one does,
           * select the new one. */
          if( candidate_has_ipv6==false && current_has_ipv6==true ){
              select_current=true;
          }
          /* If our candidate does not even have an IPv4 address but this
           * one does, select the new one. */
          else if( candidate_has_ipv4==false && candidate_has_ipv6==false && current_has_ipv4){
              select_current=true;
          }
          /* If our candidate is a loopback iface, select the new one */
          else if( candidate_is_loopback && !current_is_loopback){

              /* Select the new one only if it has an IPv6 address
               * and the old one didn't. If our old loopback iface
               * has an IPv6 address and this one does not, we
               * prefer to keep the loopback one, even though the
               * other is not loopback */
              if(current_has_ipv6==true){
                  select_current=true;
              }
              /* We also prefer IPv4 capable interfaces than  */
              else if(candidate_has_ipv6==false && current_has_ipv4==true){
                  select_current=true;
              }
          }
          /* If both are loopback, select the best one. */
          else if( candidate->flags==PCAP_IF_LOOPBACK && curr->flags==PCAP_IF_LOOPBACK){
              if( candidate_has_ipv6==false && current_has_ipv6 )
                  select_current=true;
          }
      }

      /* Did we determine that we should discard our old candidate? */
      if( select_current ){
          candidate=curr;
          candidate_has_address=current_has_address;
          candidate_has_ipv4=current_has_ipv4;
          candidate_has_ipv6=current_has_ipv6;
          candidate_is_loopback=current_is_loopback;
      }

      /* Let's see if we have the interface of our dreams... */
      if( candidate_has_address && candidate_has_ipv6 && candidate_has_ipv4 && candidate_is_loopback==false){
          break;
      }

  }
  if(candidate==NULL){
      pcap_freealldevs(pcap_ifaces);
      return NULL;
  }else{
      strncpy(devname, candidate->name, sizeof(devname)-1);
      pcap_freealldevs(pcap_ifaces);
      return devname;
  }
} /* End of select_iface_pcap() */


int get_iface_addr_pcap(const char *ifname, struct sockaddr_storage *ss, int family){
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *pcap_ifaces=NULL;
  pcap_if_t *curr=NULL;

  /* Ask libpcap for a list of network interfaces */
  if( pcap_findalldevs(&pcap_ifaces, errbuf) != 0 )
    fatal(OUT_2, "%s", errbuf);
  /* Iterate over the interface list, trying to find the one that matches "ifname" */
  for(curr=pcap_ifaces; curr!=NULL; curr=curr->next){
    /* Discard it if the name does not match */
    if( strcmp(curr->name, ifname)!=0 )
        continue;
    /* Loop through the list of addresses and hope one matches the desired address family */
    for(pcap_addr_t *curraddr=curr->addresses; curraddr!=NULL; curraddr=curraddr->next){
        if( curraddr->addr->sa_family==AF_INET && family==AF_INET){
            memcpy(ss, curraddr->addr, sizeof(struct sockaddr_in));
            pcap_freealldevs(pcap_ifaces);
            return OP_SUCCESS;
        }else if( curraddr->addr->sa_family==AF_INET6 && family==AF_INET6){
            memcpy(ss, curraddr->addr, sizeof(struct sockaddr_in6));
            pcap_freealldevs(pcap_ifaces);
            return OP_SUCCESS;
        }
    }
  }
  pcap_freealldevs(pcap_ifaces);
  return OP_FAILURE;
} /* End of get_iface_addr_pcap() */


char *select_iface_ioctl(){
  int i=0;
  int sockfd=-1;
  int num_interfaces=0;
  struct ifreq ifaces_buff[32];
  struct ifreq tmp;
  struct ifconf  interfaces;
  static char devname[128];

  interfaces.ifc_len = 32 * sizeof( struct ifreq ) ;
  interfaces.ifc_buf = (char *)ifaces_buff;

  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
      return NULL;
  }

  if (ioctl(sockfd, SIOCGIFCONF, &interfaces) < 0){
      return NULL;
  }

  num_interfaces=interfaces.ifc_len / sizeof(struct ifreq);
  for (i=0; i <num_interfaces; i++){

      /* Store the name in a tmp struct for additioanl ioctl() calls */
      strncpy(tmp.ifr_name, interfaces.ifc_req[i].ifr_name, sizeof(tmp.ifr_name));

      if ( ioctl(sockfd, SIOCGIFFLAGS, &tmp) >= 0){
          /* Discard loopback interfaces */
          if(tmp.ifr_flags & IFF_LOOPBACK)
              continue;
          /* Discard interfaces that are down */
          else if( !(tmp.ifr_flags & IFF_UP) )
              continue;
          /* Choose the first Ethernet device we find */
          else if(tmp.ifr_flags & IFF_BROADCAST){
              strncpy(devname, interfaces.ifc_req[i].ifr_name, sizeof(devname)-1);
              return devname;
          }
      }
  }
  return NULL;
} /* End of select_iface_ioctl() */


int get_iface_addr_ioctl(const char *ifname, struct sockaddr_storage *ss, int family){
  int i=0;
  int sockfd=-1;
  int num_interfaces=0;
  struct ifreq ifaces_buff[32+1];
  struct ifconf interfaces;

  interfaces.ifc_len=32*sizeof(struct ifreq);
  interfaces.ifc_buf = (char *)ifaces_buff;

  if ((sockfd = socket(family, SOCK_DGRAM, 0)) < 0){
      perror("Failed to acquire socket: ");
      return OP_FAILURE;
  }

  if (ioctl(sockfd, SIOCGIFCONF, &interfaces) < 0){
      perror("Failed to perform ioctl SIOCGIFCONF on socket: ");
      return OP_FAILURE;
  }

  num_interfaces=interfaces.ifc_len/sizeof(struct ifreq);

  /* Iterate over the list of interfaces until we find the right one */
  for (i=0; i <num_interfaces; i++){

      /* If it's the right one, get its assigned IP address and return */
      if( !strcasecmp(ifname, interfaces.ifc_req[i].ifr_name) ){
          if(family==AF_INET6){
              memcpy(ss, &interfaces.ifc_req[i].ifr_addr, sizeof(struct sockaddr_in6));
              return OP_SUCCESS;
          }else{
              memcpy(ss, &interfaces.ifc_req[i].ifr_addr, sizeof(struct sockaddr_in));
              return OP_SUCCESS;
          }
      }
  }
  return OP_FAILURE;
} /* End of get_iface_addr_ioctl() */



char *select_iface(int family){
  if( family==AF_INET6 )
    return select_iface_pcap();
  else
    return select_iface_ioctl();
}

int get_iface_addr(const char *ifname, struct sockaddr_storage *ss, int family){
  if(family==AF_INET6)
    return get_iface_addr_pcap(ifname, ss, family);
  else
    return get_iface_addr_ioctl(ifname, ss, family);
}

int set_descriptor_blocking_state(int fd, bool blocking){
  int flags=-1;
  /* Get the flags that the socket had already */
  if( (flags=fcntl(fd, F_GETFL, 0)) == -1 )
    flags=0;
  /* Set blocking status operation */
  if(blocking){
    flags^=O_NONBLOCK;
  }else{
    flags|=O_NONBLOCK;
  }
  if( fcntl(fd, F_SETFL, flags) == -1 )
    return OP_FAILURE;
  else
    return OP_SUCCESS;
} /* End of set_socket_blocking_status()*/


int setSocketNonBlocking(int fd){
  return set_descriptor_blocking_state(fd, true);
} /* End of setSocketNonBlocking()*/


int setSocketBlocking(int fd){
  return set_descriptor_blocking_state(fd, true);
} /* End of setSocketBlocking() */


bool islocalhost(struct in_addr addr){
  /* If it is starts with 127, it's probably localhost */
  if ((addr.s_addr & htonl(0xFF000000)) == htonl(0x7F000000))
    return true;
  /* If it is 0.0.0.0, it's probably localhost */
  if (addr.s_addr==0)
    return true;
  /* Not sure, but the supplied address is probably not localhost */
  return false;
} /* End of islocalhost() */


/** Returns true if "source" contains at least one instance of "substring" */
bool contains(const char *source, const char *substring){
 if(source==NULL || substring==NULL )
    fatal(OUT_2, "contains(): NULL value received.");
 if( strcasestr(source, substring) )
    return true;
 else
    return false;
} /* End of contains() */


/** Takes a string representing a number and converts it into an actual
  * integer of the specified bits. The result is stored in memory area
  * pointed by "dstbuff".
  * @param str is the string to be converted. The number may be in any
  * of the following forms:
  *     - Hexadecimal number: It must start with "0x" and have an even
  *       number of hex digits after it.
  *     - Octal number: It must start with "0" and have any number of
  *       octal digits ([0,7]) after it.
  *     - Decimal number: Any string that does not start with "0x" or
  *       "0" will be treated as a decimal number. It may only contain
  *       decimal digits (no whitespace, no weird symbols, and not even
  *       a sign character (+ or -).
  *     - Random number: The number specification may contain the special
  *       value "rand" or "random". In that case, a random number of the
  *       requested length will be generated and stored in the supplied
  *       buffer.
  * @param bits may be one of 8, 16, 32 or 64.
  * @param dstbuff should be the address of an u8, u16, u32 or u64
  * variable. Note that "dstbuff" MUST be able to hold bits/8 bytes.
  * @return OP_SUCCESS if conversion was successful or OP_FAILURE in
  * case of error. */
#define RANGE_8_BITS  8
#define RANGE_16_BITS 16
#define RANGE_32_BITS 32
#define RANGE_64_BITS 64
static int parse_unsigned_number(const char *str, unsigned int bits, void *dstbuff){
  unsigned long int result=0;
  char *tail=NULL;

  if(str==NULL || dstbuff==NULL)
    return OP_FAILURE;

  if(bits!=8 && bits!=16 && bits!=32 && bits!=64)
    return OP_FAILURE;

  /* Check if the spec contains a sign character */
  if(strpbrk(str, "-+") != NULL)
    return OP_FAILURE;

  /* Case 1: User wants a random value */
  if(!strcasecmp(str, "rand") || !strcasecmp(str, "random")){
    fill_buffer_with_unsecure_random_data((char *)dstbuff, bits/8);
    return OP_SUCCESS;
  }

  /* Case 2: User supplied an actual number */
  errno=0;
  result=strtoul(str, &tail, 0);
  if(errno!=0 || tail==str || *tail!='\0')
    return OP_FAILURE;

  /* Check the result fits in the supplied number of bits */
  if( ((double)result) >= pow((double)2.0, (double)bits) )
    return OP_FAILURE;

  /* Store the result in the buffer supplied by the user. */
  switch(bits){

    case 8:
        *( (u8 *)dstbuff ) = result;
    break;
    case 16:
            *( (u16 *)dstbuff ) = result;
    break;
    case 32:
            *( (u32 *)dstbuff ) = result;
    break;
    case 64:
            *( (u64 *)dstbuff ) = result;
    break;
    default:
        return OP_FAILURE;
    break;

  }
  return OP_SUCCESS;
} /* End of parse_number() */


/** Takes a string representing an 8-bit number and converts it into an
  * actual integer. The result is stored in memory area pointed by
  * "dstbuff". Returns OP_SUCCESS if conversion was successful or
  * OP_FAILURE in case of error.*/
int parse_u8(const char *str, u8 *dstbuff){
    return parse_unsigned_number(str, RANGE_8_BITS, dstbuff);
}


/** Takes a string representing a 16-bit number and converts it into an
  * actual integer. The result is stored in memory area pointed by
  * "dstbuff". Returns OP_SUCCESS if conversion was successful or
  * OP_FAILURE in case of error.*/
int parse_u16(const char *str, u16 *dstbuff){
    return parse_unsigned_number(str, RANGE_16_BITS, dstbuff);
}


/** Takes a string representing a 32-bit number and converts it into an
  * actual integer. The result is stored in memory area pointed by
  * "dstbuff". Returns OP_SUCCESS if conversion was successful or
  * OP_FAILURE in case of error.*/
int parse_u32(const char *str, u32 *dstbuff){
    return parse_unsigned_number(str, RANGE_32_BITS, dstbuff);
}


/** Removes every instance of the character stored in parameter "c" in the
 * supplied string.
 * @warning the supplied buffer is modified by this function. Whenever a
 * match is found, the rest of the string is moved one position to the left
 * so the matching char gets overwritten. */
int removechar(char *string, char c){
 size_t len=0, i=0, j=0;
 if(string==NULL)
    return OP_FAILURE;

 len=strlen(string);

  for(i=0; i<len; i++){
    /* Found the character, move everything one position to the left */
    if( string[i]== c ){
        for(j=i; j<len-1; j++)
            string[j]=string[j+1];
        len-=1;
        string[len]='\0';
        /* Start again from the beginning because otherwise we don't catch
         * consecutive colons */
        i=-1; /* (get incremented by one by the loop control) */
    }
   }
   return OP_SUCCESS;
} /* End of removechar() */


/** Replaces every instance of the character stored in parameter
  * "oldchar" with the character store in newchar.
  * @warning the supplied buffer is modified by this function. */
int replacechar(char *string, char oldchar, char newchar){
 size_t len=0, i=0;
 if(string==NULL)
    return OP_FAILURE;
 len=strlen(string);
  for(i=0; i<len; i++){
    /* Found the character, replace it with the new one */
    if( string[i]== oldchar ){
        string[i]=newchar;
    }
   }
   return OP_SUCCESS;
} /* End of replacechar() */



/** Removes every instance of the character stored in parameter "c" in the
 * supplied string.
 * @warning the supplied buffer is modified by this function. Whenever a
 * colon is found, the rest of the string is moved one position to the left
 * so the colon gets overwritten. */
int removesubstring(char *string, char *sub){
 size_t len=0, i=0, j=0;
 if(string==NULL || sub==NULL)
    return OP_FAILURE;
 len=strlen(string);

  for(i=0; i<len; i++){
    /* Found a match, move everything to the left */
    if( !strncmp(string+i, sub, strlen(sub)) ){
        for(j=i; j<len-1; j++)
            string[j]=string[j+strlen(sub)];
        len-=strlen(sub);
        string[len]='\0';
        /* Start again from the beginning */
        i=-1; /* (gets incremented by one by the loop control) */
    }
   }
   return OP_SUCCESS;
} /* End of removechar() */



/** This function was originally written by Dave Sinkula and later modified
  * by Luis MartinGarcia.  The original implementation can be found at:
  * http://www.daniweb.com/code/snippet216517.html
  *
  * Description:
  * Find and replace text within a string.
  *
  * Parameters:
  * src (in) - pointer to source string
  * from (in) - pointer to search text
  * to (in) - pointer to replacement text
  *
  * Returns:
  * Returns a pointer to dynamically-allocated memory containing string
  * with occurences of the text pointed to by 'from' replaced by with the
  * text pointed to by 'to'.
  */
char *find_and_replace(const char *src, const char *from, const char *to){
  char *value=NULL;               /* Allocated buff                           */
  char *dst=NULL;                 /* Return value                             */
  const char *match=NULL;         /* Points to occurences of "from" in "src"  */
  char *temp=NULL;                /* Temp pointer for realloc operations.     */
  size_t tolen = strlen(to);      /* Lenght of new substring                  */
  size_t fromlen = strlen(from);  /* Lenght of old substring                  */
  size_t size = 1 + strlen(src);  /* Lenght of the whole original string      */
  size_t count=0;

  /* Allocate a buffer big enough to hold the original string.*/
  if ( (value=(char*)calloc(size,1)) == NULL )
    return NULL;

  /* Make a copy of the allocated buff before we start messing around with it.*/
  dst = value;

  /* Loop until no matches are found. */
      while(1337){

        /* Try to find the search text */
        match = strstr(src, from);
        if (match!=NULL){

            /* Find out how many characters to copy up to the 'match'. */
            count = match - src;

            /* Compute the total size the string will be after the replacement is
               performed. */
            size += tolen - fromlen;

            /* Attempt to realloc memory for the new size. */
            if( (temp=(char*)realloc(value, size))==NULL){
                free(value);
                return NULL;
            }

            /* The call to realloc was successful. But we'll want to
               return 'value' eventually, so let's point it to the memory
               that we are now working with. And let's not forget to point
               to the right location in the destination as well. */
            dst = temp + (dst - value);
            value = temp;

            /* Copy from the source to the point where we matched. Then
               move the source pointer ahead by the amount we copied. And
               move the destination pointer ahead by the same amount. */
            memmove(dst, src, count);
            src += count;
            dst += count;

            /* Now copy in the replacement text 'to' at the position of
               the match. Adjust the source pointer by the text we replaced.
               Adjust the destination pointer by the amount of replacement
               text. */
            memmove(dst, to, tolen);
            src += fromlen;
            dst += tolen;

        }
        else{ /* No match found. */
            /* Copy any remaining part of the string, including the null character */
            strcpy(dst, src);
            break;
        }

      } /* End of while() */
  return value;
} /* End of find_and_replace() */




/** Removes every instance of ':' in the supplied string.
 * @warning the supplied buffer is modified by this function. Whenever a
 * colon is found, the rest of the string is moved one position to the left
 * so the colon gets overwritten. */
int removecolon(char *string){
    return removechar(string, ':');
}/* End of removecolon() */


/** This function returns a string containing the hexdump of the supplied
  * buffer. It uses current locale to determine if a character is printable or
  * not. It prints 73char+\n wide lines like these:

0000   e8 60 65 86 d7 86 6d 30  35 97 54 87 ff 67 05 9e  .`e...m05.T..g..
0010   07 5a 98 c0 ea ad 50 d2  62 4f 7b ff e1 34 f8 fc  .Z....P.bO{..4..
0020   c4 84 0a 6a 39 ad 3c 10  63 b2 22 c4 24 40 f4 b1  ...j9.<.c.".$@..

  * The lines look basically like Wireshark's hex dump.
  * WARNING: This function returs a pointer to a DINAMICALLY allocated buffer
  * that the caller is supposed to free(). */
char *hexdump(const u8 *cp, u32 length){
  static char asciify[257];          /* Stores character table           */
  int asc_init=0;                    /* Flag to generate table only once */
  u32 i=0, hex=0, asc=0;             /* Array indexes                    */
  u32 line_count=0;                  /* For byte count at line start     */
  char *current_line=NULL;           /* Current line to write            */
  char *buffer=NULL;                 /* Dynamic buffer we return         */
  #define LINE_LEN 74                /* Lenght of printed line           */
  char line2print[LINE_LEN];         /* Stores current line              */
  char printbyte[16];                /* For byte conversion              */
  memset(line2print, ' ', LINE_LEN); /* We fill the line with spaces     */

  /* On the first run, generate a list of nice printable characters
   * (according to current locale) */
  if( asc_init==0){
      asc_init=1;
      for(i=0; i<256; i++){
        if( isalnum(i) || isdigit(i) || ispunct(i) ){ asciify[i]=i; }
        else{ asciify[i]='.'; }
      }
  }
  /* Allocate enough space to print the hex dump */
  int bytes2alloc=(length%16==0)? (1 + LINE_LEN * (length/16)) : (1 + LINE_LEN * (1+(length/16))) ;
  buffer=(char *)calloc(bytes2alloc, 1);
  if(buffer==NULL)
    fatal(OUT_2, "calloc() error. Not enough memory.");
  current_line=buffer;
#define HEX_START 7
#define ASC_START 57
/* This is how or line looks like.
0000   00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  .`e...m05.T..g..[\n]
01234567890123456789012345678901234567890123456789012345678901234567890123
0         1         2         3         4         5         6         7
       ^                                                 ^               ^
       |                                                 |               |
    HEX_START                                        ASC_START        Newline
*/
  i=0;
  while( i < length ){
    memset(line2print, ' ', LINE_LEN); /* Fill line with spaces */
    sprintf(line2print, "%04x", (16*line_count++) % 0xFFFF); /* Add line No.*/
    line2print[4]=' '; /* Replace the '\0' inserted by sprintf() with a space */
    hex=HEX_START;  asc=ASC_START;
    do { /* Print 16 bytes in both hex and ascii */
		if (i%16 == 8) hex++; /* Insert space every 8 bytes */
        sprintf(printbyte,"%02x", cp[i]);/* First print the hex number */
        line2print[hex++]=printbyte[0];
        line2print[hex++]=printbyte[1];
        line2print[hex++]=' ';
        line2print[asc++]=asciify[ cp[i] ]; /* Then print its ASCII equivalent */
		i++;
	} while (i < length && i%16 != 0);
    /* Copy line to output buffer */
    line2print[LINE_LEN-1]='\n';
    memcpy(current_line, line2print, LINE_LEN);
    current_line += LINE_LEN;
  }
  buffer[bytes2alloc-1]='\0';
  return buffer;
} /* End of hexdump() */


/** Prints the hexadecimal dump of the supplied buffer to standard output */
int print_hexdump(const u8 *cp, u32 length){
  char *str = hexdump(cp, length);
  if(str==NULL)
    return OP_FAILURE;
  else{
    printf("%s\n", str);
    free(str);
  }
  return OP_SUCCESS;
} /* End of print_hexdump() */


int print_hexdump(int vblevel, const u8 *cp, u32 length){
  char *str = hexdump(cp, length);
  if(str==NULL)
    return OP_FAILURE;
  else{
    output(vblevel, "%s\n", str);
    free(str);
  }
  return OP_SUCCESS;
} /* End of print_hexdump() */


int hex2str(int vblevel, const u8 *cp, u32 length){
  assert(cp!=NULL);
  for(u32 i=0; i<length; i++)
    output(vblevel, "%02x", cp[i]);
  return OP_SUCCESS;
}

int hex2strln(int vblevel, const u8 *cp, u32 length){
  hex2str(vblevel, cp, length);
  output(vblevel, "\n");
  return OP_SUCCESS;
}


/** Returns true if the specified filename exists on the current directory
 *  and can be opened for reading. Otherwise it returns false.
 *  @warning This function attemps to open the file using the fopen() system
 *  call. On success the file is closed inmmediatly using fclose(). */
bool fileExists(const char *filename){
  FILE *file=NULL;
  file = fopen(filename, "r");
  if ( file == NULL ){
    return false;
  }else{
    fclose(file);
     return true;
  }
} /* End of fileExists() */


/** Removes duplicate whitespace from the supplied buffer.
 * @warning: to perform this task, a search&replace for "  " to " " is
 * done a thousand time. It may not be enough for some cases (like a
 * buffer that contains thousands of whitespaces), but should do the
 * trick for normal usage. */
int remove_duplicate_whitespace(char *buffer){
 int times=1000;
 int bufflen=0;
 char *aux=NULL;
 if(buffer==NULL)
    return OP_FAILURE;
 if ( (bufflen=strlen(buffer)) <= 0)
    return OP_FAILURE;

    /* Hack to remove consecutive whitespaces. The find_and_replace() function
    * is run several times (1000) 'cause otherwise it only does one pass,
    * just removing half of the spaces. */
    while(times--){
        aux=find_and_replace(buffer, "  ", " ");
        if(aux==NULL)
            return OP_FAILURE;
        else{
            strncpy(buffer, aux, bufflen);
            free(aux);
        }
    }
    return OP_SUCCESS;
} /* End of remove_duplicate_whitespace() */


/** Tokenize the supplied "buffer" based on the occurences of "separator".
  * When two consecutive separators are found, NO empty token is returned.
  * This is, when parsing uc3m,,2009,10,12,,FIN with separator==",", the
  * tokenlist array will contain:
  *
  * tokenslist[0]="uc3m"
  * tokenslist[1]="2009"
  * tokenslist[2]="10"
  * tokenslist[3]="12"
  * tokenslist[4]="FIN"
  *
  * @warning This function CHANGES the supplied buffer. Make a copy of
  * it before calling this function! */
int tokenize(const char *separator, char *buffer, size_t bufferlen, char **tokenlist, size_t tokenlistsize){
 char *start_of_word=buffer;
 char *curr_pnt=buffer;
 size_t curr_token=0;
 if(separator==NULL || buffer==NULL || tokenlist==NULL)
	fatal(OUT_2, "tokenize(): NULL parameter");

  //"0123456789012345678901234567890123456789012345
  //"thisstringXYZandanotherstringXYZanthelastone0"
             //|

  for(u32 i=0; i<bufferlen; i++){

	  if( !strncmp(curr_pnt, separator, strlen(separator) ) ){
		 memset(curr_pnt, 0, strlen(separator) );

		 if(curr_token>=tokenlistsize)
			break;
		 else if( strlen(start_of_word) > 1)
			tokenlist[curr_token++]=start_of_word;

		 start_of_word=curr_pnt+strlen(separator);
		 curr_pnt+=strlen(separator);
		 i += (strlen(separator)-1);
	  }else{
		curr_pnt++;
	  }

	}

	if( strlen(start_of_word) > 0 )
		tokenlist[curr_token++]=start_of_word;

  ///* If we didn't find any delimiter, store the original string as the only token */
  //if(curr_token==0){
	//curr_token++;
  //}
  return curr_token;
} /* End of tokenize() */


/** Tokenize the supplied "buffer" based on the occurences of indivual
  * characters contained in "separator". The behaviour is the same as
  * in strtok, this is, if a separator like "*=%" is supplied, when
  * parsing this string "this*is=a=string%with*multiple*delimiters",
  * the function would return:
  *
  * tokenslist[0]="this"
  * tokenslist[1]="is"
  * tokenslist[2]="a"
  * tokenslist[3]="string"
  * tokenslist[4]="with"
  * tokenslist[5]="multiple"
  * tokenslist[6]="delimiters"
  *
  * @warning This function CHANGES the supplied buffer. Make a copy of
  * it before calling this function! */
int tokenize_single_tokens(const char *separator, char *buffer, char **tokenlist, size_t tokenlistsize){
  char *token=NULL;               /* Stores current strtok_r token */
  char *state = NULL;             /* Used for reentrancy reasons */
  size_t total_tokens=0;
  if(separator==NULL || buffer==NULL || tokenlist==NULL)
	fatal(OUT_2, "tokenize(): NULL parameter");
  for (token=strtok_r(buffer,separator, &state); token!=NULL && total_tokens<tokenlistsize; token=strtok_r(NULL, separator, &state) )
     tokenlist[total_tokens++]=token;
  return total_tokens;
} /* End of tokenize_single_tokens() */


/** Tokenize the supplied "buffer" based on the occurences of "separator".
  * When two consecutive separators are found, EMPTY tokens ARE returned.
  * This is, when parsing uc3m,,2009,10,12,,FIN with separator==",", the
  * tokenlist array will contain:
  *
  * tokenslist[0]="uc3m"
  * tokenslist[1]=""
  * tokenslist[2]="2009"
  * tokenslist[3]="10"
  * tokenslist[4]="12"
  * tokenslist[5]=""
  * tokenslist[6]="FIN"
  *
  * @warning This function CHANGES the supplied buffer. Make a copy of
  * it before calling this function! */
int tokenize_empty_tokens(const char *separator, char *buffer, size_t bufferlen, char **tokenlist, size_t tokenlistsize){

 char *start_of_word=buffer;
 char *curr_pnt=buffer;
 size_t curr_token=0;
 if(separator==NULL || buffer==NULL || tokenlist==NULL)
	fatal(OUT_2, "tokenize(): NULL parameter");

  //"0123456789012345678901234567890123456789012345
  //"thisstringXYZandanotherstringXYZanthelastone0"
             //|

  for(u32 i=0; i<bufferlen; i++){

	  if( !strncmp(curr_pnt, separator, strlen(separator) ) ){
		 memset(curr_pnt, 0, strlen(separator) );

		 if(curr_token>=tokenlistsize)
			break;
		 else
			tokenlist[curr_token++]=start_of_word;

		 start_of_word=curr_pnt+strlen(separator);
		 curr_pnt+=strlen(separator);
		 i += (strlen(separator)-1);
	  }else{
		curr_pnt++;
	  }

	}

	if( strlen(start_of_word) > 0 )
		tokenlist[curr_token++]=start_of_word;

  ///* If we didn't find any delimiter, store the original string as the only token */
  //if(curr_token==0){
	//curr_token++;
  //}
  return curr_token;
} /* End of tokenize_empty_tokens() */


/** @warning This function is CASE INSENSITIVE */
bool starts_with(const char *string, const char *start){
    if(string==NULL || start==NULL)
	fatal(OUT_2, "startsWith(): NULL parameter.");
    if( !strncasecmp(string, start, strlen(start) ) )
	return true;
    else
	return false;
} /* End of startsWith() */


/** Returns the number of times that the "test" character occurs in
  * the supplied buffer. */
int char_occurrences(const char *buffer, char test){
  int times=0;
  if(buffer==NULL)
    return 0;
  for(u32 i=0; i<strlen(buffer); i++)
    if( buffer[i]==test)
        times++;
   return times;
} /* End of char_occurrences() */


/** This function takes a buffer and removes all the crappy line spans
  * so it is left in a decent way to parse it.
    First-Field: this is the value of the first field<cr><lf>
    Second-Field: this is the value<cr><lf>
        of the<cr><lf>
        second field<cr><lf>
    <cr><lf>
 */
int unspan(char *header){
  char *aux=NULL;
  if( (aux=find_and_replace(header, "\r\n ", " ")) != NULL ){
    strcpy(header, aux);
    free(aux);
  }
  if( (aux=find_and_replace(header, "\r\n\t", " ")) != NULL ){
    strcpy(header, aux);
    free(aux);
  }
  if( (aux=find_and_replace(header, "\t", " ")) != NULL ){
    strcpy(header, aux);
    free(aux);
  }
  remove_duplicate_whitespace(header);
  return OP_SUCCESS;
} /* End of unspan() */


/** The following two functions have been inspired in code found in
  * http://local.wasp.uwa.edu.au/~pbourke/dataformats/endian/*/
u16 endian_swap(u16 val){
  u16 x=val;
  x = (x>>8) | (x<<8);
  return x;
} /* End of endian_swap() */

u32 endian_swap(u32 val){
  u32 x=val;
  x = (x>>24) | ((x<<8) & 0x00FF0000) |
      ((x>>8) & 0x0000FF00) | (x<<24);
  return x;
} /* End of endian_swap() */

u16 toLittleEndian(u16 val){
 u16 aux=val;
 aux=htons(aux);
 aux=endian_swap(aux);
 return aux;
} /* End of toLittleEndian() */


u32 toLittleEndian(u32 val){
 u32 aux=val;
 aux=htonl(aux);
 aux=endian_swap(aux);
 return aux;
} /* End of toLittleEndian() */

#define HOST_LITTLE_ENDIAN 0
#define HOST_BIG_ENDIAN    1

int testEndianness(){
  int i=1;
  char *p = (char *) &i;
  if (p[0] == 1) /* LSB is contained in the lowest address */
    return HOST_LITTLE_ENDIAN;
  else
    return HOST_BIG_ENDIAN;
} /* End of testEndianness() */


/* Little endian to host short */
u16 ltohs(u16 little){
  if( testEndianness()==HOST_LITTLE_ENDIAN )
    return little;
  else
    return endian_swap(little);
} /* End of ltohs() */


/* Little endian to host long */
u32 ltohl(u32 little){
  if( testEndianness()==HOST_LITTLE_ENDIAN )
    return little;
  else
    return endian_swap(little);
} /* End of ltohl() */


/* Host short to little endian */
u16 htols(u16 host){
  if( testEndianness()==HOST_LITTLE_ENDIAN )
    return host;
  else
    return endian_swap(host);
} /* End of htols() */


/* Host long to little endian */
u32 htoll(u32 host){
  if( testEndianness()==HOST_LITTLE_ENDIAN )
    return host;
  else
    return endian_swap(host);
} /* End of htoll() */


int strcmp_wildcarded(const char *s1, const char *s2, const char wildcard){
    int s1_len;
    int s2_len;
    int min_len;
    int result=0;

    if(s1==NULL || s2==NULL)
        fatal(OUT_2, "strcmpwildcard(): NULL parameter supplied");

    s1_len = strlen(s1);
    s2_len = strlen(s2);
    min_len = (s1_len<s2_len) ? s1_len : s2_len;
    if(s1_len!=s2_len)
        result=(s1_len<s2_len) ? -1 : 1;

    for(int i=0; i<min_len; i++){
        if(s1[i]!=s2[i] && s1[i]!=wildcard && s2[i]!=wildcard){
            result = (s1[i]<s2[i]) ? -1 : 1;
            break;
        }
    }
    if(result==0 && s1_len==s2_len)
        return 0;
    else
        return result;
}


int strncmp_wildcarded(const char *s1, const char *s2, const char wildcard, int n){
    int s1_len;
    int s2_len;
    int min_len;
    int result=0;

    if(s1==NULL || s2==NULL)
        fatal(OUT_2, "strcmpwildcard(): NULL parameter supplied");

    s1_len = strlen(s1);
    s2_len = strlen(s2);
    min_len = (s1_len<s2_len) ? s1_len : s2_len;

    if( min_len < n )
        result = -1;

    for(int i=0; i<min_len && i<n; i++){
        if(s1[i]!=s2[i] && s1[i]!=wildcard && s2[i]!=wildcard){
            result = (s1[i]<s2[i]) ? -1 : 1;
            break;
        }
    }
    return result;
}


bool contains_wildcarded(const char *string, const char *substring, const char wildcard){
  for(u32 i=0; i<strlen(string); i++){
    if( strncmp_wildcarded(string+i, substring, wildcard, strlen(substring)) == 0 )
        return true;
   }
    return false;
} /* End of contains_wildcarded() */


int strcmp_wildcarded(const char *s1, const char *s2){
    return strcmp_wildcarded(s1, s2, '*');
} /* End of strcmp_wildcarded() */


bool contains_wildcarded(const char *string, const char *substring){
    return contains_wildcarded(string, substring, '*');
} /* End of contains_wildcarded() */


/* Inspired by nmap's ll2shortascii() function. */
char *size2ascii(u32 bytes, char *buff, int bufflen) {
  if (bufflen < 2 || buff==NULL){
    fatal(OUT_2, "size2ascii(): NULL parameter supplied");
  }else if( bytes > 1073741824 ){
    snprintf(buff, bufflen, "%.2fGB", bytes / 1073741824.0);
  }else if (bytes > 1048576){
    snprintf(buff, bufflen, "%.2fMB", bytes / 1048576.0);
  }else if (bytes > 1024){
    snprintf(buff, bufflen, "%.2fKB", bytes / 1024.0);
  }else{
    snprintf(buff, bufflen, "%uB", (u32) bytes);
  }
  return buff;
} /* End of size2ascii() */

const char *cipher2ascii(int cipher){
    switch(cipher){
        case ALG_BLOWFISH:
            return "Blowfish";
        break;
        case ALG_TWOFISH:
            return "Twofish";
        break;
        case ALG_RIJNDAEL:
            return "Rijndael/AES";
        break;
        case ALG_SERPENT:
            return "Serpent";
        break;
        default:
            return "Unknown";
        break;
    }
    return "Unknown";
} /* End of cipher2ascii() */


const char *chipermode2ascii(int mode){
    switch(mode){
        case BLOCK_MODE_ECB:
            return "ECB";
        break;
        case BLOCK_MODE_CBC:
            return "CBC";
        break;
        case BLOCK_MODE_OFB:
            return "OFB";
        break;
        case BLOCK_MODE_CFB:
            return "CFB";
        break;
        default:
            return "Unknown";
        break;
    }
    return "Unknown";
} /* End of ciphermode2ascii() */


/** Receives a MAC address as a string of format 00:13:01:e6:c7:ae or
 *  00-13-01-e6-c7-ae and stores in targetbuff the 6 corresponding bytes.
 *  The "txt" parameter may take the special value "rand" or "random",
 *  in which case, 6 random bytes will be stored in "targetbuff".
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.
 *  Buffer targetbuff is NOT modified if "txt" does not have the propper
 *  format */
int parseMAC(const char *txt, u8 *targetbuff){
    u8 mac_data[6];
    char tmphex[3];
    int i=0, j=0;

   if( txt==NULL || targetbuff==NULL )
    return OP_FAILURE;

    /* Set it to FF:FF:FF:FF:FF:FF if user chose broadcast */
    if( !strcasecmp(optarg, "broadcast") || !strcasecmp(optarg, "bcast") ){
        memset(targetbuff, 0xFF, 6);
        return OP_SUCCESS;
    }

   /* Array should look like  00:13:01:e6:c7:ae  or  00-13-01-e6-c7-ae
      Array positions:        01234567890123456      01234567890123456  */
   if( strlen(txt)!=17 )
     return OP_FAILURE;
   /* Check MAC has the correct ':' or '-' characters */
   if( (txt[2]!=':' && txt[2]!='-') || (txt[5]!=':' && txt[5]!='-')   ||
       (txt[8]!=':' && txt[8]!='-') || (txt[11]!=':' && txt[11]!='-') ||
       (txt[14]!=':' && txt[14]!='-') )
        return OP_FAILURE;

   /* Convert txt into actual bytes */
   for(i=0, j=0; i<6; i++, j+=3 ){

    if( !isxdigit(txt[j]) || !isxdigit(txt[j+1]) )
        return OP_FAILURE;
    tmphex[0] = txt[j];
    tmphex[1] = txt[j+1];
    tmphex[2] = '\0';
    mac_data[i] = (u8) strtol(tmphex, NULL, 16);
   }
   memcpy(targetbuff, mac_data, 6);
  return OP_SUCCESS;
} /* End of parseMAC() */


/* This function has been taken fron LIBDNET @todo TODO: Check this */
int ip_cksum_add(const void *buf, size_t len, int cksum){
	uint16_t *sp = (uint16_t *)buf;
	int n, sn;

	sn = (int) len / 2;
	n = (sn + 15) / 16;

	/* XXX - unroll loop using Duff's device. */
	switch (sn % 16) {
	case 0:	do {
		cksum += *sp++;
	case 15:
		cksum += *sp++;
	case 14:
		cksum += *sp++;
	case 13:
		cksum += *sp++;
	case 12:
		cksum += *sp++;
	case 11:
		cksum += *sp++;
	case 10:
		cksum += *sp++;
	case 9:
		cksum += *sp++;
	case 8:
		cksum += *sp++;
	case 7:
		cksum += *sp++;
	case 6:
		cksum += *sp++;
	case 5:
		cksum += *sp++;
	case 4:
		cksum += *sp++;
	case 3:
		cksum += *sp++;
	case 2:
		cksum += *sp++;
	case 1:
		cksum += *sp++;
		} while (--n > 0);
	}
	if (len & 1)
		cksum += htons(*(u_char *)sp << 8);

	return (cksum);
}


 #define ip_cksum_carry(x) (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))
/* This function has been taken from the Nmap Security Scanner (insecure.org) @todo TODO: Check this */
/* For computing TCP/UDP checksums, see RFC 1071 and TCP/IP Illustrated
   sections 3.2, 11.3, and 17.3. */
unsigned short tcpudp_cksum(const struct in_addr *src, const struct in_addr *dst, u8 proto, u16 len, const void *hstart){
  struct pseudo {
    struct in_addr src;
    struct in_addr dst;
    u8 zero;
    u8 proto;
    u16 length;
  } hdr;
  int sum;

  hdr.src = *src;
  hdr.dst = *dst;
  hdr.zero = 0;
  hdr.proto = proto;
  hdr.length = htons(len);

  /* Get the ones'-complement sum of the pseudo-header. */
  sum = ip_cksum_add(&hdr, sizeof(hdr), 0);
  /* Add it to the sum of the packet. */
  sum = ip_cksum_add(hstart, len, sum);

  /* Fold in the carry, take the complement, and return. */
  return ip_cksum_carry(sum);
}


/** This function is a bit tricky. The thing is that some engineer had
 * the brilliant idea to remove IP_HDRINCL support in IPv6. As a result, it's
 * a big pain in the ass to create raw IPv6 headers because we can only do it
 * if we are sending packets at raw Ethernet level. So if we want our own IPv6
 * header (for source IP spoofing, etc) we have to do things like determine
 * source and dest MAC addresses (this is even more complicated in IPv6 than
 * in IPv4 because we don't have ARP anymore, we have to use something new, the
 * NDP, Neighbour Discovery Protocol.)
 * So the thing is that, if the user does not want to play with the IPv6 header,
 * why bother with all that link layer work? So what we do is create raw
 * transport layer packets and then send them through a raw IPv6 socket. The
 * socket will encapsulate our packets into a nice clean IPv6 header
 * automatically so we don't have to worry about low level details anymore.
 *
 * So this function basically takes a raw IPv6 socket descriptor and then tries
 * to set some basic parameters (like Hop Limit) using setsockopt() calls.
 * It always returns OP_SUCCESS. However, if errors are found, they are printed
 * (QT_2 level) using outError();
 * */
int set_up_socket_ipv6(int rawfd, char *device){
    int offset = 16;
    
    /* Hop Limit */
    int hoplimit=DEFAULT_IPv6_TTL;

    if( setsockopt(rawfd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (char *)&hoplimit, sizeof(hoplimit)) != 0 )
        warning(OUT_2, "Couldn't set Unicast Hop Limit on IPv6 socket.\n");
    if( setsockopt(rawfd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (char *)&hoplimit, sizeof(hoplimit)) != 0 )
        warning(OUT_2, "Couldn't set Multicast Hop Limit on IPv6 socket.\n");

    /* Transport layer checksum */
    /* This is totally crazy. We have to tell the kernel EXPLICITLY that we
     * want it to set the TCP/UDP checksum for us. Why the hell is this the
     * default behaviour if it's so difficult to get the IPv6 source address?
     */
    if( setsockopt (rawfd, IPPROTO_IPV6, IPV6_CHECKSUM, (char *)&offset, sizeof(offset)) != 0 )
        warning(OUT_2, "Couldn't set IPV6_CHECKSUM option on IPv6 socket.\n");

    /* Bind IPv6 socket to a specific network interface */
    if ( device!=NULL )  {
        /* It seems that SO_BINDTODEVICE only work on linux */
        //#ifdef LINUX
        if (setsockopt(rawfd, SOL_SOCKET, SO_BINDTODEVICE, device, strlen(device)+1) == -1) {
            warning(OUT_2, "Error binding IPv6 socket to device %s\n", device );
        }
	//#endif
    }

    return OP_SUCCESS;

} /* End of doIPv6ThroughSocket() */


u16 tcp_sum(unsigned char *tcphdr, u32 hdrlen, struct in_addr src_ip, struct in_addr dst_ip){
  tcp_phdr_t ph; /* TCP Pseudoheader, needed to compute the TCP Packet checksum */
  char block[65525]; /* TCP Pseudoheader + TCP actual header used for computing the checksum */
  memcpy(block, tcphdr, hdrlen);
  ph.src=src_ip;
  ph.dst=dst_ip;
  ph.zero=0;
  ph.protocol=IPPROTO_TCP;
  ph.tcplen=htons(hdrlen);
  memcpy(block+hdrlen, &ph, sizeof(tcp_phdr_t));
  /* Compute the TCP checksum as described in RFC 793 */
  return in_cksum((unsigned short *)(block), hdrlen+sizeof(tcp_phdr_t));
} /* End of tcp_sum() */


u32 field2len(int field){
    switch(field){
        case COVERT_IP_TOS:
            return 1;
        break;
        case COVERT_IP_ID:
        case COVERT_TCP_SPORT:
        case COVERT_TCP_DPORT:
        case COVERT_TCP_WINDOW:
        case COVERT_TCP_URP:
        case COVERT_TCP_CSUM:
            return 2;
        break;
        case COVERT_TCP_ACK:
        case COVERT_TCP_SEQ:
            return 4;
        break;
        default:
            fatal(OUT_2, "%s() Invalid parameter supplied.", __func__);
        break;
    }
    return 0;
}




/** Returns the length of data-link-layer header based on Data-Link Type value
  * provided by libpcap.                                                      */
int get_link_header_length(int dlt_type){
 switch(dlt_type){

    #ifdef DLT_LOOP
    case DLT_LOOP:       /* Loopback                                */
        return 4;
    break;
    #endif

    case DLT_NULL:       /* Loopback                                */
        return 4;
    break;

    case DLT_EN10MB:     /* IEEE 802.3 (Ethernet) 10/100/1000       */
        return 14;
    break;

    case DLT_IEEE802:    /* IEEE 802.11x (wi-fi)                    */
		return 22;
    break;

    case DLT_FDDI:       /* FDDI (Fiber Distributed Data Interface) */
        return 21;
    break;

//    case DLT_PPP:         /* PPP (Point-to-Point Protocol)        */
//        return 0;
//    break;                /* Does anybody know how to handle PPP? */

    case DLT_PPP_ETHER:  /* PPPoE (PPP over Ethernet)               */
        return 20;
    break;

    default:             /* Unknown DLT Type!                       */
        return -1;
    break;
 }
 return -1;
} /* End of get_header_length() */



bool isinlist_u8(u8 *list, size_t listlen, u8 testvalue){
  if(list==NULL || listlen==0)
    return false;
  for(size_t i=0; i<listlen; i++){
    if(list[i]==testvalue)
        return true;
  }
  return false;
}


bool isinlist_u16(u16 *list, size_t listlen, u16 testvalue){
  if(list==NULL || listlen==0)
    return false;
  for(size_t i=0; i<listlen; i++){
    if(list[i]==testvalue)
        return true;
  }
  return false;
}


bool isinlist_u32(u32 *list, size_t listlen, u32 testvalue){
  if(list==NULL || listlen==0)
    return false;
  for(size_t i=0; i<listlen; i++){
    if(list[i]==testvalue)
        return true;
  }
  return false;
}



bool isinlist_size_t(size_t *list, size_t listlen, size_t testvalue){
  if(list==NULL || listlen==0)
    return false;
  for(size_t i=0; i<listlen; i++){
    if(list[i]==testvalue)
        return true;
  }
  return false;
}


int indexcmp(const void *left, const void *right){
  size_t *a=(size_t *)left;
  size_t *b=(size_t *)right;
  return ((int)(*a) - (int)(*b));
}


/** Returns a list of unique, random, matrix indices. Returned indices 
  * are returned ordered (smallest first).*/
size_t *generate_unique_indexes(size_t number, size_t max){
  size_t *array;
  if(number>max || number==0 || max==0)
      return NULL;
  
  if((array=(size_t *)calloc(number, sizeof(size_t)))==NULL)
    return NULL;
    
  for(size_t i=0; i<number; i++){
    array[i]=o.rand.getRandom32() % (max+1);
  }

  replace_duplicated_indexes(array, number, max);
  qsort(array, number, sizeof(size_t), indexcmp);  
  return array;
}









int replace_duplicated_indexes(size_t *list, size_t list_len, size_t maxval){
    for(size_t i=0; i<list_len; i++){
        for(size_t j=i+1; j<list_len; j++){
            if(list[i]==list[j] && i!=j){             
                while(1){
                    list[j]=o.rand.getRandom32() % (maxval+1);
                    bool duplicate=false;
                    for(size_t z=0; z<list_len; z++){
                        if(list[z]==list[j] && z!=j){
                            duplicate=true;
                            break;
                        }
                    }
                    if(!duplicate)
                        break;
                }
            }
        }
    }
    return OP_SUCCESS;
}


int replace_duplicated_u16(u16 *list, size_t list_len, u16 maxval, u16 *excludevalues, size_t evalueslen){
    for(size_t i=0; i<list_len; i++){
        for(size_t j=i+1; j<list_len; j++){
            if(list[i]==list[j] && i!=j){             
                while(1){
                    while(1){
                        /* Make sure generated port in not excluded or zero */
                        list[j]=o.rand.getRandom32() % (maxval+1);
                        if( !isinlist_u16(excludevalues, evalueslen, list[j]) && list[j]!=0 )
                            break;
                    }
                    bool duplicate=false;
                    for(size_t z=0; z<list_len; z++){
                        if(excludevalues==NULL){
                            if(list[z]==list[j] && z!=j){
                                duplicate=true;
                                break;
                            }
                        }else{
                            if(list[z]==list[j] && z!=j){
                                duplicate=true;
                                break;
                             }
                        }
                    }
                    if(!duplicate)
                        break;
                }
            }
        }
    }
    return OP_SUCCESS;
}




/*
Check the functions above. replace_duplicated_indexes should generate new numbers
if duplicates are found. The print statement is just for testing. IN theory
we should never have output for the same i and j values. 
--------------------------------------------------------------------------------
ssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss
--------------------------------------------------------------------------------
*/
/** Returns a list of random TCP port numbers that includes the supplied port 
  * list. The returned buffer contains howmany+toinclude_len port numbers and 
  * it is guaranteed to contain the ports specified in list "toinclude".                                            */
/** @todo TODO: Rewrite this function to generate the same random portlist for a given
   inclusion list. Otherwise an attacker may be able to identify the real port
   sequence, capturing a few authentications. */
tcp_port_t *generate_random_portlist(size_t howmany, tcp_port_t *toinclude, size_t toinclude_len){
  tcp_port_t *portlist=NULL;
  size_t total_ports;

  /* Seed the randomizer */
  if(toinclude!=NULL){ /* TODO: Use decent random numbers here. */
     srandom( *((unsigned int *)toinclude) );
  }else{
     toinclude_len=0;
     srandom(0xA1D4B436);
  }
 
  /* Allocate space for the ports */
  total_ports=howmany+toinclude_len;
  if ( (portlist=(tcp_port_t *)calloc(total_ports, sizeof(tcp_port_t))) == NULL)
    return NULL;
  
  /* Generate random ports */
  for(size_t i=0; i<total_ports; i++){
      while(1){
        portlist[i]=o.rand.getRandom16();
        if( !isinlist_u16(toinclude, toinclude_len, portlist[i]) && portlist[i]!=0 )
            break;        
    }
  }
  o.rand.getRandomData(portlist, total_ports*sizeof(tcp_port_t));

  /* Insert ports from the include list */
  size_t *indexes=generate_unique_indexes(toinclude_len, total_ports-1);
  assert(indexes!=NULL);
  for(size_t i=0; i<toinclude_len; i++){
    portlist[ indexes[i] ] = toinclude[i];
  }

 /* Remove duplicates */
 replace_duplicated_u16(portlist, total_ports, 65535, toinclude, toinclude_len );
 
 return portlist;
} /* End of generate_random_portlist() */






/** Takes a string "src" and stores an URL-Encoded version of it
 * in supplied buffer "to". The values are hard coded and have been
 * taken from   http://www.permadi.com/tutorial/urlEncoding/
 * TODO: this function has hard-coded values. It needs to be expanded
 * so all possible values are encoded. */
int url_encode(const char *src, char *to, size_t to_len){
  char *aux=NULL;
  assert(src!=NULL && to!=NULL);

  if(to_len < strlen(src))
    return OP_FAILURE;

  #define ENCODE_TOKENS 15
  /* Order matters, think twice before changing it! */
  const char *src_tokens[ENCODE_TOKENS]={  "%",  ";",  "?",  "/",  ":",  "#",  "&",  "=",  "+",  "$",  ",",  " ",  "<",  ">",  "~"};
  const char *dst_tokens[ENCODE_TOKENS]={"%25","%3B","%3F","%2F","%3A","%23","%24","%3D","%2B","%26","%2C","%20","%3C","%3E","%7E"};

  strncpy(to, src, to_len);

  for(int i=0; i<ENCODE_TOKENS; i++){
    aux=find_and_replace(to, src_tokens[i], dst_tokens[i]);
    strncpy(to, aux, to_len);
    free(aux);
  }
  return OP_SUCCESS;
} /* End of url_encode() */




/** Takes a string "src" and stores an URL-Decoded version of it
 * in supplied buffer "to". The values are hard coded and have been
 * taken from   http://www.permadi.com/tutorial/urlEncoding/
 * TODO: this function has hard-coded values. It needs to be expanded
 * so all possible values are encoded. */
int url_decode(const char *src, char *to, size_t to_len){
  char *aux=NULL;
  assert(src!=NULL && to!=NULL);

  #define DECODE_TOKENS 16
  /* Order matters, do not to change it! */
  const char *src_tokens[DECODE_TOKENS]={"+", "%20", "%3B","%3F","%2F","%3A","%23","%24","%3D","%26","%2C","%3C","%3E","%7E", "%2B","%25"};
  const char *dst_tokens[DECODE_TOKENS]={" ",   " ",   ";",  "?",  "/",  ":",  "#",  "&",  "=",  "$",  ",",  "<",  ">",  "~",  "+", "%",};

  strncpy(to, src, to_len);
  for(int i=0; i<ENCODE_TOKENS; i++){
    aux=find_and_replace(to, src_tokens[i], dst_tokens[i]);
    strncpy(to, aux, to_len);
    free(aux);
  }
  return OP_SUCCESS;
} /* End of url_decode() */



size_t read_until(int fd, char *buff, size_t bufflen, const char *delimiter){
  int n=0;
  size_t bytes_read=0;
  char *aux=buff;
  memset(buff, 0, bufflen);
  while( (n=read(fd, aux, 1)) > 0 && !contains(buff, delimiter) && bytes_read<bufflen ){
    aux++;
    bytes_read++;
  }
  return bytes_read+1;
} /* End of readUtil() */


int read_password(char *dest, size_t dest_len, size_t *final_read_bytes) {
  struct termios old_settings;
  struct termios new_settings;
  sigset_t old_signalset;
  sigset_t new_signalset;
  size_t bytes_read=0;
  char c='\0';

  /* Grab current terminal settings */
  if (tcgetattr(fileno(stdin), &old_settings) != 0)
    return OP_FAILURE;

  /* Block SIGINT while this function runs (otherwise the terminal may
   * be left in an inconsistent state). */
  sigemptyset(&old_signalset);
  sigemptyset(&new_signalset);
  sigaddset(&new_signalset, SIGINT);
  sigprocmask(SIG_BLOCK, &new_signalset, &old_signalset);
  
  /* Play around with the flags */
  new_settings = old_settings;
  new_settings.c_lflag &= ~ECHO || ECHOCTL;

  /* Set the new settings */
  if (tcsetattr(fileno(stdin), TCSAFLUSH, &new_settings) != 0)
    return OP_FAILURE;

  /* Read the password. */
  while((c=getchar())!='\n' && ((bytes_read+1)<dest_len)){
    if(c =='\b'){
        if (bytes_read > 0) {
            bytes_read--;
            printf("\b \b");
        }
    }else{
        dest[bytes_read++] = c;
        printf("*");
    }
  }
  printf("\n");
  dest[bytes_read] = '\0';

  /* Indicate how many bytes we have read */
  if(final_read_bytes!=NULL)
    *final_read_bytes=bytes_read;

  /* Restore terminal settings. */
  if( tcsetattr(fileno(stdin), TCSAFLUSH, &old_settings) != 0 )
    return OP_FAILURE;

  /* Restore signal set */
  sigprocmask(SIG_SETMASK, &old_signalset, NULL);

  return OP_SUCCESS;
} /* End of read_password() */
