
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

#include <netinet/in.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "ssh_cookie.h"


/** Tries to resolve the given name (or literal IP) into a sockaddr
  * structure.  should be AF_INET (for IPv4) or AF_INET6.  Returns 0
  * @param hostname is the name of the host that needs to be resolved.
  * @param ss is a pointer to a previously allocated sockaddr_strorage
  * structure. Note that the buffer pointed by ss does not have to be
  * able to hold sizeof(struct sockadd_storage) bytes. It is OK to
  * pass in a sockaddr_in or sockaddr_in6 casted to a sockaddr_storage
  * as long as you use the matching address family. However, be careful,
  * if you don't wanna take risks, just pass a buffer big enough to
  * hold sizeof(struct sockaddr_storage).
  * pass "struct sockaddr_in" structures casted as "sockaddr_storage".
  * @param sslen is a pointer to the variable where the size of the
  * sockaddr_storage for the resolved address will be stored.
  * @param family is the address family to be used for the resolution.
  * It MUST be one of AF_INET (for IPv4 resolution), AF_INET6 (for IPv6)
  * or AF_UNSPEC if you don't care whether the returned address is
  * in version 4 or 6.
  *
  * This code was originally taken from the Nmap Security Scanner source
  * code (http://nmap.org), and then modified by Luis MartinGarcia. */
static int resolve(const char *hostname, struct sockaddr_storage *ss, size_t *sslen, int family) {
  struct addrinfo hints;
  struct addrinfo *result=NULL;
  int rc=0;
  /* Input validation */
  if(ss==NULL || sslen==NULL){
    return -1;
  }else if( family!=AF_INET && family!=AF_INET6 && family!=AF_UNSPEC ){
    return -1;
  }
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = family;
  /* Resolve hostname */
  if( (rc=getaddrinfo(hostname, NULL, &hints, &result)) != 0 )
    return -1;
  if(result==NULL)
    return -1;
  /* This should never happen but, just in case, we check whether the
  * returned address fits into a the appropriate sockaddr_whatever */
  if(family==AF_INET){
    if( result->ai_addrlen > 0 && result->ai_addrlen > (int) sizeof(struct sockaddr_in) )
        return -1;
  }else if(family==AF_INET6){
    if( result->ai_addrlen > 0 && result->ai_addrlen > (int) sizeof(struct sockaddr_in6) )
        return -1;
  }else{ /* Family is AF_UNSPEC */
    if( result->ai_addrlen > 0 && result->ai_addrlen > (int) sizeof(struct sockaddr_storage) )
        return -1;
  }
  /* Store the result in user-supplied parameters */
  *sslen = result->ai_addrlen;
  memcpy(ss, result->ai_addr, *sslen);
  freeaddrinfo(result);
  return 0;
} /* End of resolve() */




/** This function takes a hostname and a port number and tries to establish
  * a TCP connection with that host. On success, it returns a socket descriptor
  * that can be used for data transmission. In case of failure it returns -1 */
static int do_tcp_connect(const char *hostname, u16 port, int addr_family){
  struct sockaddr_storage server_addr;
  size_t sslen=sizeof(struct sockaddr_storage);
  struct sockaddr_in6 *s6=(struct sockaddr_in6 *)&server_addr;
  struct sockaddr_in *s4=(struct sockaddr_in *)&server_addr;
  int sd=-1;
  memset(&server_addr, 0, sizeof(struct sockaddr_in));

  /* Verify received address family */
  if(addr_family!=AF_INET && addr_family!=AF_INET6){
    fprintf(stderr, "Bogus address family supplied.\n");
    exit(1);
  }

  /* Resolve host name */
  if( resolve(hostname, &server_addr, &sslen, addr_family)!=0 ){
    fprintf(stderr,"Unable to resolve supplied hostname (%s).\n", hostname);
        exit(1);
  }

  /* Acquire socket */
  if( (sd=socket(addr_family, SOCK_STREAM, IPPROTO_TCP))<0 ){
        fprintf(stderr,"Could not obtain AF_INET6 socket\n");
        exit(1);
  }

  if(addr_family==AF_INET6){
    s6->sin6_family=AF_INET6;
    s6->sin6_port=htons(port);
    s6->sin6_flowinfo=0;
    s6->sin6_scope_id=0;
  }else{
    s4->sin_family=AF_INET;
    s4->sin_port=htons(port);
  }

  /* Attempt to connect to the remote host */
  if ( connect(sd, (struct sockaddr *)&server_addr, sslen) != 0 ){
    fprintf(stderr,"Unable to perform connect() on %s:%d\n", hostname, port);
    close(sd);
    return -1;
  }
  return sd;
} /* End of do_tcp_connect() */



static int generic_cookie_request(u8 *cookie, u8 opcode){
  int sd=-1;
  u8 response=RESULT_FAILURE;
  if( (sd=do_tcp_connect(COOKIE_SERVER_ADDR, COOKIE_SERVER_PORT, COOKIE_SERVER_ADDR_FAMILY))<0 ){
    fprintf(stderr, "Couldn't establish connection to %s:%d", COOKIE_SERVER_ADDR,COOKIE_SERVER_PORT);
    return -1;
  }
  /* Send request */
  if( write(sd, &opcode, 1) < 1 )
      return -1;
  if( write(sd, cookie, COOKIE_LEN) < COOKIE_LEN )
      return -1;
  /* Receive response */
  if( read(sd, &response, 1) < 1)
      return -1;
  if(response==RESULT_SUCCESS)
      return 0;
  else
      return -1;
}


int server_insert_cookie(u8 *cookie){
  return generic_cookie_request(cookie, OP_SERVER_INSERT);
}


int server_verify_cookie(u8 *cookie){
  return generic_cookie_request(cookie, OP_SERVER_VERIFY);
}


int client_insert_cookie(u8 *cookie){
  return generic_cookie_request(cookie, OP_CLIENT_INSERT);
}


u8 *client_retrieve_cookie(){
  int sd=-1;
  u8 opcode=OP_CLIENT_RETRIEVE;
  u8 response=RESULT_FAILURE;
  static u8 cookie[COOKIE_LEN];
  if( (sd=do_tcp_connect(COOKIE_SERVER_ADDR, COOKIE_SERVER_PORT, COOKIE_SERVER_ADDR_FAMILY))<0 ){
    fprintf(stderr, "Couldn't establish connection to %s:%d", COOKIE_SERVER_ADDR,COOKIE_SERVER_PORT);
    return NULL;
  }
  /* Send request */
  if( write(sd, &opcode, 1) < 1 )
      return NULL;
  /* Receive response code */
  if( read(sd, &response, 1) < 1 )
      return NULL;
  if(response==RESULT_SUCCESS){
      if( read(sd, cookie, COOKIE_LEN)<COOKIE_LEN ){
          return NULL;
      }else{
          return cookie;
      }
  }else{
      return NULL;
  }
}