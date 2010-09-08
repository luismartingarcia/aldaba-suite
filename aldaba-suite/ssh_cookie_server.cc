
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
#include <vector>
using namespace std;

#include "ssh_cookie.h"

#define LISTEN_QUEUE_SIZE 5

vector<cookie_t> server_cookies;
vector<cookie_t> client_cookies;

/** Returns a socket suitable to be passed to accept() */
int get_listen_socket(int addr_family){
  int one=1;                 /**< Dummy var for setsockopt() call      */
  int master_sd=-1;          /**< Master socket. Server listens on it  */
  struct sockaddr_in server_addr4;  /**< For our own IPv4 address      */
  struct sockaddr_in6 server_addr6; /**< For our own IPv6 address      */
  int port = COOKIE_SERVER_PORT;

  /* Ignore SIGPIPE signal, received when a client disconnects suddenly and
   *data is sent to it before noticing. */
  #ifndef WIN32
    signal(SIGPIPE, SIG_IGN);
  #endif

  /* AF_INET6 */
  if( addr_family==AF_INET6 ){

    /* Obtain a regular TCP socket for IPv6 */
    if( (master_sd=socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP))<0 ){
        fprintf(stderr,"Could not obtain AF_INET6 socket\n");
        exit(1);
    }

    /* Set SO_REUSEADDR on socket so the bind does not fail if we had used
     * this port in a previous execution, not long ago. */
    if( setsockopt(master_sd, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(int))!=0 )
        fprintf(stderr, "Failed to set SO_REUSEADDR on master socket.\n");
      
    memset(&server_addr6, 0, sizeof(struct sockaddr_in6));
    server_addr6.sin6_addr = in6addr_loopback;
    server_addr6.sin6_family = AF_INET6;
    server_addr6.sin6_port = htons(port);
    server_addr6.sin6_flowinfo = 0;

    /* Bind to local address and the specified port */
    if( bind(master_sd, (struct sockaddr *)&server_addr6, sizeof(server_addr6)) != 0 ){
        fprintf(stderr,"Failed to bind to localhost address\n");
        exit(1);
    }else{
        printf("[+] Server bound to ::1\n");
    }

  /* AF_INET */
  }else{

    /* Obtain a regular TCP socket for IPv4 */
    if( (master_sd=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0 ){
        fprintf(stderr,"Could not obtain AF_INET socket\n");
        exit(1);
    }
        
    /* Set SO_REUSEADDR on socket so the bind does not fail if we had used
     * this port in a previous execution, not long ago. */
    if( setsockopt(master_sd, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(int))!=0 )
        fprintf(stderr, "Failed to set SO_REUSEADDR on master socket.\n");


    memset(&server_addr4, 0, sizeof(struct sockaddr_in));
    server_addr4.sin_family = AF_INET;
    server_addr4.sin_port = htons(port);
    //server_addr4.sin_addr.s_addr = INADDR_LOOPBACK ;
    server_addr4.sin_addr.s_addr = INADDR_ANY;
    /* Bind to local address and the specified port */
    if( bind(master_sd, (struct sockaddr *)&server_addr4, sizeof(server_addr4)) != 0 ){
        fprintf(stderr,"Failed to bind to localhost address\n");
        exit(1);
    }else{
        printf("[+] Server bound to 127.0.0.1\n");
    }
  }

   /* Listen for incoming TCP connections... */
   if( listen(master_sd, LISTEN_QUEUE_SIZE) != 0 ){
       fprintf(stderr, "Failed to listen() on port %d (%s)", port, strerror(errno));
   }
  return master_sd;
} /* End of nep_listen() */


void print_cookie(u8 *cookie){
  for(size_t i=0; i<COOKIE_LEN; i++)
    printf("%02x", cookie[i]);
}


void print_cookie_nl(u8 *cookie){
  print_cookie(cookie);
  printf("\n");
}


int handle_op_client_insert(int sd){
 cookie_t new_cookie;
 u8 response=RESULT_SUCCESS;

 /* Receive cookie */
 if( read(sd, new_cookie.cookie, COOKIE_LEN)<COOKIE_LEN ){
    printf("[+] Bogus CLIENT INSERT request received.\n");
    return -1;
 }

 printf("[+] Received CLIENT INSERT request: "); print_cookie_nl(new_cookie.cookie);

 client_cookies.push_back(new_cookie);
 if( write(sd, &response, 1) < 1 )
     return -1;
 return 0;
}


int handle_op_server_insert(int sd){
 cookie_t new_cookie;
 u8 response=RESULT_SUCCESS;

 /* Receive cookie */
 if( read(sd, new_cookie.cookie, COOKIE_LEN)<COOKIE_LEN ){
    printf("[+] Bogus SERVER INSERT request received.\n");
    return -1;
 }

 printf("[+] Received SERVER INSERT request: "); print_cookie_nl(new_cookie.cookie);

 server_cookies.push_back(new_cookie);
 if( write(sd, &response, 1) < 1 )
     return -1;
 return 0;
}


int handle_op_server_verify(int sd){
  int removed=0;
  u8 response=0;
  cookie_t recv_cookie;
  size_t j=0;

  /* Receive cookie */
  if( read(sd, recv_cookie.cookie, COOKIE_LEN)<COOKIE_LEN ){
    printf("[+] Bogus SERVER VERIFY request received.\n");
    return -1;
 }

  printf("[+] Received SERVER VERIFY request: "); print_cookie_nl(recv_cookie.cookie);
  for (size_t i=0; i< server_cookies.size(); ++i) {
    if ( memcmp(server_cookies[i].cookie, recv_cookie.cookie, COOKIE_LEN)  )
        server_cookies[j++] =server_cookies[i];
    else
        removed++;
  }
  /* trim vector to its new size */
  server_cookies.resize(j);
  response=(removed>0) ?RESULT_SUCCESS : RESULT_FAILURE;
  if( write(sd, &response, 1) < 1 )
     return -1;
  return 0;
}


int handle_op_client_retrieve(int sd){
  u8 cookie_response[COOKIE_LEN];
  u8 response=0;
  memset(cookie_response, 0, COOKIE_LEN);
  size_t j=client_cookies.size();

  /* Check if there are cookies stored */
  if(j<=0){
      printf("[+] Received CLIENT RETRIEVE request but cookie jar is empty.\n");
      response=RESULT_FAILURE;
      if( write(sd, &response, 1) < 1)
          return -1;
      return -1;
  }

  printf("[+] Received CLIENT RETRIEVE request. Returning "); print_cookie_nl(client_cookies[j-1].cookie);
  response=RESULT_SUCCESS;
  if( write(sd, &response, 1) < 1 )
     return -1;
  if( write(sd, client_cookies[j-1].cookie, COOKIE_LEN) < COOKIE_LEN )
      return -1;
  client_cookies.resize(j-1);
  return 0;
}


int handle_request(int fd){
  u8 type=0;

  if( read(fd, &type, 1)!=1 )
    return -1;

  switch(type){

    case OP_CLIENT_INSERT:
        return handle_op_client_insert(fd);
    break;

    case OP_CLIENT_RETRIEVE:
        return handle_op_client_retrieve(fd);
    break;

    case OP_SERVER_INSERT:
        return handle_op_server_insert(fd);
    break;

    case OP_SERVER_VERIFY:
        return handle_op_server_verify(fd);
    break;

    default:
        printf("[+] Received bogus request, discarding it...\n");
        return -1;
    break;

  }
}


int main(int argc, char *argv[]){
  int master_socket=-1;
  int family=-1;
  int client_sd=-1;
  unsigned int served_clients=0;
  struct sockaddr_storage ss;
  socklen_t sslen;

  /* Set IPv6 if requested */
  if(argc>1 && !strcmp("-6", argv[1]) )
      family=AF_INET6;
  else
      family=AF_INET;
  
  master_socket=get_listen_socket(family);

  while(1){

    if ((client_sd=accept(master_socket, (struct sockaddr *)&ss, &sslen)) >= 0){
        printf("[+] Connection #%u received.\n", ++served_clients);
        handle_request(client_sd);
        close(client_sd);
        printf("[+] Session #%u ended.\n", served_clients);
    }
  }
}


