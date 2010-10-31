
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
 * as this disclaimer does not contain the complete information. Also, note*
 * that although Aldaba is licensed under the GNU GPL v2.0 license, it may *
 * be possible to obtain copies of it under different, less restrictive,   *
 * alternative licenses. Requests will be studied on a case by case basis. *
 * If you wish to obtain Aldaba under a different license, please use the  *
 * email address shown above.                                              *
 *                                                                         *
 ***************************************************************************/

#include "aldaba.h"
#include "output.h"
#include "AddressResolver.h"
#include "HTTPHeader.h"
#include "tools.h"
#include "IPAddress.h"
#include <assert.h>

AddressResolver::AddressResolver(){

}

AddressResolver::~AddressResolver(){

}


/** Resolves the internet-side IP address of the user's network. This is done
  * by contacting the external IP address resolution service at
  * whatismyip.aldabaknocking.com. The function takes a pointer to an IPAddress
  * object, which will be used to store the resolved IP. addr_family must be
  * one of AF_INET or AF_INET6.
  * @return OP_SUCCESS if the resolution was successful
  * @return OP_FAILURE in case of error. */
int AddressResolver::resolve(IPAddress *resolved_ip, int addr_family){
  int pf=(addr_family==AF_INET6) ? PF_INET6 : PF_INET;
  int af=(addr_family==AF_INET6) ? AF_INET6 : AF_INET;
  size_t sslen=(addr_family==AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
  struct sockaddr_storage ss;
  int sockfd=-1;
  size_t recvbytes=0;
  u8 buffer[DEFAULT_IP_RESOLVER_RESULT_MAX_LENGTH+1];
  u8 *start=NULL, *end=NULL;
  HTTPHeader http;
  IPAddress resolver;
  assert(resolved_ip!=NULL);
  memset(&ss, 0, sizeof(struct sockaddr_storage));
  memset(buffer, 0, sizeof(buffer));

  /* Build HTTP Request */
  http.addGET4FileHeader(DEFAULT_IP_RESOLVER_PATH);
  http.addHostHeader(DEFAULT_IP_RESOLVER_SITE);
  http.addUserAgentHeader(DEFAULT_IP_RESOLVER_USERAGENT);
  http.addConnectionCloseHeader();
  http.addCRLF();

  /* Determine resolver's IP address */
  if(af==AF_INET6)
    resolver.setIPv6Address(DEFAULT_IP_RESOLVER_SITE);
  else
    resolver.setIPv4Address(DEFAULT_IP_RESOLVER_SITE);
  indent(OUT_8, 2, "Using resolver %s at addr=%s:%d\n", DEFAULT_IP_RESOLVER_SITE, resolver.toString(), DEFAULT_IP_RESOLVER_PORT);

  /* Acquire socket */
  if((sockfd=socket(pf, SOCK_STREAM, 0))<0){
    return OP_FAILURE;
  }

  /* Connect to the HTTP server */
  resolver.getAddress(&ss);
  resolver.setSockaddrPort(&ss, DEFAULT_IP_RESOLVER_PORT);
  if(connect(sockfd, (struct sockaddr *)&ss, sslen )!=0) {
    return OP_FAILURE;
  }

  /* Send HTTP GET request*/
  if(send(sockfd, http.getBufferPointer(), http.getLen(), 0)==-1){
    return OP_FAILURE;
  }

  indent(OUT_7, 2, "Sent HTTP GET Request to %s:%d\n", resolver.toString(), DEFAULT_IP_RESOLVER_PORT);
  print_hexdump(OUT_8, http.getBufferPointer(), http.getLen());

  /* Read HTTP Response header */
  if((recvbytes=read_until(sockfd, (char *)buffer, DEFAULT_IP_RESOLVER_RESULT_MAX_LENGTH, "\r\n\r\n"))<=0){
    return OP_FAILURE;
  }

  /* Ensure we got a positive response (Code 2xx) */
  http.reset();
  http.storeRecvMessage(buffer, recvbytes);
  int code=http.extractCodeFromHTTPResponse();
  if(code<200 || code>=300)
      return OP_FAILURE;

  /* Read the first line of the body */
  if((recvbytes=read_until(sockfd, (char *)buffer, DEFAULT_IP_RESOLVER_RESULT_MAX_LENGTH, DEFAULT_IP_RESOLVER_CLOSE_TAG))<=0){
    return OP_FAILURE;
  }
  buffer[recvbytes]='\0';

  indent(OUT_7, 2, "Received HTTP response from %s:%d\n", resolver.toString(), DEFAULT_IP_RESOLVER_PORT);
  print_hexdump(OUT_8, buffer, recvbytes);

  if((start=(u8 *)strstr((const char *)buffer, DEFAULT_IP_RESOLVER_OPEN_TAG))==NULL)
    return OP_FAILURE;
  else
      start+=strlen(DEFAULT_IP_RESOLVER_OPEN_TAG);

  if((end=(u8 *)strstr((const char *)buffer, DEFAULT_IP_RESOLVER_CLOSE_TAG))==NULL)
    return OP_FAILURE;

  /* Check we didn't received and empty element like <tag></tag>*/
  if(end==start)
    return OP_FAILURE;

  end[0]='\0';
  if(!resolved_ip->isIPAddress((const char *)start))
    return OP_FAILURE;

  resolved_ip->setAddress((const char *)start);
  close(sockfd);
  return OP_SUCCESS;
  
} /* End of resolve() */



