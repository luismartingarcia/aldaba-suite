
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
#include "HTTPHeader.h"
#include "tools.h"
#include <assert.h>


/**********************************************************************
 * Constructors, destructors and cleanup functions                    *
 **********************************************************************/
/** Constructor */
HTTPHeader::HTTPHeader() {
    this->reset();
} /* End of HTTPHeader() */


/** Destructor */
HTTPHeader::~HTTPHeader() {

} /* End of ~HTTPHeader() */


/** @warning This method is essential for the superclass getBinaryBuffer()
 *  method to work. Do NOT change a thing unless you know what you're doing  */
u8 *HTTPHeader::getBufferPointer(){
  return (u8*)(&this->h);
} /* End of getBufferPointer() */


/** Returns the object to its initial state so it can be reused */
int HTTPHeader::reset(){
  memset(this->h, 0,HTTP_HDR_MAX_LEN);
  this->length=0;
  return OP_SUCCESS;
}


/** Returns the status code contained in a standard HTTP response */
int HTTPHeader::extractCodeFromHTTPResponse(char *msg){
  if(msg==NULL || strlen(msg)<strlen("HTTP/X.X XXX\r\n") )
    return OP_FAILURE;

  /* This will not work with proto versions longer than X.X */
  int code = strtol(msg+strlen("HTTP/X.X "), NULL, 10);

  if(code==0 && msg[0]!='0')
    return OP_FAILURE;
  else
    return code;
} /* End of extractCodeFromHTTPResponse() */


int HTTPHeader::extractCodeFromHTTPResponse(){
    return this->extractCodeFromHTTPResponse(this->h);
} /* End of extractCodeFromHTTPResponse() */


/** Returns the HTTP version contained in a standard HTTP response */
double HTTPHeader::extractVersionHTTPResponse(char *msg){
  if(msg==NULL || strlen(msg)<strlen("HTTP/X.X\r\n") )
    return OP_FAILURE;
  if( strncmp_wildcarded(msg, "HTTP/*.*", '*', 8 ) )
    return OP_FAILURE;
  if( !isdigit(msg[5]) || !isdigit(msg[7]) )
    return OP_FAILURE;
  return atof(msg+strlen("HTTP/"));
} /* End of extractCodeFromConnectResponse() */


/** Returns true if the supplied message is HTTP version 1.1 */
bool HTTPHeader::isHTTP11(char *msg){
 if(msg==NULL || strlen(msg)<strlen("HTTP/X.X\r\n") )
    return false;
 if( !strncmp(msg, "HTTP/1.1", 8) )
    return true;
 else
    return false;
} /* End of isHTTP11() */



 /**********************************************************************
 * Miscellaneous HTTP related functions                                *
 **********************************************************************/

/** Adds a User-Agent header to current packet. */
int HTTPHeader::addUserAgentHeader(const char *agent){
  char buf[512];
  assert(agent!=NULL);
  snprintf(buf, sizeof(buf), "User-Agent: %s\r\n", agent);
  strncat(this->h, buf, HTTP_HDR_MAX_LEN);
  length+=strlen(buf);
  return OP_SUCCESS;
} /* End of addUserAgentHeader() */


/** Adds a Host header to current packet. */
int HTTPHeader::addHostHeader(const char *hostname){
  char buf[512];
  assert(hostname!=NULL);
  snprintf(buf, sizeof(buf), "Host: %s\r\n", hostname);
  strncat(this->h, buf, HTTP_HDR_MAX_LEN);
  length+=strlen(buf);
  return OP_SUCCESS;
} /* End of addHostHeader() */


/** Adds a Connection: Close header to current packet. */
int HTTPHeader::addConnectionCloseHeader(){
  strncat(this->h, "Connection: close\r\n", HTTP_HDR_MAX_LEN);
  length+=strlen("Connection: close\r\n");
  return OP_SUCCESS;
} /* End of addConnectionCloseHeader() */


/** Adds a <CR><LF> line to current packet. */
int HTTPHeader::addCRLF(){
  strncat(this->h, "\r\n", HTTP_HDR_MAX_LEN);
  length+=strlen("\r\n");
  return OP_SUCCESS;
} /* End of addCRLF() */


/** Adds a GET request to the current packet.  */
int HTTPHeader::addGET4FileHeader(const char *filename){
  //char encoded[512];
  char buf[512];
  assert(filename!=NULL);
  //url_encode(filename, encoded, 512);
  //snprintf(buf, sizeof(buf), "GET %s HTTP/1.1\r\n", encoded);
  snprintf(buf, sizeof(buf), "GET %s HTTP/1.1\r\n", filename);
  strncat(this->h, buf, HTTP_HDR_MAX_LEN);
  length+=strlen(buf);
  return OP_SUCCESS;
} /* End of addGET4FileHeader() */



/**********************************************************************
 *  Some other miscellanious functions                                *
 **********************************************************************/

/** Divides the supplied buffer into tokens, usgin <CR><LF> as separator. */
int HTTPHeader::tokenizePacket(char *buffer, size_t bufferlen, char **tokenlist, size_t tokenlistsize){
  return tokenize("\r\n", buffer, bufferlen, tokenlist, tokenlistsize);
}


/** Stores supplied packet in the internal buffer so the information
  * can be accessed using the standard get & set methods. */
int HTTPHeader::storeRecvMessage(u8 *buf, size_t len){
  assert(buf!=NULL);
  memset(this->h, 0, HTTP_HDR_MAX_LEN);
  length =  (len<HTTP_HDR_MAX_LEN) ? len : HTTP_HDR_MAX_LEN;
  memcpy( this->h, buf,  length);
  return OP_SUCCESS;
} /* End of storeRecvMessage() */


/** Parses one header and returns its type, as defined in rotella.h */
int HTTPHeader::header2type(char *header){
  assert(header!=NULL);
  if( starts_with(header, "User-Agent:") )
    return HTTP_USER_AGENT;
  if( starts_with(header, "GET") )
    return HTTP_GET;
  else if( starts_with(header, "Host:") )
    return HTTP_HOST;
  else if( starts_with(header, "Connection:") )
    return HTTP_CONNECTION;
  else if( starts_with(header, "Server:") )
    return HTTP_SERVER;
  else if( starts_with(header, "HTTP/") )
    return HTTP_STD_RESPONSE_CODE;
  else if( starts_with(header, "Content-type:") )
    return HTTP_CONTENT_TYPE;
  else if( starts_with(header, "Content-length:") )
    return HTTP_CONTENT_LENGTH;
  else if( starts_with(header, "\r\n") )
    return HTTP_CRLF;
  else
    return HTTP_UNKNOWN;
} /* End of header2type() */


/** Wrapper for the previous function */
int HTTPHeader::header2type(){
  return this->header2type( this->h );
} /* End of header2type() */


