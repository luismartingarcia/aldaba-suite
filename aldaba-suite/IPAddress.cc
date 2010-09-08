
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
#include "IPAddress.h"
#include <assert.h>


/** Standard constructor. Inits the internal attributes of the object.
  * Basically it just performs a reset() operation. Check IPAddress::reset()
  * documentation for details. */
IPAddress::IPAddress(){
    this->reset();
}

/** Constructor for IPv4 addreses.
  * @param val is the IPv4 address that wants to be set */
IPAddress::IPAddress(struct in_addr val){
  this->reset();
  this->ip4 = val;
  this->version = AF_INET;
}

/** Constructor for IPv6 addreses.
  * @param val is the IPv6 address that wants to be set */
IPAddress::IPAddress(struct in6_addr val){
  this->reset();
  this->ip6 = val;
  this->version = AF_INET6;
}


/** Standard destructor. It doesn't free anything (as there is no dinamically
  * allocated data inside the object), but sets the object state to the initial
  * state, through a reset() call. Check IPAddress::reset() documentation for
  * details. */
IPAddress::~IPAddress(){
    this->reset();
}


/* Determines if two ip addresses are equal. */
bool IPAddress::operator==(const IPAddress& other) const {
  if(this->version!=other.version)
    return false;
  if( this->version==AF_INET6){
    if(memcmp(this->ip6.s6_addr, other.ip6.s6_addr, 16)!=0 )
        return false;
  }else{
    if( this->ip4.s_addr!=other.ip4.s_addr )
        return false;
  }
  return true;
}


/* Determines the < relation between two ip addresses. */
bool IPAddress::operator<(const IPAddress& other) const {
  if(this->version!=other.version)
    return (this->version==AF_INET) ? true : false;
  if( this->version==AF_INET6){
      if(memcmp(this->ip6.s6_addr, other.ip6.s6_addr, 16)>=0)
          return false;
  }else{
    if( this->ip4.s_addr>=other.ip4.s_addr )
        return false;
  }
  return true;
}


/* Determines the < relation between two ip addresses. */
bool IPAddress::operator>(const IPAddress& other) const {
  if(this->version!=other.version)
    return (this->version==AF_INET) ? false : true;
  if( this->version==AF_INET6){
      if(memcmp(this->ip6.s6_addr, other.ip6.s6_addr, 16)<=0)
          return false;
  }else{
    if( this->ip4.s_addr<=other.ip4.s_addr )
        return false;
  }
  return true;
}



/** Sets the object to a safe initial state. Basically all structures that
  * hold address information are zeroed. The version flag is set to AF_INET
  * by default (IPv4 addresses by default).. */
void IPAddress::reset(){
    memset(&(this->ip4), 0, sizeof(struct in_addr));
    memset(&(this->ip6), 0, sizeof(struct in6_addr));
    this->version=AF_INET; /* Default to IPv4 */
} /* End of reset() */


/** Returns the IP version of the stored address. It returns either AF_INET or
  * AF_INET6 */
int IPAddress::getVersion() {
    return version;
} /* End of getVersion() */

/** Sets IP version to version 4 */
void IPAddress::setVersion4(){
    this->version=AF_INET;
} /* End of setVersion4() */

/** Sets IP version to version 6 */
void IPAddress::setVersion6(){
    this->version=AF_INET6;
} /* End of setVersion6() */


/** Returns true if the string pointed by "val" is valid IPv4 address in
    decimal-dot notation. The code was inspired by a post in 
    http://bytes.com/topic/c/answers/212174-code-validating-ipv4-address */
bool IPAddress::isIPv4Address(const char *val){
  uint32_t oct1=0, oct2=0, oct3=0, oct4=0;
  char dummy=0;

  /* Check string only has allowed values */
  if (strspn(val, "0123456789.") < strlen(val))
      return false;

  /* Use sscanf to divide address into octet tokens */
  if (sscanf(val, "%3u.%3u.%3u.%3u%c", &oct1, &oct2, &oct3, &oct4, &dummy)!=4)
      return false;

  /* Check numbers are in the range [0-255] */
  if( (oct1>255) || (oct2>255) || (oct3>255) || (oct4>255) )
      return false;

  return true;
        
} /* End of isIPv4Address() */


/** Returns true if the string pointed by "val" is valid IPv6 address in
  * the stantard IPv6 notation. */
bool IPAddress::isIPv6Address(const char *val){
  struct in6_addr dummy;
  if( inet_pton(AF_INET6, val, &dummy) == 0 )
    return false;
  else
    return true;
} /* End of isIPv6Address()  */


/** Returns true if string pointed by "val" is either a valid IPv4
  * address or a valid IPv6 address */
bool IPAddress::isIPAddress(const char *val){
  if( isIPv4Address(val) || isIPv6Address(val) )
    return true;
  else
    return false;
} /* End of isIPAddress() */


/** Returns true if string pointed by "val" is NOT a valid IPv4 and NOT a
  * valid IPv6 address. If both conditions are met, it is assumed that the
  * string represents a hostname.
  * @warning This functions just checks that the supplied string is NOT an
  * IPv4 or IPv6 address in their standard notation. No checks are made to
  * ensure things like, hostname does not contain ilegal characters, hostname
  * length is > 0 etc. If you need this kind of tests, you'll have to perform
  * them before calling this method. */
bool IPAddress::isHostname(const char *val){
  return !isIPAddress(val);
} /* End of isHostname() */


/** Converts the IP address stored in the object to a printable ASCII string.
  * @warning Returned parameter points to a statically allocated buffer that
  * may be overwritten if more operations are perform on the object. 
  * @return a pointer to a statically allocated buffer that holds a NULL
  * terminated string or NULL in case of error. */
const char *IPAddress::toString(){
#ifdef INET6_ADDRSTRLEN
    static char ipstring[INET6_ADDRSTRLEN];
#else
    static char ipstring[50];
#endif
    memset(ipstring, 0, sizeof(ipstring));
    return this->toString(ipstring, sizeof(ipstring));
} /* End of toString() */

/** Converts the IP address stored in the object to a printable ASCII string
  * that is stored in the supplied buffer.
  * @param buffer should point to a previously allocated buffer, big
  * enough to hold the string representation of an IP address (at least 
  * INET_ADDRSTRLEN bytes for IPv4 addresses, and INET6_ADDRSTRLEN for IPv6
  * addresses).
  * @param bufferlen is the length of the supplied buffer. If bufferlen is not
  * big enough to hold the address, the result is unspecified..
  * @return the same pointer as "buffer" so, for example, you can use the call
  * directly as an argument to printf() or similar.
  *     eg: printf("My ip is %s", ip.toString(mybuff, 512));*/
const char *IPAddress::toString(char *buffer, size_t bufferlen){
  const char *result=NULL;
  if( this->getVersion() == AF_INET ){
    result=inet_ntop(AF_INET, &this->ip4, buffer, bufferlen);
  }else if (this->getVersion() == AF_INET6 ){
    result=inet_ntop(AF_INET6, &this->ip6, buffer, bufferlen);
  }else{
    return NULL;
  }
 /* If everything went well, result should point to "ipstring". Otherwise
  * it will be set to NULL. */
  return result;
} /* End of toString() */

/** Sets the IP Address. Supplied value can be either an IPv4 address in
  * standard dot-decimal notation, and IPv6 address in its standard notation
  * or a hostname, in which case, IPv4 resolution will be attempted.
  * @return OP_SUCCESS on success or OP_FAILURE in case of error. */
int IPAddress::setAddress(const char *val){
  /* If supplied parameter is an IPv6 address, set IPv6 */
  if( this->isIPv6Address(val) ){
    return setIPv6Address(val);    
  /* If supplied parameter is an IPv4 address or a hostname, set it */
  }else{
    return setIPv4Address(val);
  }
} /* End of setAddress() */

/** Sets the IP Address (version 4).  */
void IPAddress::setAddress(struct in_addr val){
  this->ip4=val;
  this->version=AF_INET;
}

/** Sets the IP Address (version 4).  */
void IPAddress::setAddress(struct in6_addr val){
  this->ip6=val;
  this->version=AF_INET6;
}

/** Sets the IP Address (version 4).  */
void IPAddress::setAddress(struct sockaddr_storage val){
  struct sockaddr_in *s4=(struct sockaddr_in *)&val;
  struct sockaddr_in6 *s6=(struct sockaddr_in6 *)&val;
  if( s6->sin6_family==AF_INET6 )
    return setAddress(s6->sin6_addr);
  else
    return setAddress(s4->sin_addr);
}

/** Sets the IP Address (version 4).  */
void IPAddress::setAddress(struct sockaddr_in val){
  this->ip4=val.sin_addr;
  this->version=AF_INET;
}

/** Sets the IP Address (version 4).  */
void IPAddress::setAddress(struct sockaddr_in6 val){
  this->ip6=val.sin6_addr;
  this->version=AF_INET6;
}

/** Sets the IP Address (version 4).  */
void IPAddress::setAddress(struct sockaddr_in *val){
  assert(val);
  return this->setAddress(*val);
}

/** Sets the IP Address (version 4).  */
void IPAddress::setAddress(struct sockaddr_in6 *val){
  assert(val);
  return this->setAddress(*val);
}

/** Sets the IP Address (version 4). Supplied value can be either an IPv4
  * address in standard dot-decimal notation or a hostname, in which case,
  * IPv4 resolution will be attempted.
  * @return OP_SUCCESS on success or OP_FAILURE in case of error. */
int IPAddress::setIPv4Address(const char *val){
  struct in_addr myaddr;
  memset(&myaddr, 0, sizeof(struct in_addr));
  /* Resolve it and store the address */
  if( this->str2in_addr(val, &myaddr)==OP_SUCCESS ){
    this->ip4 = myaddr;
    this->setVersion4();
    return OP_SUCCESS;
  }else{
    return OP_FAILURE;
  }
} /* End of setIPv4Address() */


/** Sets the IP Address (version 6). Supplied value can be either an IPv6
  * address in its standard notation or a hostname, in which case, IPv6
  * resolution will be attempted.
  * @return OP_SUCCESS on success or OP_FAILURE in case of error. */
int IPAddress::setIPv6Address(const char *val){
  struct in6_addr myaddr;
  memset(&myaddr, 0, sizeof(struct in6_addr));
  /* Resolve it and store the address */
  if( this->str2in6_addr(val, &myaddr)==OP_SUCCESS ){
    this->ip6 = myaddr;
    this->setVersion6();
    return OP_SUCCESS;
  }else{
    return OP_FAILURE;
  }
} /* End of setIPv6Address() */


/** Returns the IPv4 address stored in the object, as an in_addr structure.
  * @warning the caller MUST ensure that the object contains an IPv4 address
  * and NOT an IPv6 address before calling this method. This can be done
  * calling .IPAddress::getVersion() and testing whether the returned result
  * matches AF_INET (IPv4) and not AF_INET6 (IPv6).  */
struct in_addr IPAddress::getIPv4Address(){
  return this->ip4;
} /* End of getIPv4Address() */


/** Stores the IPv4 address stored in the object, in the supplied buffer.
  * @warning the caller MUST ensure that the object contains an IPv4 address
  * and NOT an IPv6 address before calling this method. This can be done
  * calling .IPAddress::getVersion() and testing whether the returned result
  * matches AF_INET (IPv4) and not AF_INET6 (IPv6).  */
int IPAddress::getIPv4Address(struct sockaddr_in *val){
  if(val==NULL)
    return OP_FAILURE;
  memset(val, 0, sizeof(struct in_addr));
  val->sin_family=AF_INET;
  val->sin_addr = this->ip4;
  return OP_SUCCESS;
} /* End of getIPv4Address() */


/** Returns the IPv6 address stored in the object, as an in6_addr structure.
  * @warning the caller MUST ensure that the object contains an IPv6 address
  * and NOT an IPv4 address before calling this method. This can be done
  * calling .IPAddress::getVersion() and testing whether the returned result
  * matches AF_INET6 (IPv6) and not  AF_INET (IPv4).  */
struct in6_addr IPAddress::getIPv6Address(){
  return this->ip6;
} /* End of getIPv4Address() */


/** Stores the IPv6 address stored in the object, in the supplied buffer.
  * @warning the caller MUST ensure that the object contains an IPv6 address
  * and NOT an IPv4 address before calling this method. This can be done
  * calling .IPAddress::getVersion() and testing whether the returned result
  * matches AF_INET6 (IPv6) and not  AF_INET (IPv4).  */
int IPAddress::getIPv6Address(struct sockaddr_in6 *val){
  if(val==NULL)
    return OP_FAILURE;
  memset(val, 0, sizeof(struct in6_addr));
  val->sin6_family=AF_INET6;
  val->sin6_addr = this->ip6;
  return OP_SUCCESS;
} /* End of getIPv6Address() */


/** Copies the address stored in the object, to the supplied buffer.
  * @warning the caller may determine which IP version the returned address
  * is, calling methot getVersion() and testing for AF_INET (IPv4) or AF_INET6
  * (IPv6).
  * @param val must point to a buffer big enough to hold a sockaddr_in structure
  * if stored IP is version 4, or a sockaddr_in6 structure if stored IP is
  * version 6. The expected type is sockaddr_storage but it is OK to pass
  * a sockaddr_in or a sockaddr_in6 casted to sockaddr_storage, as long as you
  * check the IP version before the call.  */
int IPAddress::getAddress(struct sockaddr_storage *val){
  struct sockaddr_in *dst4 = (struct sockaddr_in *)val;
  struct sockaddr_in6 *dst6 = (struct sockaddr_in6 *)val;
  if(val==NULL)
    return OP_FAILURE;
  if( this->getVersion()==AF_INET6){
    memset(dst6,0, sizeof(struct sockaddr_in6) );
    dst6->sin6_family=AF_INET6;
    dst6->sin6_addr=this->ip6;
  }else{
    memset(dst4,0, sizeof(struct sockaddr_in) );
    dst4->sin_family=AF_INET;
    dst4->sin_addr=this->ip4;
  }
  return OP_SUCCESS;
} /* End of getIPv6Address() */


/** Turns the supplied hostname or IPv4 address into an in_addr structure.
  * Supplied value can be either an IPv4 address in standard dot-decimal
  * notation or a hostname, in which case, IPv4 resolution will be attempted.
  * @return OP_SUCCESS on success or OP_FAILURE in case of error.
  * @param hostname is the hostname or IPv4 address to be converted.
  * @param address is the buffer where the resulting in_addr structure should
  * be stored */
int IPAddress::str2in_addr(const char *hostname, struct in_addr *address){
  struct sockaddr_in i;
  unsigned int stlen=0;
  if ( resolve(hostname, (sockaddr_storage*)&i, (size_t *)&stlen , AF_INET) != OP_SUCCESS )
    return OP_FAILURE;
   *address=i.sin_addr;
   return OP_SUCCESS;
} /* End of str2in_addr() */


/** Turns the supplied hostname or IPv6 address into an in6_addr structure.
  * Supplied value can be either an IPv6 address in its standard notation or
  * a hostname, in which case, IPv6 resolution will be attempted.
  * @return OP_SUCCESS on success or OP_FAILURE in case of error.
  * @param hostname is the hostname or IPv6 address to be converted.
  * @param address is the buffer where the resulting in6_addr structure should
  * be stored */
int IPAddress::str2in6_addr(const char *hostname, struct in6_addr *address){
  struct sockaddr_in6 i;
  unsigned int stlen=0;
  if ( resolve(hostname, (sockaddr_storage*)&i, (size_t *)&stlen , AF_INET6) != OP_SUCCESS )
    return OP_FAILURE;
   *address=i.sin6_addr;
   return OP_SUCCESS;
} /* End of str2in_addr() */


/** Tries to resolve the given name (or literal IP) into a sockaddr
  * structure.  should be PF_INET (for IPv4) or PF_INET6.  Returns 0
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
int IPAddress::resolve(const char *hostname, struct sockaddr_storage *ss, size_t *sslen, int family) {
  struct addrinfo hints;
  struct addrinfo *result=NULL;
  int rc=0;
  /* Input validation */
  if(ss==NULL || sslen==NULL){
    return OP_FAILURE;
  }else if( family!=AF_INET && family!=AF_INET6 && family!=AF_UNSPEC ){
    return OP_FAILURE;
  }
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = family;
  /* Resolve hostname */
  if( (rc=getaddrinfo(hostname, NULL, &hints, &result)) != 0 )
    return OP_FAILURE;
  if(result==NULL)
    return OP_FAILURE;
  /* This should never happen but, just in case, we check whether the
  * returned address fits into a the appropriate sockaddr_whatever */
  if(family==AF_INET){
    if( result->ai_addrlen > 0 && result->ai_addrlen > (int) sizeof(struct sockaddr_in) )
        return OP_FAILURE;
  }else if(family==AF_INET6){
    if( result->ai_addrlen > 0 && result->ai_addrlen > (int) sizeof(struct sockaddr_in6) )
        return OP_FAILURE;
  }else{ /* Family is AF_UNSPEC */
    if( result->ai_addrlen > 0 && result->ai_addrlen > (int) sizeof(struct sockaddr_storage) )
        return OP_FAILURE;
  }
  /* Store the result in user-supplied parameters */
  *sslen = result->ai_addrlen;
  memcpy(ss, result->ai_addr, *sslen);
  freeaddrinfo(result);
  return OP_SUCCESS;
} /* End of resolve() */


int IPAddress::setSockaddrPort(struct sockaddr_storage *ss, u16 port){
  struct sockaddr_in *s4=(struct sockaddr_in *)ss;
  struct sockaddr_in6 *s6=(struct sockaddr_in6 *)ss;
  assert(ss!=NULL);
  if(ss->ss_family==AF_INET6){
    s6->sin6_port=htons(port);
  }else{
    s4->sin_port=htons(port);
  }
  return OP_SUCCESS;
}

