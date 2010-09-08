
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
 
#include "IPv4Header.h"
#include "aldaba.h"
#include "output.h"
#include "tools.h"


IPv4Header::IPv4Header() {
    this->reset();
} /* End of IPv4Header constructor */


IPv4Header::~IPv4Header() {

} /* End of IPv4Header destructor */

/** Sets every attribute to its default value- */
void IPv4Header::reset() {
  memset(&h, 0, 20 + MAX_IP_OPTIONS_LEN);
  ipoptlen=0;
  length=20;   /* Initial value 20. This will be incremented if options are used */
  setVersion();
  setHeaderLength();
  setTTL(DEFAULT_IP_TTL);
  setTotalLength();
} /* End of IPv4Header destructor */


/** Sets every IP header field to zero. This affects the IP Header and any
  * options that it contained. After calling this method, the IP header will
  * be a standard 20-byte header with no options. */
void IPv4Header::zero(){
  memset(&h, 0, 20 + MAX_IP_OPTIONS_LEN);
  ipoptlen=0;
  length=20;
} /* End of zero() */


/** @warning This method is essential for the superclass getBinaryBuffer()
 *  method to work. Do NOT change a thing unless you know what you're doing  */
u8 *IPv4Header::getBufferPointer(){
  return (u8*)(&h);
} /* End of getBufferPointer() */


/** Stores supplied packet in the internal buffer so the information
  * can be accessed using the standard get & set methods.
  * @warning  The IPv4Header class is able to hold a maximum of 60 bytes. If the
  * supplied buffer is longer than that, only the first 60 bytes will be stored
  * in the internal buffer.
  * @warning Supplied len MUST be at least 20 bytes (min IP header length).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error */
int IPv4Header::storeRecvData(const u8 *buf, size_t len){
  if(buf==NULL || len<IP_HEADER_LEN){
    return OP_FAILURE;
  }else{
    int stored_len = MIN((IP_HEADER_LEN + MAX_IP_OPTIONS_LEN), len);
    this->reset(); /* Re-init the object, just in case the caller had used it already */
    this->length=stored_len;
    memcpy(&(this->h), buf, stored_len);
  }
 return OP_SUCCESS;
} /* End of storeRecvData() */

/** Performs some VERY BASIC checks that intend to validate the information
  * stored in the internal buffer, as a valid protocol header.
  * @warning If the information stored in the object has been set through a
  * call to storeRecvData(), the object's internal length count may be updated
  * if the validation is successful.
  * @return the length, in bytes, of the header, if its found to be valid or
  * OP_FAILURE (-1) otherwise. */
int IPv4Header::validate(){
  if(this->getVersion()!=4)
    return OP_FAILURE;
  else if( this->getHeaderLength()<5)
    return OP_FAILURE;
  else if( this->getHeaderLength()*4 > this->length)
    return OP_FAILURE;
//else if( this->getTotalLength()==0)
//  return OP_FAILURE;
  this->length=this->getHeaderLength()*4;
  return this->length;
} /* End of validate() */


int IPv4Header::setVersion(){
  h.ip_v   = 4;
  return 4;
} /* End of setVersion() */


u8 IPv4Header::getVersion(){
  return (u8)h.ip_v;
} /* End of getVersion() */


int IPv4Header::setHeaderLength(){
  h.ip_hl  = 5 + (ipoptlen/4);
  return OP_SUCCESS;
} /* End of setHeaderLength() */



int IPv4Header::setHeaderLength(u8 l){
  h.ip_hl  = l;
  return OP_SUCCESS;
} /* End of setHeaderLength() */


u8 IPv4Header::getHeaderLength(){
  return h.ip_hl;
} /* End of getHeaderLength() */


int IPv4Header::setTOS(u8 v){
  h.ip_tos = v;
  return OP_SUCCESS;
} /* End of setTOS() */


u8 IPv4Header::getTOS(){
  return h.ip_tos;
} /* End of getTOS() */


int IPv4Header::setTotalLength(){
  int mylen = 4*getHeaderLength();
  int otherslen=0;

  if (next!=NULL)
      otherslen=next->getLen();
  h.ip_len=htons( mylen+otherslen );
  return OP_SUCCESS;
} /* End of setTotalLength() */


/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htons() */
int IPv4Header::setTotalLength(u16 l){
  h.ip_len = htons(l);
  return OP_SUCCESS;
} /* End of setTotalLength() */


/** @warning Returned value is already in host byte order. */
u16 IPv4Header::getTotalLength(){
  return ntohs(h.ip_len);
} /* End of getTotalLength() */


/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htons() */
int IPv4Header::setIdentification(u16 i){
  h.ip_id = htons(i);
  return OP_SUCCESS;
} /* End of setIdentification() */


/** @warning Returned value is already in host byte order. */
u16 IPv4Header::getIdentification(){
  return ntohs(h.ip_id);
} /* End of getIdentification() */


/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htons() */
int IPv4Header::setFragOffset(u16 i){
  /* TODO: Should we check here that i<8192 ? */
  h.ip_off = htons(i);
  return OP_SUCCESS;
} /* End of setFragOffset() */


/** @warning Returned value is already in host byte order. */
u16 IPv4Header::getFragOffset(){
  return ntohs(h.ip_off);
} /* End of getFragOffset() */


/** Set RF flag */
int IPv4Header::setRF(){
  h.ip_off |= htons(IP_RF);
  return OP_SUCCESS;
} /* End of setRF() */

/** Unset RF flag */
int IPv4Header::unsetRF(){
  h.ip_off ^= htons(IP_RF);
  return OP_SUCCESS;
} /* End of unsetRF() */


/** Get RF flag */
bool IPv4Header::getRF(){
  return h.ip_off & htons(IP_RF);
} /* End of getRF() */


/** Set MF flag */
int IPv4Header::setMF(){
  h.ip_off |= htons(IP_MF);
  return OP_SUCCESS;
} /* End of setMF() */


/** Unset MF flag */
int IPv4Header::unsetMF(){
  h.ip_off ^= htons(IP_MF);
  return OP_SUCCESS;
} /* End of unsetMF() */


/* Get MF flag */
bool IPv4Header::getMF(){
  return h.ip_off & htons(IP_MF);
} /* End of getMF() */


/** Set DF flag */
int IPv4Header::setDF(){
  h.ip_off |= htons(IP_DF);
  return OP_SUCCESS;
} /* End of setDF() */


/** Unset DF flag */
int IPv4Header::unsetDF(){
  h.ip_off ^= htons(IP_DF);
  return OP_SUCCESS;
} /* End of unsetDF() */


/** Get DF flag */
bool IPv4Header::getDF(){
  return h.ip_off & htons(IP_DF);
} /* End of getDF) */


/** @warning Supplied value MUST be in host byte order because it will get
 *  converted by this method using htons() */
int IPv4Header::setTTL(u8 t){
  h.ip_ttl = t;
  return OP_SUCCESS;
} /* End of setTTL() */


/** @warning Returned value is already in host byte order. */
u8 IPv4Header::getTTL(){
  return h.ip_ttl;
} /* End of getTTL() */


/** Sets field "next protocol" to the supplied value.
 *  @warning: No error checks are made. Make sure the supplied value
 *  corresponds to an actual IANA number. Check
 *  http://www.iana.org/assignments/protocol-numbers/ for more details.      */
int IPv4Header::setNextProto(u8 p){
  h.ip_p=p;
  return OP_SUCCESS;
} /* End of setNextProto() */


/** Sets field "next protocol" to the number that corresponds to the supplied
 *  protocol name. Currently onyl TCP, UDP and ICMP are supported. Any
 *  help to extend this functionality would be appreciated. For a list of all
 *  proto names and numbers check:
 *  http://www.iana.org/assignments/protocol-numbers/                        */
int IPv4Header::setNextProto(const char *p){
  if (p==NULL){
        printf("setNextProto(): NULL pointer supplied\n");
    return OP_FAILURE;
  }
  if( !strcasecmp(p, "TCP") )
        h.ip_p=6;   /* 6=IANA number for proto TCP */

  else if( !strcasecmp(p, "UDP") )
        h.ip_p=17;  /* 17=IANA number for proto UDP */

  else if( !strcasecmp(p, "ICMP") )
        h.ip_p=1;   /* 1=IANA number for proto ICMP */
  else{
        printf("setNextProto(): Invalid protocol number\n");
        return OP_FAILURE;
  }
  return OP_SUCCESS;
} /* End of setNextProto() */


/** Returns next protocol number */
u8 IPv4Header::getNextProto(){
  return h.ip_p;
} /* End of getNextProto() */


/** Computes the IPv4 header checksum and sets the ip_sum field to the right
 *  value. */
int IPv4Header::setSum(){
  h.ip_sum = 0;
  h.ip_sum=in_cksum((unsigned short *)&h, 20 + ipoptlen ); /** @todo TODO: Test if this works */
  return OP_SUCCESS;
} /* End of setSum() */


/** @warning Sum is set to supplied value with NO byte ordering conversion
 *  performed.
 *  @warning If sum is supplied this way, no error checks are made. Caller is
 *  responsible for the correctness of the value. */
int IPv4Header::setSum(u16 s){
  h.ip_sum = s;
  return OP_SUCCESS;
} /* End of setSum() */


/** Returns the value of the checksum field.
 *  @warning The returned value is in NETWORK byte order, no conversion is
 *  performed */
u16 IPv4Header::getSum(){
  return h.ip_sum;
} /* End of getSum() */


/** Sets destination IP address.
 *  @warning Destination IP must be supplied in NETWORK byte order. Usually
 *  all regular library functions return IPs in network byte order so there
 *  should be no need to worry. If you have an ip in host byte order use
 *  method setDstIPHBO() */
int IPv4Header::setDstIP(struct in_addr d){
  h.ip_dst =  d;
  return OP_SUCCESS;
} /* End of getDstIP() */


/** Returns destination ip
 *  @warning Returned value is in NETWORK byte order. */
struct in_addr IPv4Header::getDstIP(){
  return h.ip_dst;
} /* End of getDstIP() */


/** Sets source IP address.
 *  @warning Destination IP must be supplied in NETWORK byte order. Usually
 *  all regular library functions return IPs in network byte order so there
 *  should be no need to worry. If you have an ip in host byte order use
 *  method setSrcIPHBO() */
int IPv4Header::setSrcIP(struct in_addr d){
  h.ip_src =  d;
  return OP_SUCCESS;
} /* End of getSrcIP() */


/** Returns source ip
 *  @warning Returned value is in NETWORK byte order. */
struct in_addr IPv4Header::getSrcIP(){
  return h.ip_src;
} /* End of getSrcIP() */


void centre_string(const char *in, char *out, int width);


void centre_string(const char *in, char *out, int width){
  int i=0, j=0;
  int len=strlen(in);
  for (i=0; i<=((width-len)/2)-1; i++) {
    out[i]=' ';
  }
  for(j=0; j<len; j++, i++){
     out[i]=in[j];
  }
 for (; i<width; i++) {
    out[i]=' ';
 }
  out[i]='\0';

  return;
}


#define NUMBER_BASE16 16
#define NUMBER_BASE10 10
#define NUMBER_BASE8  8
#define STRING_IPv4   4
#define STRING_IPv6   6
#define FLAG_1BIT     1

char *format_field(const char *prefix, void *val, int bits, int type){
    char mybuff[256];
    int width=(bits*2)-1;
    char *p=(char *)calloc(width+1, sizeof(char));
    if(p!=NULL){
        switch(type){
            case NUMBER_BASE16:
                if(bits<=8)
                    snprintf(mybuff, 256, "%s%02X", prefix, *((u8 *)val));
                else if(bits<=16)
                    snprintf(mybuff, 256, "%s%04X", prefix, ntohs(*((u16 *)val)));
                else if(bits<=24)
                    snprintf(mybuff, 256, "%s%06X", prefix, ntohl(*((u32 *)val)));
                else
                    snprintf(mybuff, 256, "%s%08X", prefix, ntohl(*((u32 *)val)));
            break;
            case NUMBER_BASE10:
                if(bits<=8)
                    snprintf(mybuff, 256, "%s%u", prefix, *((u8 *)val));
                else if(bits<=16)
                    snprintf(mybuff, 256, "%s%u", prefix, ntohs(*((u16 *)val)));
                else if(bits<=24)
                    snprintf(mybuff, 256, "%s%u", prefix, ntohl(*((u32 *)val)));
                else
                    snprintf(mybuff, 256, "%s%u", prefix, ntohl(*((u32 *)val)));
            break;
            case NUMBER_BASE8:
                if(bits<=8)
                    snprintf(mybuff, 256, "%s%o", prefix, *((u8 *)val));
                else if(bits<=16)
                    snprintf(mybuff, 256, "%s%o", prefix, ntohs(*((u16 *)val)));
                else if(bits<=24)
                    snprintf(mybuff, 256, "%s%o", prefix, ntohl(*((u32 *)val)));
                else
                    snprintf(mybuff, 256, "%s%o", prefix, ntohl(*((u32 *)val)));
            break;
            case STRING_IPv4:
                snprintf(mybuff, 256, "%s", prefix);
                inet_ntop(AF_INET, val, mybuff+strlen(prefix), 256);
            break;
            case STRING_IPv6:
                snprintf(mybuff, 256, "%s", prefix);
                inet_ntop(AF_INET6, val, mybuff+strlen(prefix), 256);
            break;
        }
        centre_string(mybuff, p, width);
    }
    return p;
}


char *IPv4Header::toString(){

#define LINE_LEN 80+1
#define TOTAL_LINES 15
static char buffer[TOTAL_LINES][LINE_LEN];
int i=0;
u8 aux8;
u16 aux16;

char *pt[14];

aux8=this->getVersion();
pt[0]=format_field("V=", &aux8 , 4, NUMBER_BASE10);
aux8=this->getHeaderLength();
pt[1]=format_field("HL=", &aux8 , 4, NUMBER_BASE10);
pt[2]=format_field("TOS=", &this->h.ip_tos , 8, NUMBER_BASE10);
pt[3]=format_field("TLEN=", &this->h.ip_len , 16, NUMBER_BASE10);
pt[4]=format_field("ID=", &this->h.ip_id , 16, NUMBER_BASE10);
pt[5]= this->getRF() ? strdup("x") : strdup(" ");
pt[6]= this->getDF() ? strdup("D") : strdup(" ");
pt[7]= this->getMF() ? strdup("M") : strdup(" ");
aux16=this->getFragOffset();
pt[8]=format_field("OFF=", &aux16 , 13, NUMBER_BASE10);
pt[9]=format_field("TTL=", &this->h.ip_ttl , 8, NUMBER_BASE10);
pt[10]=format_field("NP=", &this->h.ip_p , 8, NUMBER_BASE10);
pt[11]=format_field("CSUM=", &this->h.ip_sum , 16, NUMBER_BASE16);
pt[12]=format_field("SRC=", &this->h.ip_src , 32, STRING_IPv4);
pt[13]=format_field("DST=", &this->h.ip_dst , 32, STRING_IPv4);


sprintf(buffer[i++], " 0                   1                   2                   3   \n");
sprintf(buffer[i++], " 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 \n");
sprintf(buffer[i++], "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
sprintf(buffer[i++], "|%s|%s|%s|%s|\n",pt[0],pt[1],pt[2],pt[3]);
sprintf(buffer[i++], "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
sprintf(buffer[i++], "|%s|%s|%s|%s|%s|\n", pt[4], pt[5], pt[6], pt[7], pt[8]);
sprintf(buffer[i++], "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
sprintf(buffer[i++], "|%s|%s|%s|\n",pt[9],pt[10],pt[11]);
sprintf(buffer[i++], "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
sprintf(buffer[i++], "|%s|\n", pt[12]);
sprintf(buffer[i++], "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
sprintf(buffer[i++], "|%s|\n", pt[13]);
sprintf(buffer[i++], "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
sprintf(buffer[i++], "|                    Options                    |    Padding    |\n");
sprintf(buffer[i++], "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
   
for(int j=0; j<TOTAL_LINES; j++){
    printf("%s", buffer[j]);
    //free(buffer[j]);
}

return NULL;

}




