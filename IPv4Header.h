
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
#ifndef IPV4HEADER_H
#define IPV4HEADER_H 1

#include "NetworkLayerElement.h"

#define DEFAULT_IP_TTL 64          /* Default IP Time to Live        */
#define DEFAULT_IP_TOS 0           /* Default IP Type of Service     */
#define IP_RF 0x8000               /* Reserved fragment flag         */
#define IP_DF 0x4000               /* Dont fragment flag             */
#define IP_MF 0x2000               /* More fragments flag            */
#define IP_OFFMASK 0x1fff          /* Mask for fragmenting bits      */
#define MAX_IP_OPTIONS_LEN 40      /* Max Length for IP Options      */
        
class IPv4Header : public NetworkLayerElement {

    private:
    
        struct aldaba_ipv4_hdr {
        #if WORDS_BIGENDIAN
            u8 ip_v:4;                     /* Version                        */
            u8 ip_hl:4;                    /* Header length                  */
        #else
            u8 ip_hl:4;                    /* Header length                  */
            u8 ip_v:4;                     /* Version                        */
        #endif
            u8 ip_tos;                     /* Type of service                */
            u16 ip_len;                    /* Total length                   */
            u16 ip_id;                     /* Identification                 */
            u16 ip_off;                    /* Fragment offset field          */
            u8 ip_ttl;                     /* Time to live                   */
            u8 ip_p;                       /* Protocol                       */
            u16 ip_sum;                    /* Checksum                       */
            struct in_addr ip_src;         /* Source IP address              */
            struct in_addr ip_dst;         /* Destination IP address         */
            u8 options[MAX_IP_OPTIONS_LEN];  /* IP Options                   */
        }h;

        int ipoptlen; /**< Length of IP options */

    public:

    /* Misc */
    IPv4Header();
    ~IPv4Header();
    void reset();
    void zero();
    u8 *getBufferPointer();
    int storeRecvData(const u8 *buf, size_t len);
    int validate();

    /* IP version */
    int setVersion();
    u8 getVersion();

    /* Header Length */
    int setHeaderLength();
    int setHeaderLength(u8 l);
    u8 getHeaderLength();

    /* Type of Service */
    int setTOS(u8 v);
    u8 getTOS();

    /* Total lenght of the datagram */
    int setTotalLength();
    int setTotalLength(u16 l);
    u16 getTotalLength();

    /* Identification value */
    int setIdentification(u16 i);
    u16 getIdentification();

    /* Fragment Offset */
    int setFragOffset(u16 f);
    u16 getFragOffset();

    /* Flags */
    int setRF();
    int unsetRF();
    bool getRF();
    int setDF();
    int unsetDF();
    bool getDF();
    int setMF();
    int unsetMF();
    bool getMF();

    /* Time to live */
    int setTTL(u8 t);
    u8 getTTL();

    /* Next protocol */
    int setNextProto(u8 p);
    int setNextProto(const char *p);
    u8 getNextProto();

    /* Checksum */
    int setSum();
    int setSum(u16 s);
    u16 getSum();

    /* Destination IP */
    int setDstIP(struct in_addr d);
    struct in_addr getDstIP();

    /* Source IP */
    int setSrcIP(struct in_addr d);
    struct in_addr getSrcIP();

    char *toString();

}; /* End of class IPv4Header */

#endif
