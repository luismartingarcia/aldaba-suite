
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

#ifndef IPV6HEADER_H
#define IPV6HEADER_H 1

#include "NetworkLayerElement.h"


#define DEFAULT_IPv6_TTL 64           /* Default IPv6 Hop Limit     */
#define DEFAULT_IPv6_FLOW 0           /* Default IPv6 Flow Label    */
#define DEFAULT_IPv6_TCLASS 0         /* Default IPv6 Traffic Class */

#define IPv6_HEADER_LEN 40

class IPv6Header : public NetworkLayerElement {

    private:
    
  /*  IPv6 Header Format:
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |Version| Traffic Class |             Flow Label                |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |         Payload Length        |  Next Header  |   Hop Limit   |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                                                               |
        +--                                                           --+
        |                                                               |
        +--                      Source Address                       --+
        |                                                               |
        +--                                                           --+
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                                                               |
        +--                                                           --+
        |                                                               |
        +--                    Destination Address                    --+
        |                                                               |
        +--                                                           --+
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */
    
        struct my_ipv6
        {
            u8  ip6_start[4];                /* Version, Traffic and Flow   */
            u16 ip6_len;                     /* Payload length              */
            u8  ip6_nh;                      /* Next Header                 */
            u8  ip6_hopl;                    /* Hop Limit                   */
            u8  ip6_src[16];                 /* Source IP Address           */
            u8  ip6_dst[16];                 /* Destination IP Address      */    
        }h;


    public:
    
        /* Misc */
        IPv6Header();
        ~IPv6Header();
        void reset();
        u8 *getBufferPointer();
        int storeRecvData(const u8 *buf, size_t len);
        int validate();
        
        /* IP version */
        int setVersion();
        int setVersion(u8 val);    
        u8 getVersion();

        /* Traffic class */
        int setTrafficClass(u8 val);
        u8 getTrafficClass();

        /* Flow Label */
        int setFlowLabel(u32 val);
        u32 getFlowLabel();
        
        /* Payload Length */
        int setPayloadLength(u16 val);
        int setPayloadLength();
        u16 getPayloadLength();
        
        /* Next Header */
        int setNextHeader(u8 val);
        int setNextHeader(const char *p);
        u8 getNextHeader();
        
        /* Hop Limit */
        int setHopLimit(u8 val);
        u8 getHopLimit();
        
        /* Source Address */
        int setSourceAddress(u8 *val);
        struct in6_addr getSourceAddress();
        
        /* Destination Address*/
        int setDestinationAddress(u8 *val);
        struct in6_addr getDestinationAddress();

};

#endif
