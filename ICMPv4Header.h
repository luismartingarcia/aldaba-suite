
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
#ifndef ICMPv4HEADER_H
#define ICMPv4HEADER_H 1

#include "NetworkLayerElement.h"

/* ICMP types and codes. These defines were originally taken from  Slirp 1.0
 * source file ip_icmp.h  http://slirp.sourceforge.net/ (BSD licensed) and
 * then, partially modified for Aldaba                                       */
#define ICMP_ECHOREPLY               0     /* Echo reply                     */
#define ICMP_UNREACH                 3     /* Destination unreachable:       */
#define    ICMP_UNREACH_NET            0   /*  --> Bad network               */
#define    ICMP_UNREACH_HOST           1   /*  --> Bad host                  */
#define    ICMP_UNREACH_PROTOCOL       2   /*  --> Bad protocol              */
#define    ICMP_UNREACH_PORT           3   /*  --> Bad port                  */
#define    ICMP_UNREACH_NEEDFRAG       4   /*  --> DF flag caused pkt drop   */
#define    ICMP_UNREACH_SRCFAIL        5   /*  --> Source route failed       */
#define    ICMP_UNREACH_NET_UNKNOWN    6   /*  --> Unknown network           */
#define    ICMP_UNREACH_HOST_UNKNOWN   7   /*  --> Unknown host              */
#define    ICMP_UNREACH_ISOLATED       8   /*  --> Source host isolated      */
#define    ICMP_UNREACH_NET_PROHIB     9   /*  --> Prohibited access         */
#define    ICMP_UNREACH_HOST_PROHIB    10  /*  --> Prohibited access         */
#define    ICMP_UNREACH_TOSNET         11  /*  --> Bad TOS for network       */
#define    ICMP_UNREACH_TOSHOST        12  /*  --> Bad TOS for host          */
#define    ICMP_UNREACH_COMM_PROHIB    13  /*  --> Prohibited communication  */
#define    ICMP_UNREACH_HOSTPRECEDENCE 14  /*  --> Host precedence violation */
#define    ICMP_UNREACH_PRECCUTOFF     15  /*  --> Precedence cutoff         */
#define ICMP_SOURCEQUENCH            4     /* Source Quench.                 */
#define ICMP_REDIRECT                5     /* Redirect:                      */
#define    ICMP_REDIRECT_NET           0   /*  --> For the network           */
#define    ICMP_REDIRECT_HOST          1   /*  --> For the host              */
#define    ICMP_REDIRECT_TOSNET        2   /*  --> For the TOS and network   */
#define    ICMP_REDIRECT_TOSHOST       3   /*  --> For the TOS and host      */
#define ICMP_ECHO                    8     /* Echo request                   */
#define ICMP_ROUTERADVERT            9     /* Router advertisement           */
#define    ICMP_ROUTERADVERT_MOBILE    16  /* Used by mobile IP agents       */
#define ICMP_ROUTERSOLICIT           10    /* Router solicitation            */
#define ICMP_TIMXCEED                11    /* Time exceeded:                 */
#define    ICMP_TIMXCEED_INTRANS       0   /*  --> TTL==0 in transit         */
#define    ICMP_TIMXCEED_REASS         1   /*  --> TTL==0 in reassembly      */
#define ICMP_PARAMPROB               12    /* Parameter problem              */
#define    ICMM_PARAMPROB_POINTER      0   /*  --> Pointer shows the problem */
#define    ICMP_PARAMPROB_OPTABSENT    1   /*  --> Option missing            */
#define    ICMP_PARAMPROB_BADLEN       2   /*  --> Bad datagram length       */
#define ICMP_TSTAMP                  13    /* Timestamp request              */
#define ICMP_TSTAMPREPLY             14    /* Timestamp reply                */
#define ICMP_INFO                    15    /* Information request            */
#define ICMP_INFOREPLY               16    /* Information reply              */
#define ICMP_MASK                    17    /* Address mask request           */
#define ICMP_MASKREPLY               18    /* Address mask reply             */
#define ICMP_TRACEROUTE              30    /* Traceroute                     */
#define    ICMP_TRACEROUTE_SUCCESS     0   /*  --> Dgram sent to next router */
#define    ICMP_TRACEROUTE_DROPPED     1   /*  --> Dgram was dropped         */


#define ICMP_PAYLOAD_LEN 1500


class ICMPv4Header : public NetworkLayerElement {

    private:
    
        struct my_icmpv4{
            u8 type;                     /* ICMP Message Type                        */
            u8 code;                     /* ICMP Message Code                        */
            u16 checksum;                /* Checksum                                 */
            union{
                u32 unused;              /* Dest unreach/Source quench/Time exceeded */
                u32 addr;                /* Redirect                                 */
                u8 pointer8_unused24[4]; /* Parameter problem                        */
                u8 num8_size8_time16[4]; /* Router advertisement                     */
                u16 id_seq[2];           /* Echo/Timestamp/Mask                      */
                u16 id_unused[2];        /* Traceroute                               */
                u32 f32;                 /* Generic name. One 32 bit word            */
                u16 f16[2];              /* Generic name. Two 16 bit words           */
                u8 f8[4];                /* Generic name. Four 8 bit workds          */
            }h3;          
            u8 data[ICMP_PAYLOAD_LEN]; /* Note -- first 4-12 bytes can be used for ICMP header */
        }h;
        
        int routeradventries; /* Internal count for Router Adverstisement entries */

    public:
 
        /* Misc */
        ICMPv4Header();
        ~ICMPv4Header();
        void reset();
        void zero();
        u8 *getBufferPointer();

        /* ICMP Type */
        int setType(u8 val);
        u8 getType();
        bool validateType();
        bool validateType(u8 val);

        /* Code */
        int setCode(u8 c);
        u8 getCode();
        bool validateCode();
        bool validateCode(u8 type, u8 code);

        /* Checksum */
        int setSum();
        int setSum(u16 s);
        u16 getSum();

        /* Dest unreach/Source quench/Time exceeded */
        int setUnused(u32 val);
        u32 getUnused();

        /* Redirect */
        int setPreferredRouter(u32 ipaddr);
        u32 getPreferredRouter();

        /* Parameter problem */
        int setPointer(u8 val);
        u8 getPointer();

        /* Router Solicitation */
        int setReserved( u32 val );
        u32 getReserved();

        /* Router advertisement */
        int setNumAddresses(u8 val);
        u8 getNumAddresses();
        int setAddrEntrySize(u8 val);
        u8 getAddrEntrySize();
        int setLifetime(u16 val);
        u16 getLifetime();
        int addRouterAdvEntry( u32 raddr, u32 pref);
        u8 *getRouterAdvEntries(int *num);
        int clearRouterAdvEntries();

        /* Echo/Timestamp/Mask */
        int setIdentifier(u16 val);
        u16 getIdentifier();
        int setSequence(u16 val);
        u16 getSequence();

        /* Timestamp only */
        int setOriginateTimestamp(u32 t);
        u32 getOriginateTimestamp();
        int setReceiveTimestamp(u32 t);
        u32 getReceiveTimestamp();
        int setTransmitTimestamp(u32 t);
        u32 getTransmitTimestamp();

        /* Traceroute */
        int setIDNumber(u16 val);
        u16 getIDNumber();

        /* Payload */
        int addPayload(const u8 *src, int len);
        int addPayload(const char *src);

        /* Misc */
        int getICMPHeaderLengthFromType( u8 type );

}; /* End of class ICMPv4Header */

#endif
