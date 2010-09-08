
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
#ifndef __SPAHEADER_H__
#define __SPAHEADER_H__ 1

#include "TransportLayerElement.h"
#include "IPAddress.h"

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 0 |                                                               |
   +--                                                           --+
 1 |                                                               |
   +--                   Initialization Vector                   --+
 2 |                                                               |
   +--                                                           --+
 3 |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 4 |  SPA Version  |  IP Version   |Prot#1 |Actn#1 |Prot#2 |Actn#2 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 5 |            Port #1            |            Port #2            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 6 |                          Magic Number                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 7 |                            Reserved                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 8 |                                                               |
   +--                                                           --+
 9 |                                                               |
   +--                   Authorized IP Address                   --+
10 |                                                               |
   +--                                                           --+
11 |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
12 |                           Timestamp                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
13 |                                                               |
   +--                                                           --+
14 |                                                               |
   +--                           Nonce                           --+
15 |                                                               |
   +--                                                           --+
16 |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
17 |                                                               |
   +--                                                           --+
18 |                                                               |
   +--                          Username                         --+
19 |                                                               |
   +--                                                           --+
20 |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
21 |                                                               |
 . .                                                               .
 . .                           User Data                           .
 . .                                                               .
27 |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
28 |                                                               |
 . .                                                               .
 . .                   Message Authentication Code                 .
 . .                                                               .
35 |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/



/* LENGTHS */
#define SPA_IV_LEN 16
#define SPA_NONCE_LEN 16
#define SPA_ADDR_LEN 16
#define SPA_USERNAME_LEN 16
#define SPA_USERDATA_LEN 28
#define SPA_MAC_LEN 32
#define SPA_HEADER_LEN 144

/* CONSTANTS DEFINED IN THE RFC */
/* IP Versions */
#define SPA_IP_VERSION_4  0x04
#define SPA_IP_VERSION_6  0x06

/* Port protocols */
#define SPA_PORT_PROTO_TCP  0x1
#define SPA_PORT_PROTO_UDP  0x2
#define SPA_PORT_PROTO_SCTP 0x3

/* Port actions */
#define SPA_ACTION_OPEN    0x1
#define SPA_ACTION_CLOSE   0x2
#define SPA_ACTION_FORWARD 0x3

/* Misc */
#define SPA_CURRENT_VERSION 0x01
#define SPA_MAGIC_NUMBER 0xA1DABA77


class SPAHeader : public TransportLayerElement {

    private:
    
        struct spa_hdr{
            u8 iv[SPA_IV_LEN];
            u8 spa_version;
            u8 ip_version;
        #if WORDS_BIGENDIAN
            u8 proto_p1:4;
            u8 action_p1:4;
        #else
            u8 action_p1:4;
            u8 proto_p1:4;
        #endif
        #if WORDS_BIGENDIAN
            u8 proto_p2:4;
            u8 action_p2:4;
        #else
            u8 action_p2:4;
            u8 proto_p2:4;
        #endif
            u16 port1;
            u16 port2;
            u32 magic;
            u32 reserved;
            u8 address[SPA_ADDR_LEN];
            u32 timestamp;
            u8 nonce[SPA_NONCE_LEN];
            char username[SPA_USERNAME_LEN];
            u8 userdata[SPA_USERDATA_LEN];
            u8 mac[SPA_MAC_LEN];
        }__attribute__((__packed__));
        typedef struct spa_hdr spahdr_t;
        spahdr_t h;

    public:

        SPAHeader();
        ~SPAHeader();
        void reset();
        u8 *getBufferPointer();
        int storeRecvData(const u8 *buf, size_t len);
        int validate();

        int setInitializationVector(u8 *val);
        u8 *getInitializationVector();

        int setSPAVersion(u8 val);
        u8 getSPAVersion();

        int setIPVersion(u8 val);
        u8 getIPVersion();

        int setProtocolPort1(u8 val);
        u8 getProtocolPort1();

        int setActionPort1(u8 val);
        u8 getActionPort1();

        int setProtocolPort2(u8 val);
        u8 getProtocolPort2();

        int setActionPort2(u8 val);
        u8 getActionPort2();

        int setPort1(u16 val);
        u16 getPort1();

        int setPort2(u16 val);
        u16 getPort2();

        int setMagicNumber(u32 val);
        u32 getMagicNumber();

        int setReserved(u32 val);
        u32 getReserved();

        int setAddress(u8 *val);
        int setAddress(struct in_addr addr);
        int setAddress(struct in6_addr addr);
        IPAddress getAddress();
        int getAddress(struct in_addr *addr);
        int getAddress(struct in6_addr *addr);

        int setTimestamp(u32 val);
        u32 getTimestamp();

        int setNonce(u8 *val);
        u8 *getNonce();

        int setUsername(const char *val);
        char *getUsername();

        int setUserdata(u8 *val);
        u8 *getUserdata();

        int setMAC(u8 *val);
        int setMAC(u8 *key, size_t keylen);
        u8 *getMAC();
        int verifyMAC(u8 *key, size_t keylen);

        int encrypt(int cipher, int mode, u8 *key, size_t keylen);
        int decrypt(int cipher, int mode, u8 *key, size_t keylen);

        char *toString();

}; /* End of class SPAHeader */

#endif /* __SPAHEADER_H__ */

