
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

#ifndef __PKDATALIGHT4_H__
#define __PKDATALIGHT4_H__ 1

#include "ApplicationLayerElement.h"
#include "IPAddress.h"

#define PK_LIGHT_IPv4_DATA_LEN 8

/**
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 0 |                    Authorized IPv4 Address                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 1 |           Knock Port          | Message Authentication Code |A|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 */

class PKDataLight4 : public ApplicationLayerElement {

    private:
        
        struct pk_light_header_ipv4{
            struct in_addr knock_ip;
            u16 knock_port;
            u16 mac;
        }__attribute__((__packed__));

        typedef struct pk_light_header_ipv4 pk_light_header_ipv4_t;
        
        pk_light_header_ipv4_t h;

    protected:
        
        u8 *getBufferPointer();
        u8 *getBufferPointer(u32 *len);
        int setKnockData(u8 *buffer, u32 *final_len, IPAddress ip, tcp_port_t port, int action, u8 *key, size_t keylen);

    public:

        PKDataLight4();
        ~PKDataLight4();
        void reset();
        int storeRecvData(const u8 *buf, size_t len);

        void getKnockData(u8 *buff, u32 *final_len);
        u8 *getKnockData(u32 *len);
        u8 *getKnockData();
        int setKnockData(u8 *buff);
        int setKnockData(IPAddress ip, tcp_port_t port, int action, u8 *key, size_t keylen);

        IPAddress getAddress();
        tcp_port_t getPort();
        int getAction();
        bool validateKnockData(u8 *key, size_t keylen);
        const char *toString();

};

#endif /* __PKDATALIGHT4_H__ */
