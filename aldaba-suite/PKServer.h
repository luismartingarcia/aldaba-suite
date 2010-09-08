
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

#ifndef __PKSERVER_H__
#define __PKSERVER_H__ 1

#include "IPAddress.h"
#include "IPv4Header.h"
#include "TCPHeader.h"
#include "PKDataLight4.h"
#include "PKDataLight6.h"
#include "PKDataStrong4.h"
#include "PKDataStrong6.h"
#include "PKAuthAttempt.h"
#include "Server.h"

class PKServer : public Server {

    private:
        vector<PKAuthAttempt *> auths;

        static u8 *extract_field_data(IPv4Header *ip4, TCPHeader *tcp, int field, size_t *final_len);

    public:
        PKServer();
        ~PKServer();
        void reset();
        int run();
        static char *getFilterString();
        static int post_auth(PKDataLight4 *pkdata);
        static int post_auth(PKDataLight6 *pkdata);
        static int post_auth(PKDataStrong4 *pkdata);
        static int post_auth(PKDataStrong6 *pkdata);
        static int post_auth(tcp_port_t port, bool open, IPAddress ip);
        int pk_packet_handler(u8 *args, const struct pcap_pkthdr* pkthdr, const u8 *packet);

        PKAuthAttempt *auth_new(size_t chunk_len, u16 seq_ports);
        PKAuthAttempt *auth_lookup(IPAddress addr);
        int auth_insert(PKAuthAttempt *);
        int auth_remove(IPAddress addr);
        int handle_complete_attempt(PKAuthAttempt *attempt);

}; /* End of class PKServer */

void pk_packet_handler_wrapper(u8 *args, const struct pcap_pkthdr* pkthdr, const u8 *packet);

#endif /* __PKSERVER_H__ */
