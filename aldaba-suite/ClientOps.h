
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

/** \file filename.ext
  * \brief Short description. */

#ifndef __CLIENTOPS_H__
#define __CLIENTOPS_H__ 1

#include "aldaba.h"
#include "IPAddress.h"
#include "GeneralOps.h"


class ClientOps : public GeneralOps {

    private:

        char hostname[MAX_HOSTNAME_LEN+1]; /**< Target host name      */
        bool hostname_set;

        IPAddress dst_ip; /**< Target host IP Address                 */
        bool dst_ip_set;

        IPAddress src_ip; /**< Source IP Address                      */
        bool src_ip_set;

        bool do_resolution;
        IPAddress address_resolver; /**< External IP resolving service */
        bool address_resolver_set;

        IPAddress knock_ip; /**< Knock IP (IP to which the port will be opened to*/
        bool knock_ip_set;

        tcp_port_t knock_ports[MAX_KNOCK_PORTS]; /**< Knock Port (port to open)         */
        size_t knock_ports_set;

        u8 knock_port_protos[MAX_KNOCK_PORTS];
        size_t knock_port_protos_set;

        vector<IPAddress> decoys; /**< List of decoy hosts            */
        bool decoys_set;

        int knock_actions[MAX_KNOCK_PORTS]; /**< Action to take (open/close port) */
        size_t knock_actions_set;

        tcp_port_t *noise_ports;
        u32 noise; /**< Number of Noise packets to send */
        bool noise_set;

        u32 delay; /**< Delay between sent packets */
        bool delay_set;

    public:

        /* Constructors / Destructors */
        ClientOps();
        ~ClientOps();
        void reset();

        int setHostname(const char *val);
        char *getHostname();
        bool issetHostname();

        int setDestinationIP(IPAddress val);
        int setDestinationIP(const char *val);
        IPAddress getDestinationIP();
        bool issetDestinationIP();

        int setSourceIP(IPAddress val);
        int setSourceIP(const char *val);
        IPAddress getSourceIP();
        bool issetSourceIP();

        int resolve(bool val);
        bool resolve();
        int setAddressResolver(IPAddress val);
        int setAddressResolver(const char *val);
        IPAddress getAddressResolver();
        bool issetAddressResolver();
        int resolveIP(IPAddress *val);

        int setKnockIP(IPAddress val);
        int setKnockIP(const char *val);
        IPAddress getKnockIP();
        bool issetKnockIP();

        int setKnockPort(tcp_port_t val);
        tcp_port_t getKnockPort(size_t index);
        bool issetKnockPort();
        bool issetKnockPort(size_t index);

        int setKnockPortProto(u8 val);
        u8 getKnockPortProto(size_t index);
        bool issetKnockPortProto(size_t index);

        int addDecoy(IPAddress val);
        IPAddress *getDecoy(size_t index);
        bool issetDecoys();
        size_t getNumberOfDecoys();

        int setAction(int val);
        int getAction(size_t index);
        bool issetAction(size_t index);

        int setNoisePackets(u16 val);
        u16 getNoisePackets();
        bool issetNoisePackets();
        int generateNoisePorts();
        tcp_port_t *getNoisePortList();

        int setDelay(u32 val);
        u32 getDelay();
        bool issetDelay();

        int validateConfiguration();

        const char *select_interface();

}; /* End of class ClientOps */

#endif /* __CLIENTOPS_H__ */
