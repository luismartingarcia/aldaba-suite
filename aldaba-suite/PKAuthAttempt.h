
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

#ifndef __PKAUTHATTEMPT_H__
#define __PKAUTHATTEMPT_H__ 1

#include "IPAddress.h"

class PKAuthAttempt {

    private:
        IPAddress clntaddr;        /* Address where the knock auth comes from */
        struct timeval timestamp;  /* Time first knock was received           */
        
        /* Knock data */
        u8 *knock_data;            /* Received knock data                     */
        size_t knock_chunk_len;    /* Length of each knock chunk              */

        /* Sequence ports */
        u16 total_sequence_ports;  /* Number of ports in the sequence         */
        u8 *hits;                  /* Ports that were actually reached        */

    public:
        PKAuthAttempt(size_t chunk_len, u16 seq_ports);
        ~PKAuthAttempt();
        void freeMem();
        void clear();
        int update(u8 *data, tcp_port_t port, tcp_port_t *seq);
        bool complete();

        u8 *getData();
        u8 *getData(size_t *final_len);

        int setAddress(IPAddress addr);
        IPAddress getAddress();

}; /* End of class PKAuthAttempt */

#endif /* __PKAUTHATTEMPT_H__ */
