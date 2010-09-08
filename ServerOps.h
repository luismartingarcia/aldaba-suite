
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

#ifndef __SERVEROPS_H__
#define __SERVEROPS_H__ 1

#include "aldaba.h"
#include "IPAddress.h"
#include "GeneralOps.h"


class ServerOps : public GeneralOps {

    private:

        bool promiscuous;
        bool promiscuous_set;

        bool daemonize;
        bool daemonize_set;

        u16 data_link_header_len;
        bool data_link_header_len_set;

        char bpf_filter[MAX_BPF_FILTER_LEN];
        bool bpf_filter_set;

    public:

        /* Constructors / Destructors */
        ServerOps();
        ~ServerOps();
        void reset();

        int setPromiscuous(bool val);
        bool getPromiscuous();
        bool issetPromiscuous();

        int setDaemonize(bool val);
        bool getDaemonize();
        bool issetDaemonize();

        int setLinkHeaderLength(u16 val);
        u16 getLinkHeaderLength();
        bool issetLinkHeaderLength();

        int setBPF(const char * val);
        char *getBPF();
        bool issetBPF();

        int validateConfiguration();

}; /* End of class ServerOps */

#endif /* __SERVEROPS_H__ */
