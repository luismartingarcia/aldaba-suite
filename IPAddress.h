
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

#ifndef __IPADDRESS_H__
#define __IPADDRESS_H__ 1

#include "aldaba.h"

class IPAddress {

    private:
        
        int version;         /* IP version. MUST be one of AF_INET or AF_INET6 */
        struct in_addr ip4;  /* Holds an IPv4 address */
        struct in6_addr ip6; /* Holds an IPv6 address */

    private:
        void setVersion4();
        void setVersion6();

    public:

        /* Constructors and destructors */
        IPAddress();
        IPAddress(struct in_addr val);
        IPAddress(struct in6_addr val);
        ~IPAddress();
        bool operator==(const IPAddress& other) const;
        bool operator<(const IPAddress& other) const;
        bool operator>(const IPAddress& other) const;

        void reset();

        /* Aux methods */
        static bool isIPv4Address(const char *val);
        static bool isIPv6Address(const char *val);
        static bool isIPAddress(const char *val);
        static bool isHostname(const char *val);
        static int str2in_addr(const char *val, struct in_addr *address);
        static int str2in6_addr(const char *val, struct in6_addr *address);
        static int resolve(const char *hostname, struct sockaddr_storage *ss, size_t *sslen, int family);
        int setAddress(const char *val);
        void setAddress(struct in_addr val);
        void setAddress(struct in6_addr val);
        void setAddress(struct sockaddr_storage val);
        void setAddress(struct sockaddr_in val);
        void setAddress(struct sockaddr_in6 val);
        void setAddress(struct sockaddr_in *val);
        void setAddress(struct sockaddr_in6 *val);
        int setIPv4Address(const char *val);
        int setIPv6Address(const char *val);
        struct in_addr getIPv4Address();
        int getIPv4Address(struct sockaddr_in *val);
        struct in6_addr getIPv6Address();
        int getIPv6Address(struct sockaddr_in6 *val);
        int getAddress(struct sockaddr_storage *val);
        int getVersion();
        const char *toString();
        const char *toString(char *buffer, size_t bufferlen);
        static int setSockaddrPort(struct sockaddr_storage *ss, u16 port);



}; /* End of class IPAddress */

#endif /* __IPADDRESS_H__ */
