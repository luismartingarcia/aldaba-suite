
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

#ifndef __HTTP_HDR_H__
#define __HTTP_HDR_H__ 1

#include "PacketElement.h"
#include <string>

#define HTTP_HDR_MAX_LEN 512

#define HTTP_USER_AGENT          0xA2
#define HTTP_GET                 0xA4
#define HTTP_HOST                0xA5
#define HTTP_CONNECTION          0xA6
#define HTTP_SERVER              0xA7
#define HTTP_STD_RESPONSE_CODE   0xA8
#define HTTP_CONTENT_TYPE        0xA9
#define HTTP_CONTENT_LENGTH      0xAA
#define HTTP_CRLF                0xAC
#define HTTP_UNKNOWN             0xAD

class HTTPHeader : public PacketElement {
    
    private:

        char h[HTTP_HDR_MAX_LEN];

    public:

        HTTPHeader();
        ~HTTPHeader();
        u8 *getBufferPointer();
        int reset();
        static int extractCodeFromHTTPResponse(char *msg);
        int extractCodeFromHTTPResponse();
        static double extractVersionHTTPResponse(char *msg);
        static bool isHTTP11(char *msg);
        int addUserAgentHeader(const char *agent);
        int addHostHeader(const char *hostname);
        int addConnectionCloseHeader();
        int addCRLF();
        int addGET4FileHeader(const char *filename);
        int tokenizePacket(char *buffer, size_t bufferlen, char **tokenlist, size_t tokenlistsize);
        int storeRecvMessage(u8 *buf, size_t len);
        int header2type(char *header);
        int header2type();

};
  
#endif /* __HTTP_HDR_H__ */

