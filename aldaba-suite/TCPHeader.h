
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

#ifndef __TCPHEADER_H__
#define __TCPHEADER_H__ 1

#include "TransportLayerElement.h"

/* TCP FLAGS */
#define TH_FIN   0x01
#define TH_SYN   0x02
#define TH_RST   0x04
#define TH_PUSH  0x08
#define TH_ACK   0x10
#define TH_URG   0x20
#define TH_ECN   0x40
#define TH_CWR   0x80

#define TCP_HEADER_LEN 20
#define MAX_TCP_OPTIONS_LEN 40

class TCPHeader : public TransportLayerElement {

    private:

        struct my_tcp_hdr {
            u16 th_sport;                      /* Source port                 */
            u16 th_dport;                      /* Destination port            */
            u32 th_seq;                        /* Sequence number             */
            u32 th_ack;                        /* Acknowledgement number      */
            #if WORDS_BIGENDIAN
                u8 th_off:4;                   /* Data offset                 */
                u8 th_x2:4;                    /* Reserved                    */
            #else
                u8 th_x2:4;                    /* Reserved                    */
                u8 th_off:4;                   /* Data offset                 */
            #endif
            u8 th_flags;                       /* Flags                       */
            u16 th_win;                        /* Window size                 */
            u16 th_sum;                        /* Checksum                    */
            u16 th_urp;                        /* Urgent pointer              */

            u8 options[MAX_TCP_OPTIONS_LEN ];  /* Space for TCP Options       */
        }h;

        struct tcpopt_hdr {
            u_char type;   /* type   */
            u_char len;    /* length */
            u_short value; /* value  */
        };

        int tcpoptlen; /**< Length of TCP options */

    public:

        TCPHeader();
        ~TCPHeader();
        void reset();
        u8 *getBufferPointer();
        int storeRecvData(const u8 *buf, size_t len);
        int validate();
        
        int setSrcPort(u16 p);
        u16 getSrcPort();

        int setDstPort(u16 p);
        u16 getDstPort();

        int setSeq(u32 p);
        u32 getSeq();

        int setAck(u32 p);
        u32 getAck();

        int setOffset(u8 o);
        int setOffset();
        u8 getOffset();

        int setFlags(u8 f);
        u8 getFlags();
        bool setCWR();
        bool unsetCWR();
        bool getCWR();
        bool setECE();
        bool unsetECE();
        bool getECE();
        bool setECN();
        bool unsetECN();
        bool getECN();
        bool setURG();
        bool unsetURG();
        bool getURG();
        bool setACK();
        bool unsetACK();
        bool getACK();
        bool setPUSH();
        bool unsetPUSH();
        bool getPUSH();
        bool setRST();
        bool unsetRST();
        bool getRST();
        bool setSYN();
        bool unsetSYN();
        bool getSYN();
        bool setFIN();
        bool unsetFIN();
        bool getFIN();

        int setWindow(u16 p);
        u16 getWindow();

        int setUrgPointer(u16 l);
        u16 getUrgPointer();

        int setSum(u16 s);
        int setSum(struct in_addr source, struct in_addr destination);
        u16 getSum();

}; /* End of class TCPHeader */

#endif /* __TCPHEADER_H__ */