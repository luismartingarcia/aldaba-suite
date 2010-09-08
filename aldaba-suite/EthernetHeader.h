
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

#ifndef ETHERNETHEADER_H
#define ETHERNETHEADER_H 1

#include "DataLinkLayerElement.h"

/* Ether Types. (From RFC 5342 http://www.rfc-editor.org/rfc/rfc5342.txt)     */
#define ETHTYPE_IPV4       0x0800 /* Internet Protocol Version 4              */
#define ETHTYPE_ARP        0x0806 /* Address Resolution Protocol              */
#define ETHTYPE_FRAMERELAY 0x0808 /* Frame Relay ARP                          */
#define ETHTYPE_PPTP       0x880B /* Point-to-Point Tunneling Protocol        */
#define ETHTYPE_GSMP       0x880C /* General Switch Management Protocol       */
#define ETHTYPE_RARP       0x8035 /* Reverse Address Resolution Protocol      */
#define ETHTYPE_IPV6       0x86DD /* Internet Protocol Version 6              */
#define ETHTYPE_MPLS       0x8847 /* MPLS                                     */
#define ETHTYPE_MPS_UAL    0x8848 /* MPLS with upstream-assigned label        */
#define ETHTYPE_MCAP       0x8861 /* Multicast Channel Allocation Protocol    */
#define ETHTYPE_PPPOE_D    0x8863 /* PPP over Ethernet Discovery Stage        */
#define ETHTYPE_PPOE_S     0x8864 /* PPP over Ethernet Session Stage          */
#define ETHTYPE_CTAG       0x8100 /* Customer VLAN Tag Type                   */
#define ETHTYPE_EPON       0x8808 /* Ethernet Passive Optical Network         */
#define ETHTYPE_PBNAC      0x888E /* Port-based network access control        */
#define ETHTYPE_STAG       0x88A8 /* Service VLAN tag identifier              */
#define ETHTYPE_ETHEXP1    0x88B5 /* Local Experimental Ethertype             */
#define ETHTYPE_ETHEXP2    0x88B6 /* Local Experimental Ethertype             */
#define ETHTYPE_ETHOUI     0x88B7 /* OUI Extended Ethertype                   */
#define ETHTYPE_PREAUTH    0x88C7 /* Pre-Authentication                       */
#define ETHTYPE_LLDP       0x88CC /* Link Layer Discovery Protocol (LLDP)     */
#define ETHTYPE_MACSEC     0x88E5 /* Media Access Control Security            */
#define ETHTYPE_MVRP       0x88F5 /* Multiple VLAN Registration Protocol      */
#define ETHTYPE_MMRP       0x88F6 /* Multiple Multicast Registration Protocol */
#define ETHTYPE_FRRR       0x890D /* Fast Roaming Remote Request              */

/* Lengths */
#define ETH_HEADER_LEN 14
#define ETH_FOOTER_LEN 2

class EthernetHeader : public DataLinkLayerElement {

    private:

        struct my_eth_hdr{
          u8 eth_dmac[6];
          u8 eth_smac[6];
          u16 eth_type;
        }h;

        struct my_eth_ftr{
            u32 crc;
        }f;

    public:
    
        EthernetHeader();
        ~EthernetHeader();
        u8 *getBufferPointer();

        int setSrcMAC(u8 *m);
        int setSrcMAC(char *m);
        u8 *getSrcMAC();

        int setDstMAC(u8 *m);
        int setDstMAC(char *m);
        u8 *getDstMAC();

        int setEtherType(u16 val);
        u16 getEtherType();

        int setSum();
        int setSum(u32 s);
        int setSumRandom();
        u32 getSum();

};

#endif
