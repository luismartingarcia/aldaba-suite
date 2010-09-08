
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

#ifndef __TOOLS_H__
#define __TOOLS_H__ 1

#include "aldaba.h"

int isipaddr(const char *ipaddr);
int istcpport(long int portn);
int istcpport(int portn);
unsigned short in_cksum(unsigned short *addr, int len);
int daemonize(void);
int gets_noecho(char *buffer, int buflen);
int gets_noecho_stars(char *buffer, int buflen);
long int get_decent_random_seed(int seed);
int fill_buffer_with_random_data(char *buffer, int buffer_len);
int display_table_header(int mode, int family);
int display_table_delimiter(int technique);
int print_Ethernet_header(int vblevel, char *packet);
int print_UDP_IP_header(int vblevel, char *packet);
int print_TCP_IP_header(int vblevel, char *packet);
int wipe_buffer(unsigned char *buffer, int len);
void cleanup(void);
int getinterfaceaddr(char *iface_name, struct in_addr *ip);
int setSocketNonBlocking(int fd);
int setSocketBlocking(int fd);
int removechar(char *string, char c);
int replacechar(char *string, char oldchar, char newchar);
int removesubstring(char *string, char *sub);
char *find_and_replace(const char *src, const char *from, const char *to);
int removecolon(char *string);
char *hexdump(const unsigned char *cp, u32 length);
int print_hexdump(const u8 *cp, u32 length);
int print_hexdump(int vblevel, const u8 *cp, u32 length);
int hex2str(int vblevel, const u8 *cp, u32 length);
int hex2strln(int vblevel, const u8 *cp, u32 length);
int remove_duplicate_whitespace(char *buffer);
int char_occurrences(const char *buffer, char test);
int unspan(char *header);
u16 endian_swap(u16 val);
u32 endian_swap(u32 val);
u16 toLittleEndian(u16 val);
u32 toLittleEndian(u32 val);
int testEndianness(void);
u16 ltohs(u16 little);
u32 ltohl(u32 little);
u16 htols(u16 host);
u32 htoll(u32 host);
int strcmp_wildcarded(const char *s1, const char *s2, const char wildcard);
int strncmp_wildcarded(const char *s1, const char *s2, const char wildcard, int n);
int strcmp_wildcarded(const char *s1, const char *s2);
char *size2ascii(u32 bytes, char *buff, int bufflen);
int tokenize(const char *separator, char *buffer, size_t bufferlen, char **tokenlist, size_t tokenlistsize);
int tokenize_single_tokens(const char *separator, char *buffer, char **tokenlist, size_t tokenlistsize);
const char *cipher2ascii(int cipher);
const char *chipermode2ascii(int mode);
int parseMAC(const char *txt, u8 *targetbuff);
int parse_ip_options(const char *txt, u8 *data, int datalen, int* firsthopoff, int* lasthopoff, char *errstr, size_t errstrlen);
char *format_ip_options(u8* ipopt, int ipoptlen);
unsigned short tcpudp_cksum(const struct in_addr *src, const struct in_addr *dst, u8 proto, u16 len, const void *hstart);
int set_up_socket_ipv6(int rawfd, char *device);
u16 tcp_sum(unsigned char *tcphdr, u32 hdrlen, struct in_addr src_ip, struct in_addr dst_ip);

char *select_iface_pcap();
int get_iface_addr_pcap(const char *ifname, struct sockaddr_storage *ss, int family);
char *select_iface_ioctl();
int get_iface_addr_ioctl(const char *ifname, struct sockaddr_storage *ss, int family);

char *select_iface(int family);
int get_iface_addr(const char *ifname, struct sockaddr_storage *ss, int family);

u32 field2len(int field);
int get_link_header_length(int dlt_type);

int parse_u8(const char *str, u8 *dstbuff);
int parse_u16(const char *str, u16 *dstbuff);
int parse_u32(const char *str, u32 *dstbuff);

tcp_port_t *generate_random_portlist(size_t howmany, tcp_port_t *toinclude, size_t toinclude_len);


bool isinlist_u8(u8 *list, size_t listlen, u8 testvalue);
bool isinlist_u16(u16 *list, size_t listlen, u16 testvalue);
bool isinlist_u32(u32 *list, size_t listlen, u32 testvalue);
size_t *generate_unique_indexes(size_t number, size_t max);
int replace_duplicated_indexes(size_t *list, size_t list_len, size_t maxval);
int replace_duplicated_u16(u16 *list, size_t list_len, u16 maxval, u16 *excludevalues, size_t evalueslen);
int url_encode(const char *src, char *to, size_t to_len);
int url_decode(const char *src, char *to, size_t to_len);
bool starts_with(const char *string, const char *start);
size_t read_until(int fd, char *buff, size_t bufflen, const char *delimiter);

#endif /* __TOOLS_H__ */
