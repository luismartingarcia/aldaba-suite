
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

#include "post_auth.h"
#include "output.h"

/** Executes /etc/aldabad/aldaba_close.sh using the system() call. */
int close_port(tcp_port_t port, IPAddress ip, u8 proto){
  output(OUT_9, "%s()\n", __func__);
  char msg[2001];
  memset(msg, 0, sizeof(msg));
  const char *proto_str=NULL;
  if( (proto_str=portproto2str(proto))==NULL )
      return OP_FAILURE;
  snprintf(msg, 2000, "%s/%s %d %s %s &", SCRIPTSDIR, CLOSE_SCRIPT_NAME, port, proto_str, ip.toString());
  if( system(msg)==-1 )
      return OP_FAILURE;
  return OP_SUCCESS;
} /* End of close_port() */


/** Executes /etc/aldabad/aldaba_open.sh using the system() call. */
int open_port(tcp_port_t port, IPAddress ip, u8 proto, int time){
  output(OUT_9, "%s()\n", __func__);
  char msg[2001];
  memset(msg, 0, sizeof(msg));
  const char *proto_str=NULL;
  if( (proto_str=portproto2str(proto))==NULL )
      return OP_FAILURE;
  snprintf(msg, 2000, "%s/%s %d %s %s %i &", SCRIPTSDIR, OPEN_SCRIPT_NAME, port, proto_str, ip.toString(), time);
  if( system(msg)==-1 )
      return OP_FAILURE;
  return OP_SUCCESS;
} /* End of open_port() */


/** Executes /etc/aldabad/aldaba_forward.sh using the system() call. */
int forward_port(tcp_port_t from, tcp_port_t to, IPAddress ip, IPAddress fwd_ip, u8 proto){
  output(OUT_9, "%s()\n", __func__);
  char msg[2001];
  char in_ip_str[128];
  char fwd_ip_str[128];
  memset(msg, 0, sizeof(msg));
  const char *proto_str=NULL;
  if( (proto_str=portproto2str(proto))==NULL )
      return OP_FAILURE;
  snprintf(in_ip_str, 127,"%s", ip.toString());
  snprintf(fwd_ip_str, 127,"%s", fwd_ip.toString());
  snprintf(msg, 2000, "%s/%s %d %d %s %s %s &", SCRIPTSDIR, FORWARD_SCRIPT_NAME, from, to, proto_str, in_ip_str, fwd_ip_str);
  if( system(msg)==-1 )
      return OP_FAILURE;
  return OP_SUCCESS;
} /* End of forward_port() */


const char *portproto2str(u8 proto){
  static char buffer[16];
  switch(proto){
      case KNOCK_PORT_PROTO_ANY:
          snprintf(buffer, sizeof(buffer)-1, "any");
      break;
      case KNOCK_PORT_PROTO_TCP:
          snprintf(buffer, sizeof(buffer)-1, "tcp");
      break;
      case KNOCK_PORT_PROTO_UDP:
          snprintf(buffer, sizeof(buffer)-1, "udp");
      break;
      case KNOCK_PORT_PROTO_SCTP:
          snprintf(buffer, sizeof(buffer)-1, "sctp");
      break;

      default:
          return NULL;
      break;
  }
  return buffer;
}


