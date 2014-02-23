
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

#ifndef __ARGPARSERSERVER_H__
#define __ARGPARSERSERVER_H__ 1

#include "aldaba.h"
#include "GeneralOps.h"
#include "ServerOps.h"
#include "IPAddress.h"
#include "ArgParser.h"

class ArgParserServer : public ArgParser {

  public:
    ArgParserServer();
    ~ArgParserServer();
    static int parse_arguments(int argc, char *argv[], ServerOps *opt);
    static void display_version();
    static void display_usage();
    static int handle_cmdline_args(int argc, char *argv[],  ServerOps *opt);
    static int display_help();
    static int config_file_parser(ServerOps *opt, const char * filename);
    static int process_arg_promiscuous(ServerOps *opt, const char * arg);
    static int process_arg_open_time(ServerOps *opt, const char * arg);
    static int process_arg_daemonize(ServerOps *opt, const char * arg);
    static int process_arg_linkhdrlen(ServerOps *opt, const char * arg);
    static int process_arg_bpf(ServerOps *opt, const char * arg);

}; /* End of class ArgParserServer */

#endif /* __ARGPARSERSERVER_H__ */
