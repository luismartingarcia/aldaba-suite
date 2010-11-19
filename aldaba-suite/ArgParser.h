
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

#ifndef _ALDABAPARSER_H_
#define _ALDABAPARSER_H_ 1

#include "aldaba.h"
#include "GeneralOps.h"
#include "GeneralOps.h"
#include "IPAddress.h"

class ArgParser {

  public:

    ArgParser();
    ~ArgParser();

    static int parse_portlist(const char *portlist, GeneralOps *opt );
    static int process_arg_passphrase(GeneralOps *opt, const char * arg);
    static int process_arg_port_sequence(GeneralOps *opt, const char * arg);
    static int process_arg_interface(GeneralOps *opt, const char * arg);
    static int process_arg_verbosity(GeneralOps *opt, const char * arg);
    static int process_arg_technique(GeneralOps *opt, const char * arg);
    static int process_arg_quiet(GeneralOps *opt);
    static int process_arg_debug(GeneralOps *opt);
    static int process_arg_cipher(GeneralOps *opt, const char * arg);
    static int process_arg_field(GeneralOps *opt, const char * arg);
    static int process_arg_auth(GeneralOps *opt, const char * arg);
    static int process_arg_ssh_cookie(GeneralOps *opt, const char * arg);

}; /* End of class ArgParser*/

#endif /* _ALDABAPARSER_H_ */
