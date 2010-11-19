
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

#ifndef __GENERALOPS_H__
#define __GENERALOPS_H__ 1

#include "aldaba.h"
#include "IPAddress.h"
#include "Random.h"


class GeneralOps {

    private:

        char iface[MAX_IFACE_LEN+1]; /**< System's network interface  */
        bool iface_set;

        char path_cfile[MAX_PATH_LEN+1]; /**< Configuration file path */
        bool path_cfile_set;

        tcp_port_t pkseq[MAX_PKSEQ_PORTS]; /**< Knock Port Sequence   */
        size_t total_pkseq_ports;
        bool pkseq_set;

        int mode; /**< Operation mode (PK, SPA...) */
        bool mode_set;

        int field; /**< Header field to use to establish the PK covert channel */
        bool field_set;

        int auth_type; /**< Type of PK authentication (light, medium...) */
        bool auth_type_set;
        
        int cipher;  /**< Cipher suite to use (AES, Twofish...) */
        bool cipher_set;

        int cipher_mode; /**< Cipher block mode (ECB, CBC...) */
        bool cipher_mode_set;

        char passphrase[MAX_PASSPHRASE_LEN+1];
        bool passphrase_set;
        
        u8 cipher_key[MAX_CIPHER_KEY_LEN +1]; /**< Symmetric encryption key */
        int cipher_key_len;
        bool cipher_key_set;

        u8 mac_key[MAX_CIPHER_KEY_LEN +1]; /**< HMAC computation key */
        int mac_key_len;
        bool mac_key_set;

        int vb; /**< Verbosity level */
        bool vb_set;

        int lg; /**< Logging level */
        bool lg_set;

        bool is_root;  /**< True if current user has root privileges */
        bool is_root_set;

        int ip_version;
        bool ip_version_set;

        bool ssh_cookie;

    public:

        Random rand;

        /* Constructors / Destructors */
        GeneralOps();
        ~GeneralOps();
        void reset();

        int setInterface(const char *val);
        char *getInterface();
        bool issetInterface();

        int setConfigurationFile(const char *val);
        char *getConfigurationFile();
        bool issetConfigurationFile();

        int setSequencePort(tcp_port_t val);
        int derivePortSequence(size_t ports_needed);
        size_t getNumberOfSequencePorts();
        tcp_port_t getSequencePort(size_t index);
        bool issetSequencePorts();
        bool isSequencePort(tcp_port_t n);
        tcp_port_t *getSequencePortArray(size_t *final_ports);
        tcp_port_t *getSequencePortArray();
        const char *getSequencePorts_str();

        int setMode(int val);
        int getMode();
        bool issetMode();
        const char *getMode_str();

        int setAuthType(int val);
        int getAuthType();
        bool issetAuthType();
        const char *getAuthType_str();

        int setField(int val);
        int getField();
        bool issetField();
        const char *getField_str();

        int setCipher(int val);
        int getCipher();
        bool issetCipher();
        const char *getCipher_str();

        int setCipherMode(int val);
        int getCipherMode();
        bool issetCipherMode();
        const char *getCipherMode_str();

        int setPassphrase(const char *val);
        const char *getPassphrase();
        bool issetPassphrase();

        int computeCipherKey();
        u8 *getCipherKey();
        int getCipherKey(u8 *buff, int max_buff_len);
        int getCipherKeyLength();
        bool issetCipherKey();
        const char *getCipherKey_str();

        int computeMacKey();
        u8 *getMacKey();
        int getMacKey(u8 *buff, int max_buff_len);
        int getMacKeyLength();
        bool issetMacKey();
        const char *getMacKey_str();

        int setVerbosityLevel(int val);
        int getVerbosityLevel();
        bool issetVerbosityLevel();

        int setLoggingLevel(int val);
        int getLoggingLevel();
        bool issetLoggingLevel();

        int setIsRoot(bool val);
        bool isRoot();
        bool issetIsRoot();

        int setIPVersion(int family);
        int getIPVersion();
        bool issetIPVersion();
        const char *getIPVersion_str();

        int enableSSHCookie();
        int disableSSHCookie();
        bool SSHCookie();

}; /* End of class GeneralOps */

#endif /* __GENERALOPS_H__ */
