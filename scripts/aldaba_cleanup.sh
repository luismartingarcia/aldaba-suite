#!/bin/bash
#  ***************************************************************************
#  *                                                                         *
#  *                   _        _____               ____                     *
#  *           /\     | |      |  __ \      /\     |  _ \      /\            *
#  *          /  \    | |      | |  | |    /  \    | |_) |    /  \           *
#  *         / /\ \   | |      | |  | |   / /\ \   |  _ <    / /\ \          *
#  *        / ____ \  | |___   | |__| /  / ____ \  | |_) /  / ____ \         *
#  *       /_/    \_\ | ____|  |_____/  /_/    \_\ |____/  /_/    \_\        *
#  *                                                                         *
#  *    == {Port Knocking/Single Packet Authorization} Security Suite ==     *
#  *                                                                         *
#  ***************************************************************************
#
# This script should contain the necessary commands to leave system's firewall
# in given state after the Aldaba Server has been stopped.
# The script is called everytime the Aldaba Server is turned off. 

# It should return 0 on success and -1 in case of error.
#echo "This script should cleanup the local firewall policy"
BACKUPDIR=$1

if [[ -f ${BACKUPDIR}/iptables-backup.fw ]]; then
	/sbin/iptables-restore < ${BACKUPDIR}/iptables-backup.fw
	rm ${BACKUPDIR}/iptables-backup.fw
fi

exit 0
