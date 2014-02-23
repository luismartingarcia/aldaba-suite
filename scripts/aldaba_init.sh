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
# This script should contain the necessary commands to set up system's firewall.
# The script is called everytime the Aldaba Server is started. It shouls
# normally instruct the firewall to drop all incoming packets.
# It should return 0 on success and -1 in case of error.
#echo "This script should initialize the local firewall"

#Here is an example:
#
IPT="/sbin/iptables"
BACKUPDIR=$1

#saving the actual state
/sbin/iptables-save > ${BACKUPDIR}/iptables-backup.fw

# Flush old rules, old custom tables
$IPT -w --flush
$IPT -w --delete-chain

# Default action: drop
$IPT -w -P INPUT DROP
$IPT -w -P FORWARD DROP

# Allow initiating connections from this host
$IPT -w -P OUTPUT ACCEPT
$IPT -w -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# Enable free use of loopback interfaces
$IPT -w -A INPUT -i lo -j ACCEPT
$IPT -w -A OUTPUT -o lo -j ACCEPT













exit 0

