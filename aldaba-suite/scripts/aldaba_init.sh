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
echo "This script should initialize the local firewall"
exit 0;


#Here is an example:
#
#IPT="/sbin/iptables"

# Flush old rules, old custom tables
#	$IPT --flush
#	$IPT --delete-chain

# Set default policies for all three default chains
#	$IPT -P INPUT DROP
#	$IPT -P FORWARD DROP
#   $IPT -P OUTPUT DROP 

# Enable free use of loopback interfaces
#	$IPT -A INPUT -i lo -j ACCEPT
#	$IPT -A OUTPUT -o lo -j ACCEPT

# All TCP sessions should begin with SYN
#	$IPT -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

#   exit 0
