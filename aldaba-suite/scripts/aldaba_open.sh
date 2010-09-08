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
# This script should contain the necessary commands to 
# open a port to a specific IP address.
# The information is given as command line arguments:
# $1 is the port number
# $2 is the port protocol
# $3 is the authorized IP address.
# It should return 0 on success and -1 in case of error.

echo "This script should open port number $1/$2 to address $3"
exit 0;

# Here is an example:
# IPT="/sbin/iptables"

# Accept inbound packets
#	$IPT -A INPUT -p tcp -j ACCEPT --dport $1  --src $2 -m state --state NEW
#   exit 0
