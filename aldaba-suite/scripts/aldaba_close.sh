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
# close a port to a specific IP address.
# The information is given as command line arguments:
# $1 is the port number
# $2 is the port protocol
# $3 is the IP address.
# It should return 0 on success and -1 in case of error.

#echo "This script should close port number $1/$2 to address $3"

# Here is an example:
   IPT="/sbin/iptables"

#   Drop inbound packets
    echo "Removing $3:$1 rules..."
    $IPT -w -D INPUT `$IPT -L INPUT -n --line-numbers | grep $3 | grep $1 | awk 'NR==1 {print $1}'`> /dev/null 2>&1
    $IPT -w -D OUTPUT `$IPT -L OUTPUT -n --line-numbers | grep $3 | grep $1 | awk 'NR==1 {print $1}'`> /dev/null 2>&1
    exit 0
