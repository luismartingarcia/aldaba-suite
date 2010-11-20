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
# forward  one port to another, for a specific IP.
# The information is given as command line arguments:
# $1 is the external port
# $2 is the internal port
# $3 is the port protocol
# $4 is the incoming IP address
# $5 is the target IP address
# It should return 0 on success and -1 in case of error.

echo "This script should forward traffic targetted to port $1/$3 from address $4 to port $2/$3 in address $5"
exit 0
