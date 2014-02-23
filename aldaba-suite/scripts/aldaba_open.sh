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

#echo "This script should open port number $1/$2 to address $3"


# Here is an example:
IPT="/sbin/iptables"

# Accept inbound packets
  
   # Add rules for input/output
   $IPT -w -A INPUT -p tcp -j ACCEPT --dport $1  -s $3 -m state --state NEW,ESTABLISHED
   $IPT -w -A OUTPUT -p tcp -j ACCEPT --sport $1 -d $3 -m state --state NEW,ESTABLISHED

   echo "Opening port $1 to $3. Accepting new connections for $4 seconds..."

   # Wait for $4 seconds to close the ports
   for (( i=$4; i>0; i--)); do
      sleep 1 &
   	wait
   done

   if [[ ! `$IPT -w -L INPUT -n --line-numbers | grep $3 | grep $1 | grep RELATED | wc -l` > 0 ]]; then
      $IPT -w -R INPUT `$IPT -L INPUT -n --line-numbers | grep $3 | grep $1 | grep NEW | awk 'NR==1 {print $1}'` -p tcp -j ACCEPT --dport $1 -s $3 -m state --state ESTABLISHED,RELATED > /dev/null 2>&1
      $IPT -w -R OUTPUT `$IPT -L OUTPUT -n --line-numbers | grep $3 | grep $1 | grep NEW | awk 'NR==1 {print $1}'` -p tcp -j ACCEPT --sport $1 -d $3 -m state --state ESTABLISHED,RELATED > /dev/null 2>&1
   else
      $IPT -w -D INPUT `$IPT -L INPUT -n --line-numbers | grep $3 | grep $1 | grep NEW | awk 'NR==1 {print $1}'`
      $IPT -w -D OUTPUT `$IPT -L OUTPUT -n --line-numbers | grep $3 | grep $1 | grep NEW | awk 'NR==1 {print $1}'`
   fi
   
   echo "Timer expired. No more connections will be accepted on port $1 from $3."

   exit 0
