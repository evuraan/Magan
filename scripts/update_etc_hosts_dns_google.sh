#!/bin/bash 
# Author: evuraan@gmail.com

host dns.Google.com 8.8.8.8 |awk '/has address/ {print $NF}' | while read a 
do
	grep -qw $a /etc/hosts || { 
		b=$(date)
		sed -i '/dns.google.com/d' /etc/hosts
		echo "$a dns.google.com #updated: $b" >> /etc/hosts
	}
done
