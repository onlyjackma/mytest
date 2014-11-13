#!/bin/sh
load_kos(){
	VERSION=`uname -r`

	insmod /lib/modules/${VERSION}/cls_u32.ko 2>/dev/null
	insmod /lib/modules/${VERSION}/sch_sfq.ko 2>/dev/null
	insmod /lib/modules/${VERSION}/sch_htb.ko 2>/dev/null
}

load_kos
LAN_IFACE=br-lan1
LAN_IPADDR="192.168.10.1"
tc qdisc del dev $LAN_IFACE root 2> /dev/null
tc qdisc add dev $LAN_IFACE root handle 1: htb r2q 60 default 10 2> /dev/null
tc class add dev $LAN_IFACE parent 1: classid 1:1 htb rate ${1}kbit burst 15k quantum 1500 2>/dev/null
tc qdisc add dev $LAN_IFACE parent 1:1 handle 1: sfq perturb 10 2>/dev/null
tc filter add dev $LAN_IFACE parent 1: protocol ip prio 1 u32 match ip dst 192.168.10.0/24 flowid 1:1 2>/dev/null
