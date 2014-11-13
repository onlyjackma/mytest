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
tc class add dev $LAN_IFACE parent 1: classid 1:1 htb rate 10000kbit burst 15k quantum 1500 2>/dev/null
for i in `seq 150 254`
do
		tc class add dev $LAN_IFACE parent 1:1 classid 1:${i} htb rate 500kbit ceil 1000kbit burst 10k quantum 1500 prio 1 2>/dev/null
		tc qdisc add dev $LAN_IFACE parent 1:${i} handle ${i}: sfq perturb 10 2>/dev/null
		#tc filter add dev $LAN_IFACE parent 1: protocol ip prio 1 u32 match ip src $LAN_IPADDR flowid 1:10 2>/dev/null
		tc filter add dev $LAN_IFACE parent 1: protocol ip prio 1 u32 match ip dst 192.168.10.$i flowid 1:${i} 2>/dev/null
done
