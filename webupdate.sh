#!/bin/sh
get_update(){
	local e3g_ip='130.255.1.100'
	local old_ver_ID=12
	local new_ver_ID
	local dev_sn=sb941
	local e3g_name='admin'
	local e3g_passwd='admin'
	
	echo wget -q -O /tmp/vrest 'http://'$e3g_ip'/e3g/bussinessmanage/upgrade/version.do?sn='$dev_sn'&versionId='$old_ver_ID
	wget -q -O /tmp/vrest 'http://'$e3g_ip'/e3g/bussinessmanage/upgrade/version.do?sn='$dev_sn'&versionId='$old_ver_ID
	rest=`cat /tmp/vrest`
	nver=`echo $rest | awk -F ',' '{ if(NF==2){print $2}}' 2>/dev/null`
	echo $nver
	[ -n "$nver" ] && {
		new_ver_ID=`echo $nver | awk -F ':' '{print $2}'`
	}||{
		return
	}
	echo $new_ver_ID
	echo "wget -q -O /tmp/webupdate.zip  'http://'$e3g_ip'/e3g/bussinessmanage/upgrade/download.do?sn='$dev_sn'&username='$e3g_name'&password='$e3g_passwd'&versionId='$new_ver_ID"
	[ -n "$new_ver_ID" ] && wget -q -O /tmp/webupdate.zip  'http://'$e3g_ip'/e3g/bussinessmanage/upgrade/download.do?sn='$dev_sn'&username='$e3g_name'&password='$e3g_passwd'&versionId='$new_ver_ID
	if [ $? == "0" ];then
		wget -q 'http://'$e3g_ip'/e3g/bussinessmanage/upgrade/downloadResult.do?sn='$dev_sn'&errorNo=0'
	else
		wget -q 'http://'$e3g_ip'/e3g/bussinessmanage/upgrade/downloadResult.do?sn='$dev_sn'&errorNo=1'
	fi
	
	[ -e /tmp/webupdate.zip ] && {
		#rm -rf /mnt/native/www
		#tar -xzf /tmp/webupdate.zip -C /mnt/native/
		cd /tmp
		unzip webupdate.zip
		if [ $? == "0" ];then
			wget -q 'http://'$e3g_ip'/e3g/bussinessmanage/upgrade/downloadResult.do?sn='$dev_sn'&errorNo=0'
		else
			wget -q 'http://'$e3g_ip'/e3g/bussinessmanage/upgrade/downloadResult.do?sn='$dev_sn'&errorNo=2'
		fi
		sh /tmp/update.sh
		if [ $? == "0" ];then
			wget -q 'http://'$e3g_ip'/e3g/bussinessmanage/upgrade/downloadResult.do?sn='$dev_sn'&errorNo=0'
		#	uci set wbuconf.webupdate.currentid=$new_ver_ID
		#	uci commit wbuconf
		else
			wget -q 'http://'$e3g_ip'/e3g/bussinessmanage/upgrade/downloadResult.do?sn='$dev_sn'&errorNo=2'
		fi
	}
}
#while :
#do
	#local interval=`uci get -P /var/state wbuconf.webupdate.interval 2>/dev/null`
	#interval=${interval:-60}
	get_update
#	sleep 60
#done
