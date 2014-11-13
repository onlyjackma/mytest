#!/bin/sh
STATUS=LOADING
signal_handle(){
if [ "$STATUS" == "LOADING" ];then
	echo "catch signal"
fi

}
while :
do
	trap "signal_handle" 1 2 9
	sleep 3
	echo "hello man"

done
