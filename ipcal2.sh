#!/bin/sh
ipcalc(){
	echo $1,$2 |awk 'BEGIN{FS=",";ip_max=256}
         {
         split($1,ips,".");split($2,ipe,".");
         for(i=ips[4]+ips[3]*ip_max+ips[2]*ip_max^2+ips[1]*ip_max^3;
             i<=ipe[4]+ipe[3]*ip_max+ipe[2]*ip_max^2+ipe[1]*ip_max^3;
             i++){
                  print int(i/ip_max^3)"."\
                        int(i%ip_max^3/ip_max^2)"."\
                        int(i%ip_max^3%ip_max^2/ip_max)"."\
                        i%ip_max^3%ip_max^2%ip_max":"i
                 }
          }'
}

for ip in `ipcalc "10.10.10.2" "10.10.10.6"`
do
	
	ip1=`echo $ip | awk -F":" '{print $1}'`
	num=`echo $ip | awk -F":" '{print $2}'`
	echo ip=$ip1 num=$num
done
