num3g=$(uci get capacity.capacity.3g 2>/dev/null)
if [ $num3g == 1 ]; then
	flag=$(uci show firewall | grep zone | grep -w umts2 | cut -d'.' -f2 2>/dev/null)
	[ -z "$flag" ] || uci del firewall.$flag
fi
numwifi=$(uci get capacity.capacity.wifi 2>/dev/null)

if [ $numwifi == 1 -o $numwifi == 0 ]; then
	flag=$(uci show firewall | grep zone | grep -w wwan1 | cut -d'.' -f2 2>/dev/null)
	[ -z "$flag" ] || uci del firewall.$flag
fi

numwan=$(uci get capacity.capacity.wan 2>/dev/null)
numwan=${numwan:-0}
if [ $numwan == 0 ];then
	flag=$(uci show firewall | grep zone | grep -w wan1 | cut -d'.' -f2 2>/dev/null)
	[ -z "$flag" ] || uci del firewall.$flag
fi

