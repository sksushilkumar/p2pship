#! /bin/sh

hip=
hip_nat=
while [ ! -z "$1" ]; do
    if [ "$1" = "h" ]; then
	hip=1
	if [ ! -z "$2" ]; then
	    hip_nat=$2
	    shift
	fi
    fi
    shift
done

while [ 1 ]; do
    if [ ! -z "$hip" ]; then
	echo "starting HIP"
        sudo hipd -k &
	sleep 1
    fi
    if [ ! -z "$hip_nat" ]; then
	echo "setting nat.."
	exit 0
	sudo hipconf nat $1
	sudo hipconf add server rvs 193.167.187.134 3600
    fi
    ./p2pship -R
    if [ ! -z "$hip" ]; then
	echo "killing HIP"
        sudo kill -9 `pidof hipd`
	sleep 1
    fi
done