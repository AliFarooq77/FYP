#!/bin/bash

set -euo pipefail

ESP32_SUFFIXES=(222) #Tell every host on local network, that these IPs belong to me
SPOOFED_LIST="/tmp/spoofed_targets.txt"
SCAN_RETRIES=5
INTERFACE=$(ip route | awk '/default/ {print $5; exit}')
ARPSPOOF_PIDS=() # Store background PIDs
IDS_SCRIPT="realtime_IDS_multiclass.py"
ACTIVE_HOSTS="/tmp/active_hosts.txt"
MY_IP=$(hostname -I | awk '{print $1}')
NET_OCTET=$(echo "$MY_IP" | cut -d "." -f1-3)
TERMINAL_PID=""

author(){
	# Define colors
	BOLD='\033[1m'
	CYAN='\033[0;36m'
	YELLOW='\033[1;33m'
	GREEN='\033[0;32m'
	NC='\033[0m' # No Color

	# Print script info with fixed label coloring
	echo -e "${CYAN}${BOLD}===============================================${NC}"
	echo -e "${CYAN}${BOLD} Script Name :${NC} ${YELLOW}Ghost Route${NC}"
	echo -e "${CYAN}${BOLD} Description :${NC} ${YELLOW}Spoofs the ARP of devices on local network${NC}"
	echo -e "${CYAN}${BOLD} Author      :${NC} ${GREEN}Muhammad Ali Farooq${NC}"
	echo -e "${CYAN}${BOLD} Version     :${NC} ${GREEN}1.0${NC}"
	echo -e "${CYAN}${BOLD}===============================================${NC}"
}

check_dependencies(){
	echo "[+] Checking dependencies"
	for cmd in arpspoof iptables python3; do
		command -v "$cmd" >/dev/null 2>&1 || {
			echo "Error: Required command '$cmd' not found." >&2
			exit
		}
	done
	echo -e "[+] Okay\n"
}

python3_dependencies(){
	echo "[+] Changing directory to where $IDS_SCRIPT is, to install python3 dependencies in virtual environment"
	set +e
	IDS_DIRECTORY=$(find / -type f -name $IDS_SCRIPT 2> /dev/null | head -n1 | sed 's/\/[^/]*$//')
	set -e
	if [[ -z "$IDS_DIRECTORY" ]]; then
		echo "Error: $IDS_SCRIPT not found" >&2
		return 1
	fi

	cd $IDS_DIRECTORY

	if [ ! -d "myenv" ]; then
		echo -e "[+] Creating venv and installing dependencies\n"
		if python3 -m venv myenv; then
			:
		else
			echo -e "Error occurred while executing python3 -m venv myenv\n"
			rm -rf myenv 2>/dev/null
			return 1
		fi
		./myenv/bin/python -m pip install joblib
		./myenv/bin/python -m pip install scapy
		./myenv/bin/python -m pip install numpy
		./myenv/bin/python -m pip install pandas
		./myenv/bin/python -m pip install scikit-learn
	else
		echo -e "[+] myenv already exists\n"
	fi
}

cleanup(){
	echo "SCRIPT INTERRUPTED! EXIT CODE: $? ... Cleaning up..."
	rm -f "$SPOOFED_LIST" #"$ACTIVE_HOSTS"
	for pid in "${ARPSPOOF_PIDS[@]}"; do
		kill "$pid" 2>/dev/null || true
	done

	# Kill terminal if it's still running
	if [[ -n "$TERMINAL_PID" ]]; then
		kill "$TERMINAL_PID" 2> /dev/null || true
	fi

	exit
}

trap cleanup INT TERM 

disable_firewalld(){
	echo "[+] Disabling firewalld"
	if sudo systemctl stop firewalld 2> /dev/null; then
		echo -e "[+] Okay\n"
	else
		echo -e "firewalld is not installed or an error has occurred\n" >&2
	fi
}

allow_forwarding(){
	echo "[+] Appending 1 in ip_forward file"

	if echo "1" | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null; then
		echo -e "[+] Okay\n"
	else
		echo -e "Error occured while editing ip_forward file\n" >&2
	fi

	echo "[+] Adding forwarding rule in iptables"
	if sudo iptables -I FORWARD -j ACCEPT; then
		echo -e "[+] Okay\n"
	else
		echo -e "Error occurred while adding forwarding rule\n" >&2
	fi
}

active_hosts(){

	>> $ACTIVE_HOSTS
	echo "[+] Scanning for active hosts on the local network"
	for host in {1..254}; do
		ping -c1 ${NET_OCTET}.${host} | grep "64 bytes" | cut -d " " -f4 | tr -d ":" >> $ACTIVE_HOSTS &
	done
	echo -e "[+] Done scanning\n"
}

remove_duplicate(){

	echo -e "[+] Removing duplicate host entries"
	sort "$ACTIVE_HOSTS" | uniq > "$ACTIVE_HOSTS.tmp" && mv "$ACTIVE_HOSTS.tmp" "$ACTIVE_HOSTS"

	HOSTS_COUNT=$(wc -l $ACTIVE_HOSTS | awk '{print $1}')
	echo -e "[+] Number of active hosts are: $HOSTS_COUNT\n"
}

launch_ids(){
	#echo "Running find command"
	set +e
	IDS_PATH=$(find / -type f -name $IDS_SCRIPT 2> /dev/null | head -n1)
	set -e
	#echo "Find command finished"
	if [[ -n "$IDS_PATH" && -f "$IDS_PATH" ]]; then
		echo "[+] Launching IDS"
		
		if command -v gnome-terminal > /dev/null 2>&1; then
			gnome-terminal -- bash -c "sudo ./myenv/bin/python3 "$IDS_PATH"; exec bash" &
		elif command -v qterminal > /dev/null 2>&1; then
			qterminal -e bash -c "sudo ./myenv/bin/python3 "$IDS_PATH"; exec bash" &
		elif command -v konsole > /dev/null 2>&1; then
			konsole -e bash -c "sudo ./myenv/bin/python3 "$IDS_PATH"; exec bash" &
		elif command -v xterm > /dev/null 2>&1; then
			xterm -e bash -c "sudo ./myenv/bin/python3 "$IDS_PATH"; exec bash" &
		else
			echo "No suitable terminal found" >&2
			return 1
		fi
		TERMINAL_PID=$!
	else
		echo "IDS script "$IDS_SCRIPT" not found in /"
		return 1
	fi
}

#get_netaddr(){
#	ip a | awk '$0 ~ /scope global/ {
#		split($2, a, "/");
#		ip = a[1];
#		cidr = a[2];
#		split(ip, o, ".");
#		o[4] = 0;
#		print o[1]"."o[2]"."o[3]"."o[4]"/"cidr;
#		exit;
#	}'
#}

spoof_targets(){
	> "$SPOOFED_LIST"

	ESP32_IPS=()
	#NETADDR=$(get_netaddr)

	echo "[+] Spoofing the devices on local network"

	for suffix in "${ESP32_SUFFIXES[@]}"; do
		ESP32_IPS+=("${NET_OCTET}.${suffix}")
	done

	for i in $(seq 1 $SCAN_RETRIES); do

		TARGETS=$(cat $ACTIVE_HOSTS)
		
		for ESP32 in "${ESP32_IPS[@]}"; do
			for target in $TARGETS; do
				[[ "$target" == "$ESP32" || "$target" == "$MY_IP" ]] && continue
				
				SPOOF_PAIR="${target}|${ESP32}"
				if grep -q "$SPOOF_PAIR" "$SPOOFED_LIST"; then
					echo "Skipping $target- already spoofed"
					continue
				fi

				sudo arpspoof -i $INTERFACE -t "$target" "$ESP32" &
				ARPSPOOF_PIDS+=($!)
				echo "$SPOOF_PAIR" >> "$SPOOFED_LIST"
			done
			echo "Ready to spoof local network with another ESP32 IP"
		done
		sleep 1
	done
}

main(){
	author
	check_dependencies
	python3_dependencies
	disable_firewalld
	allow_forwarding
	launch_ids
	for i in {1..10}; do
		active_hosts
		sleep 1
	done
	remove_duplicate
	spoof_targets

 	echo -e "SPOOFED!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
	wait
}

main
