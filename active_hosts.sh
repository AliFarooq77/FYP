#!/bin/bash

author(){
	
	BOLD='\033[1m'
	CYAN='\033[0;36m'
	YELLOW='\033[1;33m'
	GREEN='\033[0;32m'
	NC='\033[0m' # No Color

	# Print script info with fixed label coloring
	echo -e "${CYAN}${BOLD}===============================================${NC}"
	echo -e "${CYAN}${BOLD} Script Name :${NC} ${YELLOW}Network Scanner${NC}"
	echo -e "${CYAN}${BOLD} Description :${NC} ${YELLOW}Scans for the devices on local network${NC}"
	echo -e "${CYAN}${BOLD} Author 1    :${NC} ${GREEN}Muhammad Ali Farooq${NC}"
	echo -e "${CYAN}${BOLD} Version     :${NC} ${GREEN}1.0${NC}"
	echo -e "${CYAN}${BOLD}===============================================${NC}"
}

MY_IP=$(hostname -I | awk '{print $1}')
NET_OCTET=$(echo "$MY_IP" | cut -d "." -f1-3)
ACTIVE_HOSTS="/tmp/activehosts.txt"

author

>> $ACTIVE_HOSTS
echo "[+] Scanning for active hosts on the local network"

for host in {1..254}; do
	ping -c1 ${NET_OCTET}.${host} | grep "64 bytes" | cut -d " " -f4 | tr -d ":" >> $ACTIVE_HOSTS &
done

echo -e "[+] Done scanning. Listing\n"
cat $ACTIVE_HOSTS
rm $ACTIVE_HOSTS
