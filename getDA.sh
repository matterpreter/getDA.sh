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
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No color

# Enable autopwn if provided the option is specified
AUTOPWN=""
if [[ $1 = "--autopwn" ]]; then
  AUTOPWN="true"
else
  AUTOPWN="false"
  echo "try again"
fi

# Check if required tools exist. Only supporting tools in /opt but this is easy
# to change
if [[ ! -d "/opt/Responder/" ]]; then
  echo "[-] Couldn't find Responder. Installing now..."
  git clone https://github.com/lgandx/Responder.git /opt/Responder
  # Need to install Responder as well
fi
if ! python_loc="$(type -p python)"; then
  echo "[-] Couldn't find Python. Installing now..."
  apt -y install python
fi
if [[ ! -d "/opt/impacket/" ]]; then
  echo "[-] Couldn't find Impacket. Installing now..."
  git clone https://github.com/CoreSecurity/impacket.git /opt/impacket
  cd /opt/impacket && python setup.py install && cd -
fi
if ! cme_loc="$(type -p cme)"; then
  echo "[-] CME isn't installed. Installing now..."
  git clone https://github.com/byt3bl33d3r/CrackMapExec.git /opt/CrackMapExec
  cd  /opt/CrackMapExec && python setup.py install && cd -
fi
if [[ ! -d "/opt/SIET/" ]]; then
  echo "[-] Couldn't find SIET. Installing now..."
  git clone https://github.com/Sab0tag3d/SIET.git /opt/SIET
fi
if ! rpcclient_loc="$(type -p rpcclient)"; then # Don't know where this would be the case, but who knows
  echo "[-] Couldn't find rpcclient. Installing now..."
  apt -y install rpcclient
fi
if ! nmap_loc="$(type -p nmap)"; then
  echo "[-] Couldn't find nmap. Installing now..."
  apt -y install nmap
fi
if ! masscan_loc="$(type -p masscan)"; then
  echo "[-] Couldn't find masscan. Installing now..."
  apt -y install masscan
fi


echo -e "${BLUE}------------------------------------------------${NC}"
echo -e "${BLUE}-------------------${YELLOW}EZ mode DA${BLUE}-------------------${NC}"
echo -e "${BLUE}--------------------${YELLOW}v0.3beta${BLUE}--------------------${NC}"
if [[ $AUTOPWN = 'true' ]]; then
  echo -e "${BLUE}---------------${YELLOW}Autopwn: ${RED}ACTIVATED${BLUE}---------------${NC}"
fi
echo -e "${BLUE}------------------------------------------------${NC}"
echo "Currently supported vectors to check:"
echo "1) SMB Relay"
echo "2) Kerberoast"
echo "3) MS17-010 (EternalBlue)"
echo "4) Null Session Enumeration"
echo "5) Cisco Smart Install"
echo "0) All of the above"

read -p "Option: " OPTION

case "$OPTION" in
  1)  echo "[+] Checking if a SMB relay attack is viable"
      echo "Before we get started, enter file containing your targets (/root/targets.txt)" #*** Need to fix this so that it doesn't run if the option isn't valid
      read -p "Targets file: " TARGETSFILE
      smbRelay $TARGETSFILE
      ;;
  2)  echo "[+] Getting ready to kerberoast"
      kerberoast
      ;;
  3)  echo "[+] Checking for MS17-010"
      echo "Before we get started, enter file containing your targets (/root/targets.txt)" #*** Need to fix this so that it doesn't run if the option isn't valid
      read -p "Targets file: " TARGETSFILE
      ms17-010 $TARGETSFILE
      ;;
  4)  echo "[+] Attempting to get usernames via null sessions"
      nullSessionEnum
      ;;
  5)  echo "[+] Checking for hosts with Cisco Smart Install enabled"
      echo "Before we get started, enter file containing your targets (/root/targets.txt)" #*** Need to fix this so that it doesn't run if the option isn't valid
      read -p "Targets file: " TARGETSFILE
      smartInstall $TARGETSFILE
      ;;
  0)  echo "[+] Running all checks."
      echo "Before we get started, enter file containing your targets (/root/targets.txt)" #*** Need to fix this so that it doesn't run if the option isn't valid
      read -p "Targets file: " TARGETSFILE
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
      ;;
  *) echo "That is not a valid option. Try again.";;
esac
