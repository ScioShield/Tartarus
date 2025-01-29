#!/usr/bin/env bash
# This will only work on Rocky Linux (it has not been tested on other distros!)

# Cleanup
for file in "/vagrant/keys/ESapikey.txt" "/root/ESapikey.txt" "/root/ESUpass.txt" "/root/Kibpass.txt" "/root/Ftoken.txt" "/root/FPid.txt" "/root/FIid.txt" "/root/WPid.txt" "/root/LPid.txt" "/root/WIid.txt" "/root/CWIid.txt" "/root/WEDI.txt" "/root/WEDI_out.txt" "/root/WEDI_in.txt" "/root/LIid.txt" "/root/LEDI.txt" "/root/LEDI_out.txt" "/root/LEDI_in.txt"
do
    sudo rm -f "$file"
done
