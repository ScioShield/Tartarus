#!/usr/bin/env bash
# This will only work on Rocky Linux (it has not been tested on other distros!)

export VER=$(grep -oE "^VER=(.*)" /vagrant/vars | cut -d "=" -f2)
export IP_ADDR=$(grep -oE "^IP_ADDR=(.*)" /vagrant/vars | cut -d "=" -f2)
export K_PORT=$(grep -oE "^K_PORT=(.*)" /vagrant/vars | cut -d "=" -f2)
export K_PORT_EXT=$(grep -oE "^K_PORT_EXT=(.*)" /vagrant/vars | cut -d "=" -f2)
export ES_PORT=$(grep -oE "^ES_PORT=(.*)" /vagrant/vars | cut -d "=" -f2)
export F_PORT=$(grep -oE "^F_PORT=(.*)" /vagrant/vars | cut -d "=" -f2)
export DNS=$(grep -oE "^DNS=(.*)" /vagrant/vars | cut -d "=" -f2)

E_PASS=$(sudo grep "generated password for the elastic" /root/ESUpass.txt | awk '{print $11}')

echo "Go to https://$DNS:$K_PORT_EXT once you have updated your DNS settings in your hosts, hosts file!"
echo "It must be https://$DNS:$K_PORT_EXT and must point to 127.0.0.1 due to a reverse proxy being used"
echo "Just going to the IP address won't work!"
echo "Username: elastic"
echo "Password: $(echo $E_PASS)"
echo "SAVE THE PASSWORD!!!"
echo "If you didn't save this password you can reset the Elastic user password with this command"
echo "on the elastic guest:"
echo "sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic"
echo "The CA cert is in certs/"
echo "You can add the CA to your host device trust store"
echo "On Linux you can use the command:"
echo "sudo cp ./certs/root_ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates"
echo "On Windows you can use the command:"
echo "certutil -addstore -f Root ./certs/root_ca.crt"
echo "And also add it to your browser trust store!"
echo "Tokens are saved in tokens/"