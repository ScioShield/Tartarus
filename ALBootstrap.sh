#!/usr/bin/env bash
# This will only work on Centos 7 (it has not been tested on other distros)
echo "192.168.56.10 atomicfirefly-elastic" >> /etc/hosts
# unpack the agent
tar -xf /vagrant/apps/elastic-agent-8.8.0-linux-x86_64.tar.gz -C /opt/

# Check if Kibana is reachable 
kcheck=$(curl -L --silent --output /dev/null --cacert /vagrant/certs/ca.crt -XGET 'https://atomicfirefly-elastic:5601' --write-out %{http_code})
until [ $kcheck -eq 200 ]
do
  echo "Checking if Kibana is reachable, retrying..."
  sleep 5
done
echo "Kibana is reachable"

# Install the agent
sudo /opt/elastic-agent-8.8.0-linux-x86_64/elastic-agent install -f \
  --url=https://atomicfirefly-elastic:8220 \
  --enrollment-token=$(cat /vagrant/tokens/LAEtoken.txt) \
  --certificate-authorities=/vagrant/certs/ca.crt