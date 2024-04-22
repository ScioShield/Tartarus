#!/usr/bin/env bash
# This will only work on Centos 7 (it has not been tested on other distros)
echo "192.168.56.10 atomicfirefly-elastic" >> /etc/hosts
# unpack the agent
tar -xf /vagrant/apps/elastic-agent-8.12.0-linux-x86_64.tar.gz -C /opt/

# Check if Kibana is reachable 
kcheck=$(curl -L --silent --output /dev/null --cacert /vagrant/certs/root_ca.crt -XGET 'https://atomicfirefly-elastic:5443' --write-out %{http_code})
until [ $kcheck -eq 200 ]
do
  echo "Checking if Kibana is reachable, retrying..."
  sleep 5
done
echo "Kibana is reachable"

# Install the agent
sudo /opt/elastic-agent-8.12.0-linux-x86_64/elastic-agent install -f \
  --url=https://atomicfirefly-elastic:8220 \
  --enrollment-token=$(cat /vagrant/tokens/LAEtoken.txt) \
  --certificate-authorities=/vagrant/certs/root_ca.crt

# Download the audit.rules file
sudo curl -o /etc/audit/rules.d/audit.rules https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules
sudo chmod 0640 /etc/audit/rules.d/audit.rules

echo "Please restart the system to apply the audit rules."