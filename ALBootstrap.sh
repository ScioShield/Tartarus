#!/usr/bin/env bash
# This will only work on Centos 7 (it has not been tested on other distros)

# Var declarations
export VER=$(grep -oE "^VER=(.*)" /vagrant/vars | cut -d "=" -f2)
export IP_ADDR=$(grep -oE "^IP_ADDR=(.*)" /vagrant/vars | cut -d "=" -f2)
export DNS=$(grep -oE "^DNS=(.*)" /vagrant/vars | cut -d "=" -f2)
export ES_PORT=$(grep -oE "^ES_PORT=(.*)" /vagrant/vars | cut -d "=" -f2)
export F_PORT=$(grep -oE "^F_PORT=(.*)" /vagrant/vars | cut -d "=" -f2)

echo "${IP_ADDR} ${DNS}" >> /etc/hosts
# unpack the agent
tar -xf /vagrant/apps/elastic-agent-${VER}-linux-x86_64.tar.gz -C /opt/

# Check if Kibana is reachable 
attempt=0
kcheck=$(curl -L --silent --output /dev/null --cacert /vagrant/certs/root_ca.crt -XGET "https://${DNS}:${ES_PORT}" --write-out %{http_code})
until [ $kcheck -eq 401 ]
do
  attempt=$((attempt+1))
  if [ $attempt -ge 5 ]; then
    echo "Device can't reach Kibana on port 9200 after 5 attempts. Exiting..."
    exit 1
  fi
  echo "Checking if Kibana is reachable, retrying..."
  sleep 5
done
echo "Elasticsearch is reachable"

# Install the agent
sudo /opt/elastic-agent-${VER}-linux-x86_64/elastic-agent install -f \
  --url=https://${DNS}:${F_PORT} \
  --enrollment-token=$(cat /vagrant/tokens/LAEtoken.txt) \
  --certificate-authorities=/vagrant/certs/bundle.crt

# Download the audit.rules file
sudo curl  --silent --output /etc/audit/rules.d/audit.rules https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules
sudo chmod 0640 /etc/audit/rules.d/audit.rules

echo "Please restart the system to apply the audit rules."
