#!/usr/bin/env bash
# This will only work on Rocky Linux (it has not been tested on other distros!)

# Test if the VM can reach the internet to download packages
until ping -c 1 google.com | grep -q "bytes from"
do
    echo "offline, still waiting..."
    sleep 5
done
echo "online"

# Install Elasticsearch, Kibana, Unzip, wget and jq
yum install -y unzip wget jq

# Get the GPG key temp work around is to reenable SHA1 support for GPG keys, will update when Elastic move to 256/512
# Run this when done
# update-crypto-policies --set DEFAULT
update-crypto-policies --set DEFAULT:SHA1
rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch

# Add Elastic and Kibana and the Elastic Agents
# Download and install Ealsticsearch and Kibana change ver to whatever you want
# For me 8.8.0 is the latest we put it in /vagrant/apps to not download it again
# The -q flag is need to not spam stdout on the host machine
# We also pull the SHA512 hashes for you to check

# var settings
export VER=8.8.0
export IP_ADDR=192.168.56.10
export K_PORT=5601
export ES_PORT=9200
export F_PORT=8220
export DNS=atomicfirefly-elastic

echo "$IP_ADDR $DNS" >> /etc/hosts

wget -nc -q https://download.sysinternals.com/files/Sysmon.zip -P /vagrant/apps
wget -nc -q https://github.com/git-for-windows/git/releases/download/v2.39.2.windows.1/Git-2.39.2-64-bit.exe -P /vagrant/apps

download_and_verify() {
  local url="$1"
  local dest_dir="$2"
  local file_name
  file_name=$(basename "$url")

  wget -nc -q "$url" -P "$dest_dir"
  wget -nc -q "${url}.sha512" -P "$dest_dir"

  pushd "$dest_dir" > /dev/null
  sha512sum -c "${file_name}.sha512" 2> /dev/null
  if [ $? -ne 0 ]; then
    echo "Checksum verification failed for ${file_name}"
    return 1
  else
    echo "Checksum verified for ${file_name}"
  fi
  popd > /dev/null
}

download_and_verify "https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-$VER-x86_64.rpm" "/vagrant/apps"
download_and_verify "https://artifacts.elastic.co/downloads/kibana/kibana-$VER-x86_64.rpm" "/vagrant/apps"
download_and_verify "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-$VER-linux-x86_64.tar.gz" "/vagrant/apps"
download_and_verify "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-$VER-windows-x86_64.zip" "/vagrant/apps"


# We output to a temp password file allowing auto config later on
tar -xf /vagrant/apps/elastic-agent-$VER-linux-x86_64.tar.gz -C /opt/
rpm --install /vagrant/apps/elasticsearch-$VER-x86_64.rpm 2>&1 | tee /root/ESUpass.txt
rpm --install /vagrant/apps/kibana-$VER-x86_64.rpm

# Make the cert dir to prevent pop-up later
mkdir /tmp/certs/

# Config the instances file for cert gen the ip is $IP_ADDR
cat > /tmp/certs/instance.yml << EOF
instances:
  - name: 'elasticsearch'
    dns: ['$DNS']
    ip: ['$IP_ADDR']
  - name: 'kibana'
    dns: ['$DNS']
    ip: ['$IP_ADDR']
  - name: 'fleet'
    dns: ['$DNS']
    ip: ['$IP_ADDR']
EOF

# Make the certs and move them where they are needed
/usr/share/elasticsearch/bin/elasticsearch-certutil ca --pem --pass secret --out /tmp/certs/elastic-stack-ca.zip
unzip -q /tmp/certs/elastic-stack-ca.zip -d /tmp/certs/
/usr/share/elasticsearch/bin/elasticsearch-certutil cert --ca-cert /tmp/certs/ca/ca.crt -ca-key /tmp/certs/ca/ca.key --ca-pass secret --pem --in /tmp/certs/instance.yml --out /tmp/certs/certs.zip
unzip -q /tmp/certs/certs.zip -d /tmp/certs/

mkdir /etc/kibana/certs
mkdir /etc/pki/fleet

cp /tmp/certs/ca/ca.crt /tmp/certs/elasticsearch/* /etc/elasticsearch/certs
cp /tmp/certs/ca/ca.crt /tmp/certs/kibana/* /etc/kibana/certs
cp /tmp/certs/ca/ca.crt /tmp/certs/fleet/* /etc/pki/fleet
cp -r /tmp/certs/* /root/

# This cp should be an unaliased cp to replace the ca.crt if it exists in the shared /vagrant/certs dir
cp -u /tmp/certs/ca/ca.crt /vagrant/certs

# Config and start Elasticsearch (we are also increasing the timeout for systemd to 500)
mv /etc/elasticsearch/elasticsearch.yml /etc/elasticsearch/elasticsearch.yml.bak

cat > /etc/elasticsearch/elasticsearch.yml << EOF
# ======================== Elasticsearch Configuration =========================
#
# ----------------------------------- Paths ------------------------------------
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
# ---------------------------------- Network -----------------------------------
network.host: $IP_ADDR
http.port: $ES_PORT
# --------------------------------- Discovery ----------------------------------
discovery.type: single-node
# ----------------------------------- X-Pack -----------------------------------
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.key: /etc/elasticsearch/certs/elasticsearch.key
xpack.security.transport.ssl.certificate: /etc/elasticsearch/certs/elasticsearch.crt
xpack.security.transport.ssl.certificate_authorities: [ "/etc/elasticsearch/certs/ca.crt" ]
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.key: /etc/elasticsearch/certs/elasticsearch.key
xpack.security.http.ssl.certificate: /etc/elasticsearch/certs/elasticsearch.crt
xpack.security.http.ssl.certificate_authorities: [ "/etc/elasticsearch/certs/ca.crt" ]
xpack.security.authc.api_key.enabled: true
EOF

sed -i 's/TimeoutStartSec=75/TimeoutStartSec=500/g' /lib/systemd/system/elasticsearch.service
systemctl daemon-reload
systemctl start elasticsearch
systemctl enable elasticsearch

# Gen the users and paste the output for later use
/usr/share/elasticsearch/bin/elasticsearch-reset-password -b -u kibana_system -a > /root/Kibpass.txt

# Add the Kibana password to the keystore
grep "New value:" /root/Kibpass.txt | awk '{print $3}' | sudo /usr/share/kibana/bin/kibana-keystore add --stdin elasticsearch.password

# Configure and start Kibana adding in the unique kibana_system keystore pass and generating the sec keys
cat > /etc/kibana/kibana.yml << EOF
# =========================== Kibana Configuration ============================
# -------------------------------- Network ------------------------------------
server.host: 0.0.0.0
server.port: $K_PORT
server.publicBaseUrl: "https://$DNS:$K_PORT"
# ------------------------------ Elasticsearch --------------------------------
elasticsearch.hosts: ["https://$IP_ADDR:$ES_PORT"]
elasticsearch.username: "kibana_system"
elasticsearch.password: "\${elasticsearch.password}"
# ---------------------------------- Various -----------------------------------
telemetry.enabled: false
server.ssl.enabled: true
server.ssl.certificate: "/etc/kibana/certs/kibana.crt"
server.ssl.key: "/etc/kibana/certs/kibana.key"
elasticsearch.ssl.certificateAuthorities: [ "/etc/kibana/certs/ca.crt" ]
elasticsearch.ssl.verificationMode: "none"
# ---------------------------------- X-Pack ------------------------------------
xpack.security.encryptionKey: "$(tr -dc A-Za-z0-9 </dev/urandom | head -c 32 ; echo '')"
xpack.encryptedSavedObjects.encryptionKey: "$(tr -dc A-Za-z0-9 </dev/urandom | head -c 32 ; echo '')"
xpack.reporting.encryptionKey: "$(tr -dc A-Za-z0-9 </dev/urandom | head -c 32 ; echo '')"
EOF

systemctl start kibana
systemctl enable kibana

# Var settings (has to happen after Elastic is installed)
E_PASS=$(sudo grep "generated password for the elastic" /root/ESUpass.txt | awk '{print $11}')
grep "generated password for the elastic" /root/ESUpass.txt | awk '{print $11}' > /vagrant/Password.txt

# Test if Kibana is running
echo "Testing if Kibana is online, could take some time, no more than 5 mins"
until curl --silent --cacert /tmp/certs/ca/ca.crt -XGET "https://$DNS:$K_PORT/api/fleet/agent_policies" -H 'accept: application/json' -u elastic:$E_PASS | grep -q '"items":\[\]'
do
    echo "Kibana starting, still waiting..."
    sleep 5
done
echo "Kibana online"

# Make the Fleet token
curl --silent -XPUT --url "https://$IP_ADDR:$ES_PORT/_security/service/elastic/fleet-server/credential/token/fleet-token-1" \
 --user elastic:$E_PASS \
 --output /root/Ftoken.txt \
 --cacert /tmp/certs/ca/ca.crt

jq --raw-output '.token.value' /root/Ftoken.txt > /vagrant/tokens/Ftoken.txt

# Add Fleet Policy
curl --silent -XPOST \
  --user  elastic:$E_PASS \
  --output /root/FPid.txt \
  --cacert /tmp/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/agent_policies?sys_monitoring=true" \
  --header @/vagrant/config/headers.txt \
  --data @/vagrant/config/fleet_policy_add.json

jq --raw-output '.item.id' /root/FPid.txt > /vagrant/keys/FPid.txt

export FLEET_POLICY_ID=$(cat /vagrant/keys/FPid.txt)

# Add Fleet Integration
curl --silent -XPOST \
  --user elastic:$E_PASS \
  --output /root/FIid.txt \
  --cacert /tmp/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/package_policies" \
  --header @/vagrant/config/headers.txt \
  --data @<(envsubst < /vagrant/config/fleet_integration_add.json)

jq --raw-output '.item.id' /root/FIid.txt > /vagrant/keys/FIid.txt

# Add host IP and yaml settings to Fleet API
curl --silent -XPUT \
 --user elastic:$E_PASS \
 --cacert /tmp/certs/ca/ca.crt \
 --url "https://$DNS:$K_PORT/api/fleet/package_policies/$(cat /vagrant/keys/FIid.txt)" \
 --header @/vagrant/config/headers.txt \
 --data @<(envsubst < /vagrant/config/fleet_integration_update_ip.json)

# Add host IP and yaml settings to Fleet API
 curl --silent -XPUT \
 --user elastic:$E_PASS \
 --cacert /tmp/certs/ca/ca.crt \
 --url "https://$DNS:$K_PORT/api/fleet/outputs/fleet-default-output" \
 --header @/vagrant/config/headers.txt \
 --data @<(envsubst < /vagrant/config/fleet_integration_update_es_ip.json)


# Create the Windows Policy
curl --silent -XPOST \
  --user elastic:$E_PASS \
  --output /root/WPid.txt \
  --cacert /tmp/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/agent_policies?sys_monitoring=true" \
  --header @/vagrant/config/headers.txt \
  --data @/vagrant/config/windows_policy_add.json

jq --raw-output '.item.id' /root/WPid.txt > /vagrant/keys/WPid.txt

export WINDOWS_POLICY_ID=$(cat /vagrant/keys/WPid.txt)

# Create the Linux Policy
curl --silent -XPOST \
  --user elastic:$E_PASS \
  --output /root/LPid.txt \
  --cacert /tmp/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/agent_policies?sys_monitoring=true" \
  --header @/vagrant/config/headers.txt \
  --data @/vagrant/config/linux_policy_add.json

jq --raw-output '.item.id' /root/LPid.txt > /vagrant/keys/LPid.txt

export LINUX_POLICY_ID=$(cat /vagrant/keys/LPid.txt)

# Add Windows Integration
curl --silent -XPOST \
  --user elastic:$E_PASS \
  --output /root/WIid.txt \
  --cacert /tmp/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/package_policies" \
  --header @/vagrant/config/headers.txt \
  --data @<(envsubst < /vagrant/config/windows_integration_add.json)

jq --raw-output '.item.id' /root/WIid.txt > /vagrant/keys/WIid.txt

# Add Custom Windows Event Logs - Windows Defender Logs
curl --silent -XPOST \
  --user elastic:$E_PASS \
  --output /root/CWIid.txt \
  --cacert /tmp/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/package_policies" \
  --header @/vagrant/config/headers.txt \
  --data @<(envsubst < /vagrant/config/windows_integration_update_defender_logs.json)

# Create the Windows Elastic Defender Intigration 
curl --silent -XPOST \
  --user elastic:$E_PASS \
  --output /root/WEDI.txt \
  --cacert /tmp/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/package_policies" \
  --header @<(envsubst < /vagrant/config/sec_headers.txt) \
  --data @<(envsubst < /vagrant/config/windows_integration_defender_add.json)

jq --raw-output '.item.id' /root/WEDI.txt > /vagrant/keys/WEDIid.txt

jq 'del(.item.id, .item.revision, .item.created_at, .item.created_by, .item.updated_at, .item.updated_by) | .item' /root/WEDI.txt > /root/WEDI_out.txt

jq '.inputs[0].config.policy.value.windows.malware.mode = "detect" |
.inputs[0].config.policy.value.mac.malware.mode = "detect" |
.inputs[0].config.policy.value.linux.malware.mode = "detect" |
.inputs[0].config.policy.value.windows.antivirus_registration.enabled = "true"' /root/WEDI_out.txt > /root/WEDI_in.txt

# Update the Windows Elastic Defender Intigration to detect mode
curl --silent -XPUT \
  --user elastic:$E_PASS \
  --cacert /tmp/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/package_policies/$(cat /vagrant/keys/WEDIid.txt)" \
  --header @<(envsubst < /vagrant/config/sec_headers.txt) \
  --data @/root/WEDI_in.txt

# Add Linux Auditd Integration
curl --silent -XPOST \
  --user elastic:$E_PASS \
  --output /root/LIid.txt \
  --cacert /tmp/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/package_policies" \
  --header @/vagrant/config/headers.txt \
  --data @<(envsubst < /vagrant/config/linux_integration_auditd_add.json)

jq --raw-output '.item.id' /root/LIid.txt > /vagrant/keys/LIid.txt

# Create the Linux Elastic Defender Intigration 
curl --silent -XPOST \
  --user elastic:$E_PASS \
  --output /root/LEDI.txt \
  --cacert /tmp/certs/ca/ca.crt \
  --url "https://$DNS:$K_PORT/api/fleet/package_policies" \
  --header @<(envsubst < /vagrant/config/sec_headers.txt) \
  --data @<(envsubst < /vagrant/config/linux_integration_defender_add.json)

jq --raw-output '.item.id' /root/LEDI.txt > /vagrant/keys/LEDIid.txt

jq 'del(.item.id, .item.revision, .item.created_at, .item.created_by, .item.updated_at, .item.updated_by) | .item' /root/LEDI.txt > /root/LEDI_out.txt

jq '.inputs[0].config.policy.value.windows.malware.mode = "detect" |
.inputs[0].config.policy.value.mac.malware.mode = "detect" |
.inputs[0].config.policy.value.linux.malware.mode = "detect"' /root/LEDI_out.txt > /root/LEDI_in.txt

# Update the Linux Elastic Defender Intigration to detect mode
curl --silent --user elastic:$E_PASS -XPUT "https://$DNS:$K_PORT/api/fleet/package_policies/$(cat /vagrant/keys/LEDIid.txt)" \
  --cacert /tmp/certs/ca/ca.crt \
  --header @<(envsubst < /vagrant/config/sec_headers.txt) \
  --data @/root/LEDI_in.txt

# Enable all Windows and Linux default alerts
curl --silent -XPOST \
  --user elastic:$E_PASS \
  --cacert /tmp/certs/ca/ca.crt \
  --header @/vagrant/config/headers.txt \
  --url "https://$DNS:$K_PORT/api/detection_engine/rules/_bulk_action" \
  --data '{
  "query": "alert.attributes.tags: \"Windows\" OR alert.attributes.tags: \"Linux\"",
  "action": "enable"
}'

# Install the fleet server
sudo /opt/elastic-agent-$VER-linux-x86_64/elastic-agent install -f --url=https://$DNS:$F_PORT \
 --fleet-server-es=https://$DNS:$ES_PORT \
 --fleet-server-service-token=$(cat /vagrant/tokens/Ftoken.txt) \
 --fleet-server-policy=$(cat /vagrant/keys/FPid.txt) \
 --certificate-authorities=/vagrant/certs/ca.crt \
 --fleet-server-es-ca=/etc/pki/fleet/ca.crt \
 --fleet-server-cert=/etc/pki/fleet/fleet.crt \
 --fleet-server-cert-key=/etc/pki/fleet/fleet.key

# Get the Windows policy id
curl --silent --cacert /tmp/certs/ca/ca.crt -XGET "https://$DNS:$K_PORT/api/fleet/enrollment_api_keys" -H 'accept: application/json' -u elastic:$E_PASS | sed -e "s/\},{/'\n'/g" -e "s/items/'\n'/g" | grep -E -m1 $(cat /vagrant/keys/WPid.txt) | grep -oP '[a-zA-Z0-9\=]{40,}' > /vagrant/tokens/WAEtoken.txt
# Get the Linux policy id
curl --silent --cacert /tmp/certs/ca/ca.crt -XGET "https://$DNS:$K_PORT/api/fleet/enrollment_api_keys" -H 'accept: application/json' -u elastic:$E_PASS | sed -e "s/\},{/'\n'/g" -e "s/items/'\n'/g" | grep -E -m1 $(cat /vagrant/keys/LPid.txt) | grep -oP '[a-zA-Z0-9\=]{40,}' > /vagrant/tokens/LAEtoken.txt

echo "To log into KLibana go to https://$IP_ADDR:$K_PORT"
echo "Or go to https://$DNS:$K_PORT once you have updated your DNS settings in your hosts, hosts file!"
echo "Username: elastic"
echo "Password: $(cat /vagrant/Password.txt)"
echo "Password is saved in Password.txt"
echo "Tokens are saved in tokens/"
echo "To enroll Windows agents use this token: $(cat /vagrant/tokens/WAEtoken.txt)"
echo "To enroll Linux agents use this token: $(cat /vagrant/tokens/LAEtoken.txt)"