#!/usr/bin/env bash
# This will only work on Rocky Linux (it has not been tested on other distros!)

# Test if the we can reach the internet to download packages
attempt=0
until curl --silent --head --fail https://www.google.com | grep -q "HTTP/.* 200"
do
    attempt=$((attempt+1))
    if [ $attempt -ge 5 ]; then
        echo "Device can't reach the internet on port 443 after 5 attempts. Exiting..."
        exit 1
    fi
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
# For me 8.12.0 is the latest we put it in /vagrant/apps to not download it again
# The -q flag is need to not spam stdout on the host machine
# We also pull the SHA512 hashes for you to check

# var settings
export VER=8.12.0
export IP_ADDR=192.168.56.10
export K_PORT=5601
export K_PORT_EXT=5443
export ES_PORT=9200
export F_PORT=8220
export DNS=atomicfirefly-elastic

echo "$IP_ADDR $DNS" >> /etc/hosts
echo "$IP_ADDR ca.$DNS" >> /etc/hosts

wget -nc -q https://download.sysinternals.com/files/Sysmon.zip -P /vagrant/apps
wget -nc -q https://github.com/git-for-windows/git/releases/download/v2.39.2.windows.1/Git-2.39.2-64-bit.exe -P /vagrant/apps

# Download and verify the smallstep cert util

download_and_verify_smallstep() {
  local url="$1"
  local dest_dir="$2"
  local file_name
  file_name=$(basename "$url")

  wget -nc -q "$url" -P "$dest_dir"

  # Download the checksum file
  local checksum_url
  checksum_url=$(dirname "$url")/checksums.txt
  wget -nc -q "$checksum_url" -O "${dest_dir}/checksums-${file_name}.txt"

  pushd "$dest_dir" > /dev/null

  # Verify the checksum
  grep "${file_name}" "checksums-${file_name}.txt" | sha256sum -c -
  if [ $? -ne 0 ]; then
    echo "Checksum verification failed for ${file_name}"
    return 1
  else
    echo "Checksum verified for ${file_name}"
  fi

  popd > /dev/null
}

download_and_verify_smallstep "https://dl.smallstep.com/cli/docs-ca-install/latest/step-cli_amd64.rpm" "/vagrant/apps"
download_and_verify_smallstep "https://dl.smallstep.com/certificates/docs-ca-install/latest/step-ca_amd64.rpm" "/vagrant/apps"

# Download and verify the Elastic packages 

download_and_verify_elastic() {
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

download_and_verify_elastic "https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-$VER-x86_64.rpm" "/vagrant/apps"
download_and_verify_elastic "https://artifacts.elastic.co/downloads/kibana/kibana-$VER-x86_64.rpm" "/vagrant/apps"
download_and_verify_elastic "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-$VER-linux-x86_64.tar.gz" "/vagrant/apps"
download_and_verify_elastic "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-$VER-windows-x86_64.zip" "/vagrant/apps"


# We output to a temp password file allowing auto config later on
tar -xf /vagrant/apps/elastic-agent-$VER-linux-x86_64.tar.gz -C /opt/
rpm --install /vagrant/apps/elasticsearch-$VER-x86_64.rpm 2>&1 | tee /root/ESUpass.txt
rpm --install /vagrant/apps/kibana-$VER-x86_64.rpm

# Install the smallstep cli and ca
rpm --install /vagrant/apps/step-cli_amd64.rpm
rpm --install /vagrant/apps/step-ca_amd64.rpm

# Install Caddy
dnf -y install 'dnf-command(copr)'
dnf -y copr enable @caddy/caddy
dnf -y install caddy

# Set the password if the file doesn't exist
if [ ! -f /vagrant/ca-password.txt ]; then
  echo "$(tr -dc A-Za-z0-9 </dev/urandom | head -c 32 ; echo '')" > /vagrant/ca-password.txt
fi

# Init the CA
step ca init \
  --name "Atomic Fire Fly Elastic CA" \
  --dns "ca.${DNS}" \
  --address ":8443" \
  --provisioner "Elasticsearch" \
  --password-file "/vagrant/ca-password.txt" \
  --with-ca-url "https://ca.${DNS}" \
  --acme

# Check if the /vagrant/certs/root_ca.crt file exists
if [ -f /vagrant/certs/root_ca.crt ]; then
  # Copy /vagrant/certs/root_ca.crt to /root/.step/certs/
  cp /vagrant/certs/*.crt /root/.step/certs/ && cp /vagrant/certs/*_key /root/.step/secrets/
else
  # Copy the .step cert file to /vagrant/certs/
  cp /root/.step/certs/*.crt /root/.step/secrets/*_key /vagrant/certs/
fi

# Make the cert dir to prevent pop-up later
mkdir /tmp/certs/

# Update the ca.json to allow for longer cert durations
jq '.authority.provisioners[] |= if .name == "Elasticsearch" then .claims.maxTLSCertDuration = "8760h" else . end' /root/.step/config/ca.json > /root/.step/config/ca.json.tmp && mv -f /root/.step/config/ca.json.tmp /root/.step/config/ca.json

# Define the IP addresses for each instance
declare -A ips=( ["elasticsearch"]="${IP_ADDR}" ["fleet"]="${IP_ADDR}" )

# Make the certs
for instance in "${!ips[@]}"; do
  step ca certificate --password-file "/vagrant/ca-password.txt" --provisioner Elasticsearch --not-after 8760h --san "${ips[$instance]}" --san atomicfirefly-elastic "$instance.$DNS" /tmp/certs/$instance.crt /tmp/certs/$instance.key --offline 
done

mkdir /etc/kibana/certs
mkdir /etc/pki/fleet

# Copy the certs to the correct location

cp /root/.step/certs/root_ca.crt /tmp/certs/elasticsearch* /etc/elasticsearch/certs
cp /root/.step/certs/root_ca.crt /tmp/certs/fleet* /etc/pki/fleet
cp -r /tmp/certs/* /root/

# Change the permissions
chown -R elasticsearch:elasticsearch /etc/elasticsearch/certs
chown -R root:root /etc/pki/fleet

# Make the CA dir
mkdir /etc/elastic-step-ca

# Create the password file
cp /vagrant/ca-password.txt /etc/elastic-step-ca/password.txt

# Make the user for the CA
useradd --user-group --system --home /etc/step-ca --shell /bin/false step
setcap CAP_NET_BIND_SERVICE=+eip $(which step-ca)
cp -r $(step path)/* /etc/elastic-step-ca
chown -R step:step /etc/elastic-step-ca

# Move the certs to the correct location
mkdir /etc/caddy/certs
cp /etc/elastic-step-ca/certs/root_ca.crt /etc/caddy/certs/
chown -R caddy:caddy /etc/caddy/certs
cp /etc/elastic-step-ca/certs/root_ca.crt /etc/kibana/certs/
chown -R kibana:kibana /etc/kibana/certs

# Change the defaults.json
jq '."ca-config" = "/etc/elastic-step-ca/config/ca.json" | ."root" = "/etc/elastic-step-ca/certs/root_ca.crt"' /etc/elastic-step-ca/config/defaults.json > /etc/elastic-step-ca/config/defaults.json.tmp && mv -f /etc/elastic-step-ca/config/defaults.json.tmp /etc/elastic-step-ca/config/defaults.json

# Change the ca.json
jq '."root" = "/etc/elastic-step-ca/certs/root_ca.crt" | ."crt" = "/etc/elastic-step-ca/certs/intermediate_ca.crt" | ."key" = "/etc/elastic-step-ca/secrets/intermediate_ca_key" | ."db"."dataSource" = "/etc/elastic-step-ca/db"' /etc/elastic-step-ca/config/ca.json > /etc/elastic-step-ca/config/ca.json.tmp && mv -f /etc/elastic-step-ca/config/ca.json.tmp /etc/elastic-step-ca/config/ca.json

# Create the systemd service for the CA
cat > /lib/systemd/system/elastic-step-ca.service << EOF
[Unit]
Description=elastic-step-ca service
Documentation=https://smallstep.com/docs/step-ca
Documentation=https://smallstep.com/docs/step-ca/certificate-authority-server-production
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=30
StartLimitBurst=3
ConditionFileNotEmpty=/etc/elastic-step-ca/config/ca.json
ConditionFileNotEmpty=/etc/elastic-step-ca/password.txt

[Service]
Type=simple
User=step
Group=step
Environment=STEPPATH=/etc/elastic-step-ca
WorkingDirectory=/etc/elastic-step-ca
ExecStart=/usr/bin/step-ca config/ca.json --password-file password.txt
ExecReload=/bin/kill --signal HUP $MAINPID
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
StartLimitInterval=30
StartLimitBurst=3

; Process capabilities & privileges
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
SecureBits=keep-caps
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
EOF

# Start the CA
systemctl daemon-reload
systemctl start elastic-step-ca
systemctl enable elastic-step-ca

# Create the Caddyfile for Kibana using acme
cat > /etc/caddy/Caddyfile << EOF
$DNS:$K_PORT_EXT {
    reverse_proxy http://127.0.0.1:${K_PORT} {
        header_up Host {host}
        header_up X-Real-IP {remote}
        header_up X-Forwarded-For {remote}
    }
    tls test@home.test {
       ca https://ca.${DNS}:8443/acme/acme/directory
       ca_root /etc/caddy/certs/root_ca.crt
    }
}
EOF

# Start Caddy
systemctl start caddy
systemctl enable caddy

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
xpack.security.transport.ssl.certificate_authorities: [ "/etc/elasticsearch/certs/root_ca.crt" ]
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.key: /etc/elasticsearch/certs/elasticsearch.key
xpack.security.http.ssl.certificate: /etc/elasticsearch/certs/elasticsearch.crt
xpack.security.http.ssl.certificate_authorities: [ "/etc/elasticsearch/certs/root_ca.crt" ]
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
server.publicBaseUrl: "https://$DNS:$K_PORT_EXT"
# ------------------------------ Elasticsearch --------------------------------
elasticsearch.hosts: ["https://$IP_ADDR:$ES_PORT"]
elasticsearch.username: "kibana_system"
elasticsearch.password: "\${elasticsearch.password}"
# ---------------------------------- Various -----------------------------------
telemetry.enabled: false
server.ssl.enabled: false
elasticsearch.ssl.certificateAuthorities: [ "/etc/kibana/certs/root_ca.crt" ]
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
#grep "generated password for the elastic" /root/ESUpass.txt | awk '{print $11}' > /vagrant/Password.txt

# Test if Kibana is running
echo "Testing if Kibana is online, could take some time, no more than 5 mins"
until curl --silent --cacert /vagrant/certs/root_ca.crt -XGET "https://$DNS:$K_PORT_EXT/api/fleet/agent_policies" -H 'accept: application/json' -u elastic:$E_PASS | grep -q '"items":\[\]'
do
    echo "Kibana starting, still waiting..."
    sleep 5
done
echo "Kibana online!"

# Install all the prebuilt rules
curl --silent -XPUT \
  --user elastic:$E_PASS \
  --cacert /vagrant/certs/root_ca.crt \
  --header @/vagrant/config/headers.txt \
  --url "https://$DNS:$K_PORT_EXT/api/detection_engine/rules/prepackaged"

# Make the Fleet token
curl --silent -XPUT --url "https://$IP_ADDR:$ES_PORT/_security/service/elastic/fleet-server/credential/token/fleet-token-1" \
 --user elastic:$E_PASS \
 --output /root/Ftoken.txt \
 --cacert /vagrant/certs/root_ca.crt

jq --raw-output '.token.value' /root/Ftoken.txt > /vagrant/tokens/Ftoken.txt

# Add Fleet Policy
curl --silent -XPOST \
  --user  elastic:$E_PASS \
  --output /root/FPid.txt \
  --cacert /vagrant/certs/root_ca.crt \
  --url "https://$DNS:$K_PORT_EXT/api/fleet/agent_policies?sys_monitoring=true" \
  --header @/vagrant/config/headers.txt \
  --data @/vagrant/config/fleet_policy_add.json

jq --raw-output '.item.id' /root/FPid.txt > /vagrant/keys/FPid.txt

export FLEET_POLICY_ID=$(cat /vagrant/keys/FPid.txt)

# Add Fleet Integration
curl --silent -XPOST \
  --user elastic:$E_PASS \
  --output /root/FIid.txt \
  --cacert /vagrant/certs/root_ca.crt \
  --url "https://$DNS:$K_PORT_EXT/api/fleet/package_policies" \
  --header @/vagrant/config/headers.txt \
  --data @<(envsubst < /vagrant/config/fleet_integration_add.json)

jq --raw-output '.item.id' /root/FIid.txt > /vagrant/keys/FIid.txt

# Add host IP and yaml settings to Fleet API
curl --silent -XPUT \
 --user elastic:$E_PASS \
 --cacert /vagrant/certs/root_ca.crt \
 --url "https://$DNS:$K_PORT_EXT/api/fleet/package_policies/$(cat /vagrant/keys/FIid.txt)" \
 --header @/vagrant/config/headers.txt \
 --data @<(envsubst < /vagrant/config/fleet_integration_update_ip.json)

# Add host IP and yaml settings to Fleet API
 curl --silent -XPUT \
 --user elastic:$E_PASS \
 --cacert /vagrant/certs/root_ca.crt \
 --url "https://$DNS:$K_PORT_EXT/api/fleet/outputs/fleet-default-output" \
 --header @/vagrant/config/headers.txt \
 --data @<(envsubst < /vagrant/config/fleet_integration_update_es_ip.json)


# Create the Windows Policy
curl --silent -XPOST \
  --user elastic:$E_PASS \
  --output /root/WPid.txt \
  --cacert /vagrant/certs/root_ca.crt \
  --url "https://$DNS:$K_PORT_EXT/api/fleet/agent_policies?sys_monitoring=true" \
  --header @/vagrant/config/headers.txt \
  --data @/vagrant/config/windows_policy_add.json

jq --raw-output '.item.id' /root/WPid.txt > /vagrant/keys/WPid.txt

export WINDOWS_POLICY_ID=$(cat /vagrant/keys/WPid.txt)

# Create the Linux Policy
curl --silent -XPOST \
  --user elastic:$E_PASS \
  --output /root/LPid.txt \
  --cacert /vagrant/certs/root_ca.crt \
  --url "https://$DNS:$K_PORT_EXT/api/fleet/agent_policies?sys_monitoring=true" \
  --header @/vagrant/config/headers.txt \
  --data @/vagrant/config/linux_policy_add.json

jq --raw-output '.item.id' /root/LPid.txt > /vagrant/keys/LPid.txt

export LINUX_POLICY_ID=$(cat /vagrant/keys/LPid.txt)

# Add Windows Integration
curl --silent -XPOST \
  --user elastic:$E_PASS \
  --output /root/WIid.txt \
  --cacert /vagrant/certs/root_ca.crt \
  --url "https://$DNS:$K_PORT_EXT/api/fleet/package_policies" \
  --header @/vagrant/config/headers.txt \
  --data @<(envsubst < /vagrant/config/windows_integration_add.json)

jq --raw-output '.item.id' /root/WIid.txt > /vagrant/keys/WIid.txt

# Add Custom Windows Event Logs - Windows Defender Logs
curl --silent -XPOST \
  --user elastic:$E_PASS \
  --output /root/CWIid.txt \
  --cacert /vagrant/certs/root_ca.crt \
  --url "https://$DNS:$K_PORT_EXT/api/fleet/package_policies" \
  --header @/vagrant/config/headers.txt \
  --data @<(envsubst < /vagrant/config/windows_integration_update_defender_logs.json)

# Create the Windows Elastic Defender Intigration 
curl -XPOST \
  --user elastic:$E_PASS \
  --output /root/WEDI.txt \
  --cacert /vagrant/certs/root_ca.crt \
  --url "https://$DNS:$K_PORT_EXT/api/fleet/package_policies" \
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
  --cacert /vagrant/certs/root_ca.crt \
  --url "https://$DNS:$K_PORT_EXT/api/fleet/package_policies/$(cat /vagrant/keys/WEDIid.txt)" \
  --header @<(envsubst < /vagrant/config/sec_headers.txt) \
  --data @/root/WEDI_in.txt

# Add Linux Auditd Integration
curl --silent -XPOST \
  --user elastic:$E_PASS \
  --output /root/LIid.txt \
  --cacert /vagrant/certs/root_ca.crt \
  --url "https://$DNS:$K_PORT_EXT/api/fleet/package_policies" \
  --header @/vagrant/config/headers.txt \
  --data @<(envsubst < /vagrant/config/linux_integration_auditd_add.json)

jq --raw-output '.item.id' /root/LIid.txt > /vagrant/keys/LIid.txt

# Create the Linux Elastic Defender Intigration 
curl --silent -XPOST \
  --user elastic:$E_PASS \
  --output /root/LEDI.txt \
  --cacert /vagrant/certs/root_ca.crt \
  --url "https://$DNS:$K_PORT_EXT/api/fleet/package_policies" \
  --header @<(envsubst < /vagrant/config/sec_headers.txt) \
  --data @<(envsubst < /vagrant/config/linux_integration_defender_add.json)

jq --raw-output '.item.id' /root/LEDI.txt > /vagrant/keys/LEDIid.txt

jq 'del(.item.id, .item.revision, .item.created_at, .item.created_by, .item.updated_at, .item.updated_by) | .item' /root/LEDI.txt > /root/LEDI_out.txt

jq '.inputs[0].config.policy.value.windows.malware.mode = "detect" |
.inputs[0].config.policy.value.mac.malware.mode = "detect" |
.inputs[0].config.policy.value.linux.malware.mode = "detect"' /root/LEDI_out.txt > /root/LEDI_in.txt

# Update the Linux Elastic Defender Intigration to detect mode
curl --silent --user elastic:$E_PASS -XPUT "https://$DNS:$K_PORT_EXT/api/fleet/package_policies/$(cat /vagrant/keys/LEDIid.txt)" \
  --cacert /vagrant/certs/root_ca.crt \
  --header @<(envsubst < /vagrant/config/sec_headers.txt) \
  --data @/root/LEDI_in.txt

# Enable all Windows and Linux default alerts (must have the pipe to dev null or it will spam STDOUT)
curl --silent -XPOST \
  --user elastic:$E_PASS \
  --cacert /vagrant/certs/root_ca.crt \
  --header @/vagrant/config/headers.txt \
  --url "https://$DNS:$K_PORT_EXT/api/detection_engine/rules/_bulk_action" \
  --data '{
  "query": "alert.attributes.tags: \"OS: Windows\" OR alert.attributes.tags: \"OS: Linux\"",
  "action": "enable"
}' > /dev/null

# Install the fleet server
sudo /opt/elastic-agent-$VER-linux-x86_64/elastic-agent install -f --url=https://$DNS:$F_PORT \
 --fleet-server-es=https://$DNS:$ES_PORT \
 --fleet-server-service-token=$(cat /vagrant/tokens/Ftoken.txt) \
 --fleet-server-policy=$(cat /vagrant/keys/FPid.txt) \
 --certificate-authorities=/vagrant/certs/root_ca.crt \
 --fleet-server-es-ca=/etc/pki/fleet/root_ca.crt \
 --fleet-server-cert=/etc/pki/fleet/fleet.crt \
 --fleet-server-cert-key=/etc/pki/fleet/fleet.key

# Get the Windows policy id
curl --silent --cacert /vagrant/certs/root_ca.crt -XGET "https://$DNS:$K_PORT_EXT/api/fleet/enrollment_api_keys" -H 'accept: application/json' -u elastic:$E_PASS | sed -e "s/\},{/'\n'/g" -e "s/items/'\n'/g" | grep -E -m1 $(cat /vagrant/keys/WPid.txt) | grep -oP '[a-zA-Z0-9\=]{40,}' > /vagrant/tokens/WAEtoken.txt
# Get the Linux policy id
curl --silent --cacert /vagrant/certs/root_ca.crt -XGET "https://$DNS:$K_PORT_EXT/api/fleet/enrollment_api_keys" -H 'accept: application/json' -u elastic:$E_PASS | sed -e "s/\},{/'\n'/g" -e "s/items/'\n'/g" | grep -E -m1 $(cat /vagrant/keys/LPid.txt) | grep -oP '[a-zA-Z0-9\=]{40,}' > /vagrant/tokens/LAEtoken.txt

# Cleanup
for file in "/root/ESUpass.txt" "/root/Kibpass.txt" "/root/Ftoken.txt" "/root/FPid.txt" "/root/FIid.txt" "/root/WPid.txt" "/root/LPid.txt" "/root/WIid.txt" "/root/CWIid.txt" "/root/WEDI.txt" "/root/WEDI_out.txt" "/root/WEDI_in.txt" "/root/LIid.txt" "/root/LEDI.txt" "/root/LEDI_out.txt" "/root/LEDI_in.txt"
do
    sudo rm -f "$file"
done

echo "Go to https://$DNS:$K_PORT_EXT once you have updated your DNS settings in your hosts, hosts file!"
echo "It must be https://$DNS:$K_PORT_EXT and must point to $IP_ADDR due to a reverse proxy being used"
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
echo "To enroll Windows agents use this token: $(cat /vagrant/tokens/WAEtoken.txt)"
echo "To enroll Linux agents use this token: $(cat /vagrant/tokens/LAEtoken.txt)"