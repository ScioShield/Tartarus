#!/usr/bin/env bash
# This will only work on Rocky Linux (it has not been tested on other distros!)

export VER=$(grep -oE "^VER=(.*)" /vagrant/vars | cut -d "=" -f2)
export IP_ADDR=$(grep -oE "^IP_ADDR=(.*)" /vagrant/vars | cut -d "=" -f2)
export K_PORT=$(grep -oE "^K_PORT=(.*)" /vagrant/vars | cut -d "=" -f2)
export K_PORT_EXT=$(grep -oE "^K_PORT_EXT=(.*)" /vagrant/vars | cut -d "=" -f2)
export ES_PORT=$(grep -oE "^ES_PORT=(.*)" /vagrant/vars | cut -d "=" -f2)
export F_PORT=$(grep -oE "^F_PORT=(.*)" /vagrant/vars | cut -d "=" -f2)
export DNS=$(grep -oE "^DNS=(.*)" /vagrant/vars | cut -d "=" -f2)

export API_KEY=$(cat /vagrant/keys/ESapikey.txt)

# Check if Kibana is reachable 
kcheck=$(curl -L --silent --output /dev/null --cacert /vagrant/certs/root_ca.crt -XGET 'https://tartarus-elastic.home.arpa:5443' --write-out %{http_code})
until [ $kcheck -eq 200 ]
do
  echo "Checking if Kibana is reachable, retrying..."
  sleep 5
done
echo "Kibana is reachable"

# Create the Linux Policy
curl --silent -XPOST \
  --output /root/LPid.txt \
  --cacert /vagrant/certs/root_ca.crt \
  --url "https://$DNS:$K_PORT_EXT/api/fleet/agent_policies?sys_monitoring=true" \
  --header @<(envsubst < /vagrant/config/auth_headers.txt) \
  --data @/vagrant/config/linux_policy_add.json

jq --raw-output '.item.id' /root/LPid.txt > /vagrant/keys/LPid.txt

export LINUX_POLICY_ID=$(cat /vagrant/keys/LPid.txt)

# Add Linux Auditd Integration
curl --silent -XPOST \
  --output /root/LIid.txt \
  --cacert /vagrant/certs/root_ca.crt \
  --url "https://$DNS:$K_PORT_EXT/api/fleet/package_policies" \
  --header @<(envsubst < /vagrant/config/auth_headers.txt) \
  --data @<(envsubst < /vagrant/config/linux_integration_auditd_add.json)

jq --raw-output '.item.id' /root/LIid.txt > /vagrant/keys/LIid.txt

# Create the Linux Elastic Defender Intigration 
curl --silent -XPOST \
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
curl --silent -XPUT "https://$DNS:$K_PORT_EXT/api/fleet/package_policies/$(cat /vagrant/keys/LEDIid.txt)" \
  --cacert /vagrant/certs/root_ca.crt \
  --header @<(envsubst < /vagrant/config/sec_headers.txt) \
  --data @/root/LEDI_in.txt > /dev/null

# Get the Linux policy id
curl --silent --cacert /vagrant/certs/root_ca.crt -XGET "https://$DNS:$K_PORT_EXT/api/fleet/enrollment_api_keys" -H 'accept: application/json' -H "Authorization: ApiKey ${API_KEY}" | sed -e "s/\},{/'\n'/g" -e "s/items/'\n'/g" | grep -E -m1 $(cat /vagrant/keys/LPid.txt) | grep -oP '[a-zA-Z0-9\=]{40,}' > /vagrant/tokens/LAEtoken.txt