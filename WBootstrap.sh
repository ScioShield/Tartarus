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

# Create the Windows Policy
curl --silent -XPOST \
  --output /root/WPid.txt \
  --cacert /vagrant/certs/root_ca.crt \
  --url "https://$DNS:$K_PORT_EXT/api/fleet/agent_policies?sys_monitoring=true" \
  --header @<(envsubst < /vagrant/config/auth_headers.txt) \
  --data @/vagrant/config/windows_policy_add.json

jq --raw-output '.item.id' /root/WPid.txt > /vagrant/keys/WPid.txt

export WINDOWS_POLICY_ID=$(cat /vagrant/keys/WPid.txt)

# Add Windows Integration
curl --silent -XPOST \
  --output /root/WIid.txt \
  --cacert /vagrant/certs/root_ca.crt \
  --url "https://$DNS:$K_PORT_EXT/api/fleet/package_policies" \
  --header @<(envsubst < /vagrant/config/auth_headers.txt) \
  --data @<(envsubst < /vagrant/config/windows_integration_add.json)

jq --raw-output '.item.id' /root/WIid.txt > /vagrant/keys/WIid.txt

# Add Custom Windows Event Logs - Windows Defender Logs
curl --silent -XPOST \
  --output /root/CWIid.txt \
  --cacert /vagrant/certs/root_ca.crt \
  --url "https://$DNS:$K_PORT_EXT/api/fleet/package_policies" \
  --header @<(envsubst < /vagrant/config/auth_headers.txt) \
  --data @<(envsubst < /vagrant/config/windows_integration_update_defender_logs.json)

# Create the Windows Elastic Defender Intigration 
curl --silent -XPOST \
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
  --cacert /vagrant/certs/root_ca.crt \
  --url "https://$DNS:$K_PORT_EXT/api/fleet/package_policies/$(cat /vagrant/keys/WEDIid.txt)" \
  --header @<(envsubst < /vagrant/config/sec_headers.txt) \
  --data @/root/WEDI_in.txt > /dev/null

# Get the Windows policy id
curl --silent --cacert /vagrant/certs/root_ca.crt -XGET "https://$DNS:$K_PORT_EXT/api/fleet/enrollment_api_keys" -H 'accept: application/json' -H "Authorization: ApiKey ${API_KEY}" | sed -e "s/\},{/'\n'/g" -e "s/items/'\n'/g" | grep -E -m1 $(cat /vagrant/keys/WPid.txt) | grep -oP '[a-zA-Z0-9\=]{40,}' > /vagrant/tokens/WAEtoken.txt