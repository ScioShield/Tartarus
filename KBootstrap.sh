#!/usr/bin/env bash

# Set desired Go version
go_version="1.20.3"

# Check if Go is installed and get its version
installed_go_version="$(go version 2>/dev/null | grep -oP 'go\K[0-9.]+')"

# Install Go if not installed or if the installed version is not the desired version
if [ -z "$installed_go_version" ] || [ "$installed_go_version" != "$go_version" ]; then
  wget -nc -q "https://go.dev/dl/go${go_version}.linux-amd64.tar.gz" -P /vagrant/apps
  sudo bash -c 'rm -rf /usr/local/go && tar -C /usr/local -xzf "/vagrant/apps/go'${go_version}'.linux-amd64.tar.gz"'
  echo "Go ${go_version} installed"
else
  echo "Go ${go_version} is already installed"
fi

# Install Caldera if not already installed
# Due to an issue with the Python version in Kali we are unable to pin to 4.1.0
caldera_dir="/opt/caldera"
if [ ! -d "$caldera_dir" ]; then
  sudo git clone -q https://github.com/mitre/caldera.git --recursive "$caldera_dir"
  sudo chown -R vagrant:vagrant "$caldera_dir"
  sudo -u vagrant python3 -m pip install --no-warn-script-location -q -r "$caldera_dir/requirements.txt"
  echo "Caldera installed"
else
  echo "Caldera is already installed"
fi

echo "run Caldera with 'cd /opt/caldera/ && python3 server.py --insecure'"
echo "there is a bug so Kali might not remain using the IP '192.168.56.129'"