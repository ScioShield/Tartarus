Vagrant.configure("2") do |config|
  config.vm.define "opnsense", autostart: true do |opnsense|
    opnsense.vm.box = "bento/freebsd-13.2"
    opnsense.vm.hostname = 'tartarus-opnsense'
    opnsense.vm.box_url = "bento/freebsd-13.2"
    opnsense.ssh.shell = '/bin/sh'
    opnsense.ssh.connect_timeout = 120
    opnsense.vm.synced_folder '.', '/vagrant', id: 'vagrant-root', disabled: true
    opnsense.vm.network "forwarded_port", guest: 443, host: 8443, auto_correct: true
    opnsense.vm.provision "file", source: "OPBootstrap.sh", destination: "/tmp/OPBootstrap.sh"
    opnsense.vm.provision "file", run: "always", source: "config/firewall.php", destination: "/tmp/firewall.php"
    opnsense.vm.provision "shell", run: "always", inline: <<-SHELL
      if ! /usr/local/sbin/pkg info | grep -q opnsense; then
        echo "OPNsense not installed. Running OPBootstrap.sh..."
        sh /tmp/OPBootstrap.sh
      elif [ -e /conf/config.xml ] && [ ! -e /conf/configured ]; then
        echo "OPNsense is already installed. Running config/firewall.php..."
        php /tmp/firewall.php
        touch /conf/configured
      else
        echo "OPNsense is already installed and configured."
      fi
    SHELL
    opnsense.vm.network :private_network, ip: "192.168.56.2", virtualbox__intnet: "vboxnet0"
    opnsense.vm.network :private_network, ip: "192.168.56.65", virtualbox__intnet: "vboxnet1"
    opnsense.vm.network :private_network, ip: "192.168.56.129", virtualbox__intnet: "vboxnet2"
    opnsense.vm.network :private_network, ip: "192.168.56.193", virtualbox__intnet: "vboxnet3"
    opnsense.vm.provider :virtualbox do |v|
     v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
     v.customize ["modifyvm", :id, "--cpus", 2]
     v.customize ["modifyvm", :id, "--memory", 1024]
     v.customize ["modifyvm", :id, "--name", "tartarus-opnsense"]
    end
  end

  config.vm.define "elastic", autostart: true do |elastic|
    elastic.vm.box = "bento/rockylinux-8.7"
    elastic.vm.hostname = 'tartarus-elastic'
    elastic.vm.box_url = "bento/rockylinux-8.7"
    elastic.vm.network :private_network, ip: "192.168.56.10", virtualbox__intnet: "vboxnet0", auto_config: false
    elastic.vm.network :forwarded_port, guest: 5443, host: 5443, host_ip: "0.0.0.0", id: "kibana", auto_correct: true
    elastic.vm.provider :virtualbox do |v|
      v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
      v.customize ["modifyvm", :id, "--cpus", 4]
      v.customize ["modifyvm", :id, "--memory", 8192]
      v.customize ["modifyvm", :id, "--name", "tartarus-elastic"]
    end
    elastic.vm.provision "shell", inline: <<-SHELL
      systemctl start NetworkManager
      systemctl enable NetworkManager

      # Check if the connection already exists
      if ! nmcli connection show eth1 >/dev/null 2>&1; then
        echo "Connection eth1 not found. Adding new connection."
        nmcli connection add type ethernet con-name eth1 ifname eth1 ip4 192.168.56.10/26 gw4 192.168.56.2
        nmcli connection modify eth1 ipv4.dns "192.168.56.2"
        nmcli connection modify eth1 ipv4.route-metric 10
      else
        echo "Connection eth1 already exists. Skipping addition."
      fi

      # Bring the connection up
      nmcli connection up eth1
    SHELL
    
    if (ENV['HOSTS'] == nil or ENV['HOSTS'] == 'elastic')
      elastic.vm.provision "shell", inline: <<-SHELL
        if ! systemctl is-active --quiet elasticsearch; then
          echo "Elasticsearch service not running. Running ESBootstrap.sh."
          bash /vagrant/ESBootstrap.sh
          bash /vagrant/PostBootstrap.sh
        else
          echo "Elasticsearch service is already running. Skipping bootstrap scripts."
        fi
      SHELL
    end
    if ENV['HOSTS'] == 'windows'
      elastic.vm.provision "shell", inline: <<-SHELL
        if ! systemctl is-active --quiet elasticsearch; then
          echo "Elasticsearch service not running. Running ESBootstrap.sh and WBootstrap.sh"
          bash /vagrant/ESBootstrap.sh
          bash /vagrant/PostBootstrap.sh
          bash /vagrant/WBootstrap.sh
        elif [ ! -e /vagrant/keys/WEDIid.txt ]; then
          echo "Elasticsearch service is running. Installing Windows addons"
          bash /vagrant/WBootstrap.sh
        else
          echo "Elasticsearch service is running and Windows addons already installed"
        fi
      SHELL
    end
    if ENV['HOSTS'] == 'linux'
      elastic.vm.provision "shell", inline: <<-SHELL
        if ! systemctl is-active --quiet elasticsearch; then
          echo "Elasticsearch service not running. Running ESBootstrap.sh and LBootstrap.sh"
          bash /vagrant/ESBootstrap.sh
          bash /vagrant/PostBootstrap.sh
          bash /vagrant/LBootstrap.sh
        elif [ ! -e /vagrant/keys/LEDIid.txt ]; then
          echo "Elasticsearch service is running. Installing Linux addons"
          bash /vagrant/LBootstrap.sh
        else
          echo "Elasticsearch service is running and Linux addons already installed"
        fi
      SHELL
    end
    if ENV['HOSTS'] == 'linwin'
      elastic.vm.provision "shell", inline: <<-SHELL
        if ! systemctl is-active --quiet elasticsearch; then
          echo "Elasticsearch service not running. Running ESBootstrap.sh, LBootstrap.sh and WBootstrap.sh"
          bash /vagrant/ESBootstrap.sh
          bash /vagrant/PostBootstrap.sh
          bash /vagrant/LBootstrap.sh
          bash /vagrant/WBootstrap.sh
        elif [[ ! -e /vagrant/keys/LEDIid.txt && ! -e /vagrant/keys/WEDIid.txt ]]; then
          echo "Elasticsearch service is running. Installing Linux and Windows addons"
          bash /vagrant/LBootstrap.sh
          bash /vagrant/WBootstrap.sh
        elif [ ! -e /vagrant/keys/LEDIid.txt ]; then
          echo "Elasticsearch service is running. Installing Linux addons"
          bash /vagrant/LBootstrap.sh
        elif [ ! -e /vagrant/keys/WEDIid.txt ]; then
          echo "Elasticsearch service is running. Installing Windows addons"
          bash /vagrant/WBootstrap.sh
        else
          echo "Elasticsearch service is running and Linux and Windows addons already installed"
        fi
      SHELL
    end
    if ENV['HOSTS'] == 'dvwa'
      elastic.vm.provision "shell", inline: <<-SHELL
        if ! systemctl is-active --quiet elasticsearch; then
          echo "Elasticsearch service not running. Running ESBootstrap.sh and APACHELBootstrap.sh"
          bash /vagrant/ESBootstrap.sh
          bash /vagrant/PostBootstrap.sh
          bash /vagrant/APACHELBootstrap.sh
        elif [ ! -e /vagrant/keys/APACHELEDIid.txt ]; then
          echo "Elasticsearch service is running. Installing Linux - Apache addons"
          bash /vagrant/APACHELBootstrap.sh
        else
          echo "Elasticsearch service is running and Linux addons already installed"
        fi
      SHELL
    end
    elastic.trigger.before :destroy do |trigger|
      trigger.warn = "Removing all .txt files from the local keys/ directory"
    
      if Vagrant::Util::Platform.windows?
        trigger.run = {
          inline: "powershell -Command \"if ((Get-Location).Path -match '\\\\Tartarus$' -and (Test-Path keys)) { Remove-Item -Path keys\\*.txt -Force -ErrorAction SilentlyContinue }\""
        }
      else
        trigger.run = {
          inline: <<-SHELL
            bash -c 'if [ "$(basename $(pwd))" = "Tartarus" ] && [ -d keys ]; then
              rm -rf keys/*.txt
            fi'
          SHELL
        }
      end
    end
  end
    

  config.vm.define "linux", autostart: false do |linux|
    linux.vm.box = "bento/rockylinux-8.7"
    linux.vm.hostname = 'tartarus-linux'
    linux.vm.box_url = "bento/rockylinux-8.7"
    linux.vm.network :private_network, ip: "192.168.56.70", virtualbox__intnet: "vboxnet1", auto_config: false
    linux.vm.provider :virtualbox do |v|
      v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
      v.customize ["modifyvm", :id, "--cpus", 1]
      v.customize ["modifyvm", :id, "--memory", 2048]
      v.customize ["modifyvm", :id, "--name", "tartarus-linux"]
    end
    linux.vm.provision "shell", inline: <<-SHELL
    systemctl start NetworkManager
    systemctl enable NetworkManager
    if ! nmcli connection show eth1 >/dev/null 2>&1; then
      echo "Connection eth1 not found. Adding new connection."
      nmcli connection add type ethernet con-name eth1 ifname eth1 ip4 192.168.56.70/26 gw4 192.168.56.65
      nmcli connection modify eth1 ipv4.dns "192.168.56.65"
      nmcli connection modify eth1 ipv4.route-metric 10
      nmcli connection up eth1
    else
      echo "Connection eth1 already exists."
    fi
  SHELL
    linux.vm.provision :shell, inline: <<-SHELL
      if ! systemctl is-active --quiet elastic-agent; then
        echo "Elastic Agent service not running. Running ALBootstrap.sh"
        bash /vagrant/ALBootstrap.sh
      else
        echo "Elastic Agent service is running"
      fi
    SHELL
  end

  config.vm.define "dvwa", autostart: false do |dvwa|
    dvwa.vm.box = "bento/ubuntu-20.04"
    dvwa.vm.hostname = 'tartarus-dvwa'
    dvwa.vm.box_url = "bento/ubuntu-20.04"
    
    # Configuring both NAT and private network interfaces
    dvwa.vm.network :private_network, ip: "192.168.56.71", virtualbox__intnet: "vboxnet1", auto_config: false
    dvwa.vm.network "forwarded_port", guest: 80, host: 8180, auto_correct: true
    
    dvwa.vm.provider :virtualbox do |v|
      v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
      v.customize ["modifyvm", :id, "--cpus", 1]
      v.customize ["modifyvm", :id, "--memory", 2028]
      v.customize ["modifyvm", :id, "--name", "tartarus-dvwa"]
    end
    
    # Provisioning script using Netplan
    dvwa.vm.provision "shell", inline: <<-SHELL
      
      # Create Netplan configuration
cat > /etc/netplan/01-netcfg.yaml << EOF
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: true
    eth1:
      dhcp4: no
      addresses:
        - 192.168.56.71/26
      gateway4: 192.168.56.65
      nameservers:
        addresses:
          - 192.168.56.65
      routes:
        - to: default
          via: 192.168.56.65
          metric: 10
EOF
      # Apply Netplan configuration
      sudo netplan apply
    SHELL
    
    # Additional provisioning script
    dvwa.vm.provision :shell,  inline: <<-SHELL
      if ! systemctl is-active --quiet elastic-agent; then
        echo "Elastic Agent service not running. Running APACHEALBootstrap.sh"
        bash /vagrant/APACHEALBootstrap.sh
      else
        echo "Elastic Agent service is running"
      fi
    SHELL
  end
  

  config.vm.define "windows", autostart: false do |windows|
    windows.vm.box = "gusztavvargadr/windows-10-21h2-enterprise"
    windows.vm.hostname = 'tartarus-windows'
    windows.vm.box_url = "gusztavvargadr/windows-10-21h2-enterprise"
    windows.vm.network :private_network, ip: "192.168.56.80", virtualbox__intnet: "vboxnet1", auto_config: false
    windows.vm.provider :virtualbox do |v|
      v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
      v.customize ["modifyvm", :id, "--cpus", 2]
      v.customize ["modifyvm", :id, "--memory", 4096]
      v.customize ["modifyvm", :id, "--name", "tartarus-windows"]
    end
    windows.vm.provision "shell", privileged: true, inline: <<-SHELL
      $interfaceIndexEth2 = (Get-NetAdapter -Name 'Ethernet 2').InterfaceIndex

      $existingIP = Get-NetIPAddress -InterfaceIndex $interfaceIndexEth2 -ErrorAction SilentlyContinue

      if ($existingIP -eq $null -or $existingIP.IPAddress -ne "192.168.56.80") {
          Write-Host "Setting IP address for Ethernet 2..."
          New-NetIPAddress -InterfaceIndex $interfaceIndexEth2 -IPAddress 192.168.56.80 -PrefixLength 26 -DefaultGateway 192.168.56.65
      } else {
          Write-Host "IP address already set. Skipping..."
      }
      
      Set-DnsClientServerAddress -InterfaceIndex $interfaceIndexEth2 -ServerAddresses "192.168.56.65"
      
      $interfaceIndexEth1 = (Get-NetAdapter -Name 'Ethernet').InterfaceIndex
      $routeExists = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceIndex $interfaceIndexEth1 -ErrorAction SilentlyContinue
      
      if ($routeExists -ne $null) {
          Write-Host "Route already exists. Updating metric..."
          route change 0.0.0.0 mask 0.0.0.0 10.0.2.2 metric 1000 IF $interfaceIndexEth1
      } else {
          Write-Host "Adding new route..."
          route add 0.0.0.0 mask 0.0.0.0 10.0.2.2 metric 1000 IF $interfaceIndexEth1
      }
    SHELL
    windows.vm.provision "shell", privileged: true, inline: <<-SHELL
      $service = Get-Service -Name "elastic-agent" -ErrorAction SilentlyContinue
      if ($service -eq $null -or $service.Status -ne "Running") {
        Write-Host "Elastic Agent is not running. Running AWBootstrap.ps1..."
        & "C:\\vagrant\\AWBootstrap.ps1"
      } else {
        Write-Host "Elastic Agent is already running. Skipping AWBootstrap.ps1."
      }
SHELL
  end

  config.vm.define "kali", autostart: false do |kali|
    kali.vm.box = "kalilinux/rolling"
    kali.vm.hostname = 'tartarus-kali'
    kali.vm.box_url = "kalilinux/rolling"
    kali.vm.network :private_network, ip: "192.168.56.200", virtualbox__intnet: "vboxnet3", auto_config: false
    kali.vm.provider :virtualbox do |v|
      v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
      v.customize ["modifyvm", :id, "--cpus", 4]
      v.customize ["modifyvm", :id, "--memory", 8192]
      v.customize ["modifyvm", :id, "--name", "tartarus-kali"]
    end
    kali.vm.provision "shell", inline: <<-SHELL
    systemctl start NetworkManager
    systemctl enable NetworkManager
    nmcli connection add type ethernet con-name eth1 ifname eth1 ip4 192.168.56.200/26 gw4 192.168.56.193
    nmcli connection modify eth1 ipv4.dns "192.168.56.193"
    nmcli connection modify eth1 ipv4.route-metric 10
    nmcli connection up eth1
    echo "    metric 100" >> /etc/network/interfaces
    systemctl restart networking.service
    SHELL
  end
end