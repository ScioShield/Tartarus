Vagrant.configure("2") do |config|
  config.vm.define "opnsense", autostart: true do |opnsense|
    opnsense.vm.box = "bento/freebsd-13.2"
    opnsense.vm.hostname = 'tartarus-opnsense'
    opnsense.vm.box_url = "bento/freebsd-13.2"
    opnsense.ssh.shell = '/bin/sh'
    opnsense.vm.synced_folder '.', '/vagrant', id: 'vagrant-root', disabled: true
    opnsense.vm.provision :shell, path: "OPBootstrap.sh"
    opnsense.vm.network :private_network, ip: "192.168.56.2"
    opnsense.vm.network :private_network, ip: "192.168.56.254"
    opnsense.vm.provider :virtualbox do |v|
     v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
     v.customize ["modifyvm", :id, "--cpus", 2]
     v.customize ["modifyvm", :id, "--memory", 2048]
     v.customize ["modifyvm", :id, "--name", "tartarus-opnsense"]
    end
  end

  config.vm.define "elastic", autostart: true do |elastic|
    elastic.vm.box = "bento/rockylinux-8.7"
    elastic.vm.hostname = 'tartarus-elastic'
    elastic.vm.box_url = "bento/rockylinux-8.7"
    elastic.vm.network :private_network, ip: "192.168.56.10", auto_config: false
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
      nmcli connection add type ethernet con-name eth1 ifname eth1 ip4 192.168.56.10/25 gw4 192.168.56.2
      nmcli connection modify eth1 ipv4.dns "1.1.1.1 1.0.0.1"
      nmcli connection modify eth1 ipv4.route-metric 10
      nmcli connection up eth1
    SHELL
    elastic.vm.provision :shell, path: "ESBootstrap.sh"
  end

  config.vm.define "linux", autostart: false do |linux|
    linux.vm.box = "bento/rockylinux-8.7"
    linux.vm.hostname = 'tartarus-linux'
    linux.vm.box_url = "bento/rockylinux-8.7"
    linux.vm.network :private_network, ip: "192.168.56.20"
    linux.vm.provider :virtualbox do |v|
      v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
      v.customize ["modifyvm", :id, "--cpus", 1]
      v.customize ["modifyvm", :id, "--memory", 4096]
      v.customize ["modifyvm", :id, "--name", "tartarus-linux"]
    end
    linux.vm.provision "shell", inline: <<-SHELL
    systemctl start NetworkManager
    systemctl enable NetworkManager
    nmcli connection add type ethernet con-name eth1 ifname eth1 ip4 192.168.56.20/25 gw4 192.168.56.2
    nmcli connection modify eth1 ipv4.dns "1.1.1.1 1.0.0.1"
    nmcli connection modify eth1 ipv4.route-metric 10
    nmcli connection up eth1
  SHELL
    linux.vm.provision :shell, path: "ALBootstrap.sh"
  end

  config.vm.define "ubuntu", autostart: false do |ubuntu|
    ubuntu.vm.box = "bento/ubuntu-20.04"
    ubuntu.vm.hostname = 'tartarus-ubuntu'
    ubuntu.vm.box_url = "bento/ubuntu-20.04"
    
    # Configuring both NAT and private network interfaces
    ubuntu.vm.network :private_network, ip: "192.168.56.21", netmask: "255.255.255.128"
    
    ubuntu.vm.provider :virtualbox do |v|
      v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
      v.customize ["modifyvm", :id, "--cpus", 1]
      v.customize ["modifyvm", :id, "--memory", 4096]
      v.customize ["modifyvm", :id, "--name", "tartarus-linux"]
    end
    
    # Provisioning script using Netplan
    ubuntu.vm.provision "shell", inline: <<-SHELL
      
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
        - 192.168.56.21/25
      gateway4: 192.168.56.2
      nameservers:
        addresses:
          - 1.1.1.1
          - 1.0.0.1
      routes:
        - to: default
          via: 192.168.56.2
          metric: 10
EOF
      # Apply Netplan configuration
      sudo netplan apply
    SHELL
    
    # Additional provisioning script
    ubuntu.vm.provision :shell, path: "ALBootstrap.sh"
  end
  

  config.vm.define "windows", autostart: false do |windows|
    windows.vm.box = "gusztavvargadr/windows-10-21h2-enterprise"
    windows.vm.hostname = 'tartarus-windows'
    windows.vm.box_url = "gusztavvargadr/windows-10-21h2-enterprise"
    windows.vm.network :private_network, ip: "192.168.56.30", auto_config: false
    windows.vm.provider :virtualbox do |v|
      v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
      v.customize ["modifyvm", :id, "--cpus", 2]
      v.customize ["modifyvm", :id, "--memory", 4096]
      v.customize ["modifyvm", :id, "--name", "tartarus-windows"]
    end
    windows.vm.provision "shell", privileged: true, inline: <<-SHELL
      $interfaceIndexEth2 = (Get-NetAdapter -Name 'Ethernet 2').InterfaceIndex
      New-NetIPAddress -InterfaceIndex $interfaceIndexEth2 -IPAddress 192.168.56.30 -PrefixLength 25 -DefaultGateway 192.168.56.2
      Set-DnsClientServerAddress -InterfaceIndex $interfaceIndexEth2 -ServerAddresses "1.1.1.1", "1.0.0.1"
      $interfaceIndexEth1 = (Get-NetAdapter -Name 'Ethernet').InterfaceIndex
      route change 0.0.0.0 mask 0.0.0.0 10.0.2.2 metric 1000 IF $interfaceIndexEth1
    SHELL
    windows.vm.provision :shell, privileged: "true", path: "AWBootstrap.ps1"
  end

  config.vm.define "kali", autostart: false do |kali|
    kali.vm.box = "kalilinux/rolling"
    kali.vm.hostname = 'tartarus-kali'
    kali.vm.box_url = "kalilinux/rolling"
    kali.vm.network :private_network, ip: "192.168.56.129", auto_config: false
    kali.vm.network :forwarded_port, guest: 8888, host: 8888, host_ip: "0.0.0.0", id: "caldera", auto_correct: true
    kali.vm.provider :virtualbox do |v|
      v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
      v.customize ["modifyvm", :id, "--cpus", 2]
      v.customize ["modifyvm", :id, "--memory", 4096]
      v.customize ["modifyvm", :id, "--name", "tartarus-kali"]
    end
    kali.vm.provision "shell", inline: <<-SHELL
    systemctl start NetworkManager
    systemctl enable NetworkManager
    nmcli connection add type ethernet con-name eth1 ifname eth1 ip4 192.168.56.129/25 gw4 192.168.56.254
    nmcli connection modify eth1 ipv4.dns "1.1.1.1 1.0.0.1"
    nmcli connection modify eth1 ipv4.route-metric 10
    nmcli connection up eth1
    echo "    metric 100" >> /etc/network/interfaces
    systemctl restart networking.service
    SHELL
  end
end