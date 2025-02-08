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