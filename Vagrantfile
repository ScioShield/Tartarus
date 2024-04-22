Vagrant.configure("2") do |config|
  config.vm.define "elastic" do |elastic|
    elastic.vm.box = "bento/rockylinux-8.7"
    elastic.vm.hostname = 'atomicfirefly-elastic'
    elastic.vm.box_url = "bento/rockylinux-8.7"
    elastic.vm.provision :shell, path: "ESBootstrap.sh"
    elastic.vm.network :private_network, ip:"192.168.56.10"
    elastic.vm.network :forwarded_port, guest: 5443, host: 5443, host_ip: "0.0.0.0", id: "kibana", auto_correct: true
    elastic.vm.provider :virtualbox do |v|
      v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
      v.customize ["modifyvm", :id, "--cpus", 4]
      v.customize ["modifyvm", :id, "--memory", 8192]
      v.customize ["modifyvm", :id, "--name", "atomicfirefly-elastic"]
    end
  end
  config.vm.define "linux", autostart: false do |linux|
    linux.vm.box = "bento/rockylinux-8.7"
    linux.vm.hostname = 'atomicfirefly-linux'
    linux.vm.box_url = "bento/rockylinux-8.7"
    linux.vm.provision :shell, path: "ALBootstrap.sh"
    linux.vm.network :private_network, ip: "192.168.56.20"
    linux.vm.provider :virtualbox do |v|
      v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
      v.customize ["modifyvm", :id, "--cpus", 1]
      v.customize ["modifyvm", :id, "--memory", 1024]
      v.customize ["modifyvm", :id, "--name", "atomicfirefly-linux"]
    end
  end
  config.vm.define "windows", autostart: false do |windows|
    windows.vm.box = "gusztavvargadr/windows-10-21h2-enterprise"
    windows.vm.hostname = 'atomicfirefly-windows'
    windows.vm.box_url = "gusztavvargadr/windows-10-21h2-enterprise"
    windows.vm.provision :shell, privileged: "true", path: "AWBootstrap.ps1"
    windows.vm.network :private_network, ip: "192.168.56.30"
    windows.vm.provider :virtualbox do |v|
     v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
     v.customize ["modifyvm", :id, "--cpus", 2]
     v.customize ["modifyvm", :id, "--memory", 4096]
     v.customize ["modifyvm", :id, "--name", "atomicfirefly-windows"]
    end
  end
  config.vm.define "kali", autostart: false do |kali|
    kali.vm.box = "kalilinux/rolling"
    kali.vm.hostname = 'atomicfirefly-kali'
    kali.vm.box_url = "kalilinux/rolling"
    kali.vm.provision :shell, path: "KBootstrap.sh"
    kali.vm.network :private_network, ip: "192.168.56.129"
    kali.vm.network :forwarded_port, guest: 8888, host: 8888, host_ip: "0.0.0.0", id: "caldera", auto_correct: true
    kali.vm.provider :virtualbox do |v|
     v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
     v.customize ["modifyvm", :id, "--cpus", 2]
     v.customize ["modifyvm", :id, "--memory", 4096]
     v.customize ["modifyvm", :id, "--name", "atomicfirefly-kali"]
    end
  end
end