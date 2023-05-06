# AtomicFireFly
AtomicFireFly, is designed to automate the process of deploying and testing security products. This solution consists of a single node ElasticSearch cluster on a Rocky8 Linux guest (for CentOS/RHEL cross compatibility). The Windows node features Sysmon, Elastic Agent, and Atomic Red Team. Additionally, a Kali Linux instance with Caldera pre-packaged ensures comprehensive testing and monitoring.  

## Requirements (host)
### Hardware
RAM - 17 GB  
CPU - 9 Cores*  
Storage - 50 GB  
*Most modern CPUs have virtual cores so if you have a 4 physical core CPU you'll have 8 virtual cores.  
RAM and Core count can be tweaked in the Vagrantfile  
You don't have to bring up all systems at once, if you are just testing Windows 12 GB of RAM and 6 CPU Cores (3 physical) is enough.  

### Software
[VirtualBox](https://www.virtualbox.org/wiki/Downloads)  
[Vagrant](https://developer.hashicorp.com/vagrant/downloads)  

## Nodes (guests)

| VM Name               | Operating System                     | CPU Cores | Memory (MB) | Private IP     | Components                                                        |
|-----------------------|--------------------------------------|-----------|-------------|----------------|-------------------------------------------------------------------|
| atomicfirefly-elastic | bento/rockylinux-8.7                 | 4         | 8192        | 192.168.56.10  | ElasticSearch, Kibana, Fleet                                      |
| atomicfirefly-linux   | bento/rockylinux-8.7                 | 1         | 1024        | 192.168.56.20  | Elastic Agent                                                     |
| atomicfirefly-windows | gusztavvargadr/windows-10-21h2-enterprise | 2    | 4096        | 192.168.56.30  | Elastic Agent, Sysmon, Atomic Red Team                            |
| atomicfirefly-kali    | kalilinux/rolling                    | 2         | 4096        | 192.168.56.129 | Caldera                                                           |  

### IP Addresses 
| Reserved for         | IP Address Range |
|----------------------|------------------|
| Networking           | 1-9              |
| Security devices     | 10-19            |
| Linux hosts          | 20-29            |
| Windows hosts        | 30-39            |
| Adversaries          | 128+             |  

The Kali instance gets such a high IP so if an Opnsense firewall is added Kali can be out of "homenet" with a /25 network.  
There is an issue of it reassigning itself an IP after ~10 min, am investigating.  

## Setup  
Bring up Elastic, Windows, Linux, Kali or all hosts with the following commands.  
The Elastic cluster has to be started first if you want telemetry data!  

### Build
Provisions the VMs ready for use.  
#### Elastic + Windows  
`vagrant up elastic windows`  
#### Elastic + Linux  
`vagrant up elastic linux`  
#### Elastic + Linux + Windows
`vagrant up elastic linux windows`  
#### Elastic + Kali  
`vagrant up elastic kali`  
#### Elastic + Kali + Windows  
`vagrant up elastic kali windows`  
### Login  
#### Elastic  
`vagrant ssh elastic`  
#### Linux  
`vagrant ssh linux`  
#### Windows  
`vagrant ssh windows`  
On Windows open RDP client and connect to `127.0.0.1:53389`  
Username: vagrant  
Password: vagrant  
If you have `xfreerdp` installed on Linux (change /size to whatever you want, cert ignore is to dismiss the untrusted cert warning on first login, the 127.0.0.1 can also be changed to a remote address if needed)  
`xfreerdp /u:"vagrant" /p:"vagrant" /v:127.0.0.1:53389 /size:1300x700 /cert:ignore`  
#### Kali  
Should popup with a GUI at first boot (remember to enable x11 if you are remote)  
`vagrant ssh kali`  
Username: vagrant  
Password: vagrant  

### Suspend
All data is saved just shuts down the VM.  
#### Elastic  
`vagrant halt elastic`  
#### Linux  
`vagrant halt linux`  
#### Windows  
`vagrant halt windows`  
#### Kali  
`vagrant halt kali`  

### Re-build
Be careful here you will lose all data internal to each VM if you do this!  
All main apps (Elasticsearch, Kibana, Agents, Sysmon, Go, Git except Caldera and Atomic Red Team) won't be redownloaded and are safe in the apps/ dir, however their configs and internal data like the Elasticsearch database, any custom Kibana dashboards, alerts, etc. will be deleted and reprovisioned. You have been warned!  
#### Elastic  
`vagrant destroy elastic`  
`vagrant up elastic --provision`  
#### Linux  
`vagrant destroy linux`  
`vagrant up linux --provision`  
#### Windows  
Reprovisioning Windows will redownload Atomic Red Team every time as it doesn't go to the /apps dir!  
`vagrant destroy windows`  
`vagrant up windows --provision`  
#### Kali  
Reprovisioning Kali will redownload Caldera every time as it doesn't go to the /apps dir!  
`vagrant destroy kali`  
`vagrant up kali --provision`  

### DNS settings
Used for remote deployments
Replace (Vagrant host ip) with the IP of the host machine you will run Vagrant from  
Windows Powershell  
`Add-Content 'C:\Windows\System32\Drivers\etc\hosts' "(Vagrant host ip) atomicfirefly-elastic"`  
Linux Bash  
`echo "(Vagrant host ip) atomicfirefly-elastic" >> /etc/hosts`  

## Kibana  
It is safe to ignore the HTTPS certificate warning as we generated our own self-signed certs in this instance.  
Log into Kibana (local)  
From your host machine  
`https://192.168.56.10:5601`  
`https://127.0.0.1:5601`  
Log into Kibana (remote)  
`https://atomicfirefly-elastic:5601`  
  
Username: `elastic` 
The password is in a file called "Password.txt" in the directory you ran Vagrant from,  
this is the password to the Superuser account so be careful.  
The password is also printed to the terminal / shell you ran `vagrant up` from.  

## Vewing Kibana Alerts
Once you have logged into the Kibana instance on `https://192.168.56.10:5601` or `https://atomicfirefly-elastic:5601` now it is time to view the alerts.  
The Windows and Linux alerts are auto enabled for you.  
Search for alerts in the universal search tab, or open the burger and scroll down to the security tab.  
![elasticAlert1](images/elasticAlert1.png "welcome")  
Now search for "alerts".  
![elasticAlert2](images/elasticAlert2.png "search")  
You should see the alerts page (Note you might not have any alerts yet, you'd need to start the Windows host and run the  EDR-Telemetry-Generator for example)  
![elasticAlert3](images/alerts.png "alert")

## Atomic Red Team Tests
Using the EDR-Telemetry-Generator from [EDR-Telemetry](https://github.com/tsale/EDR-Telemetry)  
Open PowerShell and Git clone the EDR-Telemetry project and run it, Git is pre-installed for ease of use.  
`git clone https://github.com/tsale/EDR-Telemetry.git`  
It goes without saying but this should only be run on a VM, don't run it on your host OS!  
`& .\EDR-Telemetry\Tools\Telemetry-Generator\telemetry-generator.ps1`
![edrTelem](images/TelemetryGen.png "swoosh")
Now look at the Kibana alerts dashboard.  
![alerts](images/alerts.png "pow")

## Caldera Tests
Now start Caldera and log in.  
`vagrant up kali` to start the Kali instance.  
Bring up Caldera with `cd /opt/caldera/ && python3 server.py --insecure`  
![calderaStart](images/calderaStart.png "kaboom")  
Now log into Caldera `http://192.168.56.129:8888/`  
If you have issues accessing it run `ifconfig eth1` in a new shell window and note down the IP results if different than the default and connect to that instead.  
Username: red  
Password: admin  
![calderaLogin](images/calderaLogin.png "zap")  
Now you can do the usual. I highly recommend the in platform training for a better understanding.  



## Inspirations
The main inspiration for this work is from the incredible project [EDR-Telemetry](https://github.com/tsale/EDR-Telemetry)  
The use of Vagrant as a provisioner was inspired by [Jeff Geerling's](https://github.com/geerlingguy) excellent book Ansible for DevOps.  

## Resources
### TryHackMe
[Atomic Red Team](https://tryhackme.com/room/atomicredteam)  
[Elastic](https://tryhackme.com/room/investigatingwithelk101)  
### GitHub
[EDR-Telemetry](https://github.com/tsale/EDR-Telemetry)  
[Caldera](https://github.com/mitre/caldera)  
[Elastic](https://github.com/elastic)

## TODO
Look into how ART works on Linux  
Think about a config file to hold variables that all scripts can pull from, like hostname, IP_ADDR, VER, etc.  

## Future improvements
Add an Opnsense node  
Add a Remnux/CSI Linux node  
Use Ansible to provision all the nodes for true idempotence  
Look into a cloud deployment mode of Elastic like I did in https://github.com/ScioShield/Elastic-Cloud-Agent for those who don't have 64GB RAM :)  
