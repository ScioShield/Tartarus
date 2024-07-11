#Copyright 2021 punkt.de GmbH
#Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
#Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#
#Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#
#THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#Code from https://github.com/punktDe/vagrant-opnsense/tree/main (2024)
#Modifications by ScioShield

opnsense_release='24.1'                # Which OPNsense release to install
virtual_machine_ip='192.168.56.2'     # IP address of the firewall in the host-only network

fetch -o opnsense-bootstrap.sh https://raw.githubusercontent.com/opnsense/update/$opnsense_release/src/bootstrap/opnsense-bootstrap.sh.in

# Remove reboot command from bootstrap script
sed -i '' -e '/reboot$/d' opnsense-bootstrap.sh

# Start bootstrap
sh ./opnsense-bootstrap.sh -r $opnsense_release -y

# Set correct interface names so OPNsense's order matches Vagrant's
sed -i '' -e 's/mismatch0/em1/' /usr/local/etc/config.xml
sed -i '' -e 's/mismatch1/em0/' /usr/local/etc/config.xml

# Remove IPv6 configuration from WAN
sed -i '' -e '/<ipaddrv6>dhcp6<\/ipaddrv6>/d' /usr/local/etc/config.xml

# Remove IPv6 configuration from LAN
sed -i '' -e '/<ipaddrv6>track6<\/ipaddrv6>/d' /usr/local/etc/config.xml
sed -i '' -e '/<subnetv6>64<\/subnetv6>/d' /usr/local/etc/config.xml
sed -i '' -e '/<track6-interface>wan<\/track6-interface>/d' /usr/local/etc/config.xml
sed -i '' -e '/<track6-prefix-id>0<\/track6-prefix-id>/d' /usr/local/etc/config.xml

# Change OPNsense LAN IP addresses to VirtualBox compatible one
sed -i '' -e "s/192\.168\.1\.1</${virtual_machine_ip}</" /usr/local/etc/config.xml

# Change DHCP range to match LAN IP address
lan_net=$(echo "${virtual_machine_ip}" | sed 's/\.[0-9]*$//')
sed -i '' -e "s/192\.168\.1\./${lan_net}./" /usr/local/etc/config.xml

# Create SSH file
cat > ssh.xml << EOF
      <enabled>enabled</enabled>
EOF

# Enable SSH by default
sed -i '' -e '/<group>admins<\/group>/r ssh.xml' /usr/local/etc/config.xml

# Create Filter file
cat > filter.xml << EOF
    <rule>
      <type>pass</type>
      <ipprotocol>inet</ipprotocol>
      <statetype>keep state</statetype>
      <descr>Allow SSH on all interfaces</descr>
      <direction>in</direction>
      <floating>yes</floating>
      <quick>1</quick>
      <protocol>tcp</protocol>
      <source>
        <any>1</any>
      </source>
      <destination>
        <any>1</any>
        <port>22</port>
      </destination>
    </rule>
EOF

# Allow SSH on all interfaces
sed -i '' -e '/<filter>/r filter.xml' /usr/local/etc/config.xml

# Do not block private networks on WAN
sed -i '' -e '/<blockpriv>1<\/blockpriv>/d' /usr/local/etc/config.xml

# Reset shell of Vagrant user
/usr/sbin/pw usermod vagrant -s /bin/sh

# Create XML config for Vagrant user
key=$(b64encode -r dummy <.ssh/authorized_keys | tr -d '\n')
cat > vagrant.xml << EOF
    <user>
      <name>vagrant</name>
      <descr>Vagrant User</descr>
      <scope>system</scope>
      <groupname>admins</groupname>
      <password>*</password>
      <uid>1001</uid>
      <shell>/bin/sh</shell>
      <authorizedkeys>${key}</authorizedkeys>
    </user>
EOF

# Create XML config for OPNsense admins
cat >> admins.xml << EOF
      <member>1001</member>
EOF

# Add Vagrant user - OPNsense style
sed -i '' -e '/<\/member>/r admins.xml' /usr/local/etc/config.xml
sed -i '' -e '/<\/user>/r vagrant.xml' /usr/local/etc/config.xml

# Change home directory to group nobody
chgrp -R nobody /usr/home/vagrant

# Display helpful message for the user
echo '#####################################################'
echo '#   #'
echo '#  OPNsense provisioning finished - shutting down.  #'
echo '#  Use `vagrant up` to start your OPNsense. #'
echo '#   #'
echo '#####################################################'

# Reboot the system
shutdown -r now