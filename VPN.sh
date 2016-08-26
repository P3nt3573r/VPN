#!/bin/bash

## ---------------------------------------------------------------
## Make sure the user wants to actually install the gateway
## ---------------------------------------------------------------
echo ""
while true; do
    read -p "Do you wish to install the tor gateway on this vyos instance? " -e -i y yn
    case $yn in
        [Yy]* ) break;;
        [Nn]* ) exit;;
        * ) echo "Please answer yes or no.";;
    esac
done


## ---------------------------------------------------------------
## Detect interfaces and IP addresses
## ---------------------------------------------------------------
i=1
for int in `ls /sys/class/net`; do
    if [ $i == 1 ]; then
        wanint=$int
        wanip=$(/sbin/ifconfig $wanint | awk -F ' *|:' '/inet addr/{print $4}')
        wangw=$(/sbin/ip route | awk '/default/ { print $3 }')
        i=2
    elif [ $i == 2 ]; then
        lanint=$int
        break
    fi
done


## ---------------------------------------------------------------
## Find interface, IP, and system info
## ---------------------------------------------------------------
echo -e "\n---------------------------------------------------------------"
echo "We will now collect some configuration info for the setup..."
echo "---------------------------------------------------------------"
read -p "WAN interface name: " -e -i $wanint wanint
read -p "WAN interface IP: " -e -i $wanip wanip
read -p "WAN interface netmask: " -e -i /27 wannm
read -p "WAN gateway address: " -e -i $wangw wangw
read -p "LAN interface name: " -e -i $lanint lanint
read -p "Domain name: " -e -i torgw.example.com domain
read -p "System nameserver #1 (Note: NOT used for tor or clients!): " -e -i 8.8.8.8 ns1
read -p "System nameserver #2 (Note: NOT used for tor or clients!): " -e -i 4.2.2.2 ns2
generatedvyospass=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)
read -p "VyOS admin password: " -e -i $generatedvyospass vyospass
generatedpsk=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)
read -p "L2TP pre-shared key: " -e -i $generatedpsk psk
read -p "First VPN user username: " -e -i user user1
generatedpass=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)
read -p "First VPN user password: " -e -i $generatedpass userpass1


## ---------------------------------------------------------------
## Check if user wants SSH enabled
## ---------------------------------------------------------------
while true; do
    read -p "Should we disable remote SSH access on this gateway? " -e -i n yn
    case $yn in
        [Yy]* ) 
            ssh=No;
            sshport=22;
            break;;
        [Nn]* ) 
            ssh=Yes;
            read -p "SSH listen port: " -e -i 22 sshport;
            break;;
        * ) echo "Please answer yes or no.";;
    esac
done


## ---------------------------------------------------------------
## Show configuration before applying
## ---------------------------------------------------------------
echo -e "\n---------------------------------------------------------------"
echo "Please double check your configuration values below!"
echo "---------------------------------------------------------------"
echo -e "WAN Interface:         $wanint"
echo -e "WAN IP:                $wanip"
echo -e "WAN Netmask:           $wannm"
echo -e "Gateway:               $wangw"
echo -e "LAN Interface:         $lanint"
echo -e "Domain Name:           $domain"
echo -e "SSH Enabled?           $ssh"
echo -e "SSH Port:              $sshport"
echo -e "VyOS User Password:    $vyospass"
echo -e "L2TP Pre-shared Key:   $psk"
echo -e "VPN User #1 Username:  $user1"
echo -e "VPN User #1 Password:  $userpass1"
echo ""

## ---------------------------------------------------------------
## Verify configuration with user
## ---------------------------------------------------------------
while true; do
    read -p "Are the above values correct? " yn
    case $yn in
        [Yy]* ) 
            break;;
        [Nn]* ) 
            exit;;
        * ) echo "Please answer yes or no.";;
    esac
done


## ---------------------------------------------------------------
## Vyos base configuration file
## ---------------------------------------------------------------
read -d '' vyosconf << EOF
firewall {
    all-ping disable
    broadcast-ping disable
    config-trap disable
    ipv6-receive-redirects disable
    ipv6-src-route disable
    ip-src-route disable
    log-martians disable
    name vpn-isolate {
        default-action drop
        rule 10 {
            action accept
            destination {
                address 172.16.0.1
                port 9040
            }
            protocol tcp
            source {
                address 172.16.0.10-172.16.255.254
            }
        }
        rule 20 {
            action accept
            destination {
                address 172.16.0.1
                port 53
            }
            protocol udp
            source {
                address 172.16.0.10-172.16.255.254
            }
        }
    }
    receive-redirects disable
    send-redirects disable
    source-validation strict
    syn-cookies enable
}
interfaces {
    ethernet eth0 {
        address 1.1.1.1/27
        description WAN
    }
    ethernet eth1 {
        address 172.16.0.1/16
        description "VPN Clients"
        firewall {
            in {
                name vpn-isolate
            }
        }
    }
}
nat {
    destination {
        rule 10 {
            description "Redirect .onion"
            destination {
                address 127.192.0.0/10
            }
            inbound-interface any
            protocol tcp
            source {
                address 172.16.0.10-172.16.255.254
            }
            translation {
                address 172.16.0.1
                port 9040
            }
        }
        rule 20 {
            description "Redirect to TOR"
            inbound-interface any
            protocol tcp
            source {
                address 172.16.0.10-172.16.255.254
            }
            translation {
                address 172.16.0.1
                port 9040
            }
        }
    }
}
service {
    ssh {
        listen-address 1.1.1.1
        port 22
    }
}
system {
    gateway-address 2.2.2.2
    host-name torgw.example.com
    login {
        user vyos {
            authentication {
                plaintext-password vyospass
            }
            level admin
        }
    }
    name-server 8.8.8.8
    name-server 4.2.2.2
    ntp {
        server 0.pool.ntp.org {
        }
        server 1.pool.ntp.org {
        }
        server 2.pool.ntp.org {
        }
    }
    options {
        reboot-on-panic true
    }
    package {
        repository community {
            components main
            distribution hydrogen
            url http://packages.vyos.net/vyos
        }
    }
    syslog {
        global {
            facility all {
                level notice
            }
            facility protocols {
                level debug
            }
        }
    }
    time-zone Etc/GMT
}
vpn {
    ipsec {
        ipsec-interfaces {
            interface eth0
        }
        nat-networks {
            allowed-network 0.0.0.0/0
        }
        nat-traversal enable
    }
    l2tp {
        remote-access {
            authentication {
                mode local
                local-users {
                    username user1 {
                        password userpass1
                    }
                }
            }
            client-ip-pool {
                start 172.16.0.10
                stop 172.16.255.254
            }
            dns-servers {
                server-1 172.16.0.1
            }
            ipsec-settings {
                authentication {
                    mode pre-shared-secret
                    pre-shared-secret supersecretpsk
                }
                ike-lifetime 3600
            }
            outside-address 1.1.1.1
            outside-nexthop 2.2.2.2
        }
    }
}
EOF


## ---------------------------------------------------------------
## VyOS post-boot script modifications
## ---------------------------------------------------------------
read -d '' vyospb << EOF
sudo /etc/init.d/tor start
sudo iptables -I FORWARD 1 -s 172.16.0.0/16 -d 172.16.0.1 -i l2tp+ -j ACCEPT
sudo iptables -I FORWARD 2 -s 172.16.0.0/16 ! -d 172.16.0.1 -i l2tp+ -j DROP
EOF


## ---------------------------------------------------------------
## Modified /etc/tor/torrc file
## ---------------------------------------------------------------
read -d '' torrc << EOF
SocksPort 9050
SocksListenAddress 172.16.0.1
VirtualAddrNetwork 10.192.0.0/10
AutomapHostsOnResolve 1
TransPort 9040
TransListenAddress 172.16.0.1
DNSPort 53
DNSListenAddress 172.16.0.1
EOF


## ---------------------------------------------------------------
## Modify VyOS config as per user input
## ---------------------------------------------------------------
vyosconf="${vyosconf//eth0/$wanint}"
vyosconf="${vyosconf//1\.1\.1\.1/$wanip}"
vyosconf="${vyosconf//$wanip\/27/$wanip$wannm}"
vyosconf="${vyosconf//2\.2\.2\.2/$wangw}"
vyosconf="${vyosconf//eth1/$lanint}"
vyosconf="${vyosconf//torgw\.example\.com/$domain}"
vyosconf="${vyosconf//8\.8\.8\.8/$ns1}"
vyosconf="${vyosconf//4\.2\.2\.2/$ns2}"
vyosconf="${vyosconf//user1/$user1}"
vyosconf="${vyosconf//userpass1/$userpass1}"
vyosconf="${vyosconf//supersecretpsk/$psk}"
vyosconf="${vyosconf//vyospass/$vyospass}"
if [ "$ssh" == "No" ]; then
    vyosconf="${vyosconf//listen\-address $wanip/listen-address 127.0.0.1}"
fi
vyosconf="${vyosconf//port\ 22/port $sshport}"


## ---------------------------------------------------------------
## Generate new vyos config and save to /tmp/torgw.config.boot
## ---------------------------------------------------------------
echo -e "$vyosconf" > /tmp/torgw.config


## ---------------------------------------------------------------
## Set up API session and load new config file into VyOS
## ---------------------------------------------------------------
session_env=$(cli-shell-api getSessionEnv $PPID)
eval $session_env
cli-shell-api setupSession
cli-shell-api loadFile /tmp/torgw.config
${vyatta_sbindir}/my_commit
${vyatta_sbindir}/vyatta-save-config.pl


## ---------------------------------------------------------------
## Inject post-boot script for iptables modifications
## ---------------------------------------------------------------
echo -e "$vyospb" >> /config/scripts/vyatta-postconfig-bootup.script


## ---------------------------------------------------------------
## Remove VyOS web interface
## ---------------------------------------------------------------
apt-get remove lighttpd -y
apt-get autoremove -y


## ---------------------------------------------------------------
## Install TOR binaries
## ---------------------------------------------------------------
echo -e "deb http://mirrors.kernel.org/debian squeeze main contrib non-free" >> /etc/apt/sources.list
echo -e "deb\thttp://deb.torproject.org/torproject.org squeeze main" >> /etc/apt/sources.list
gpg --keyserver keys.gnupg.net --recv 886DDD89
gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | apt-key add -
apt-get update
apt-get install deb.torproject.org-keyring -y
apt-get install tor -y


## ---------------------------------------------------------------
## Update /etc/tor/torrc file
## ---------------------------------------------------------------
echo -e "$torrc" > /etc/tor/torrc


## ---------------------------------------------------------------
## Set cron to auto-upgrade packages
## ---------------------------------------------------------------
echo -e "0 * * * *\troot\tapt-get upgrade -y" >> /etc/crontab
/etc/init.d/cron restart


## ---------------------------------------------------------------
## Remove those logs!
## ---------------------------------------------------------------
rm -rf /root/.bash_history && ln -s /dev/null /root/.bash_history
rm -rf /home/vyos/.bash_history && ln -s /dev/null /home/vyos/.bash_history
rm -rf /var/log/apt/history.log && ln -s /dev/null /var/log/apt/history.log
rm -rf /var/log/auth.log && ln -s /dev/null /var/log/auth.log
rm -rf /var/log/bootstrap.log && ln -s /dev/null /var/log/bootstrap.log
rm -rf /var/log/btmp && ln -s /dev/null /var/log/btmp
rm -rf /var/log/dmesg && ln -s /dev/null /var/log/dmesg
rm -rf /var/log/dpkg.log && ln -s /dev/null /var/log/dpkg.log
rm -rf /var/log/faillog && ln -s /dev/null /var/log/faillog
rm -rf /var/log/iptraf && ln -s /dev/null /var/log/iptraf
rm -rf /var/log/lastlog && ln -s /dev/null /var/log/lastlog
rm -rf /var/log/live.log && ln -s /dev/null /var/log/live.log
rm -rf /var/log/messages && ln -s /dev/null /var/log/messages
rm -rf /var/log/quagga && ln -s /dev/null /var/log/quagga
rm -rf /var/log/squid/cache.log && ln -s /dev/null /var/log/squid/cache.log
rm -rf /var/log/squid3/cache.log && ln -s /dev/null /var/log/squid3/cache.log
rm -rf /var/log/tor/log && ln -s /dev/null /var/log/tor/log
rm -rf /var/log/user && ln -s /dev/null /var/log/user
rm -rf /var/log/wtmp && ln -s /dev/null /var/log/twmp
rm -rf /var/log/vyatta/cfg-stderr.log && ln -s /dev/null /var/log/vyatta/cfg-stderr.log
rm -rf /var/log/vyatta/cfg-stdout.log && ln -s /dev/null /var/log/vyatta/cfg-stdout.log
rm -rf /var/log/vyatta/ipsec.log && ln -s /dev/null /var/log/vyatta/ipsec.log


## ---------------------------------------------------------------
## Start the engines!
## ---------------------------------------------------------------
echo "\n\nStarting the engines..."
/etc/init.d/tor restart
iptables -I FORWARD 1 -s 172.16.0.0/16 -d 172.16.0.1 -i l2tp+ -j ACCEPT
iptables -I FORWARD 2 -s 172.16.0.0/16 ! -d 172.16.0.1 -i l2tp+ -j DROP


## ---------------------------------------------------------------
## Inform user that install is complete and a reboot is required
## ---------------------------------------------------------------
echo -e "\n\n---------------------------------------------------------------"
echo -e "Congrats! Your new system is installed and ready to use after rebooting :)"
echo -e "Please remember to write down your L2TP pre-shared secret and credentials"
echo -e "---------------------------------------------------------------"
echo -e "VyOS Admin User:       vyos"
echo -e "VyOS Admin Password:   $vyospass"
echo -e "L2TP Pre-shared Key:   $psk"
echo -e "VPN User #1 Username:  $user1"
echo -e "VPN User #1 Password:  $userpass1"
echo ""