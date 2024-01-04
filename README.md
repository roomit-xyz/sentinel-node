# AUTOMATE INSTALL DVPN NODE


### SCOPE

```
1 vCPU
2 GB RAM
15 GB Disk
```

>OS Support x86 <=> Ubuntu 20.04 - 23.04 | Rocky Linux 8 - Fedora 38 39

>OS Support ARM <=> RaspBerryPI

For Temporary Only support 

- *Wireguard and x86_64 Ubuntu 22.04*
- *v2ray and x86_64 Ubuntu 22.04*

1 machine able running 2 service Sentinel DVPN (v2ray and wireguard)

### INSTALLATION

Clone Repository

```
wget -c https://raw.githubusercontent.com/roomit-xyz/sentinel-node/main/sentinel-node.sh
sudo su -
chmod +x sentinel-node.sh 
```

Execute
```
INSTALLATION
    ./sentinel-node.sh [options] [instruction]
    ./sentinel-node.sh [wireguard|v2ray|spawner] [install|remove|update]
Deploy Wireguard
    ./sentinel-node.sh wireguard install
Deploy V2Ray
    ./sentinel-node.sh v2ray install
Deploy spawner
    ./sentinel-node.sh spawner install
```
>> FOR UPDATE, MAKE SURE YOU HAVE MIGRATE FROM USER SENTINEL (OLD SCRIPT) WITH NEW USER SENTINEL-WIREGUARD,

Migration from old script with user sentinel to user sentinel-wireguard
```
cp -rf /app/mainnet/sentinel/ /app/mainnet/sentinel-wireguard
useradd -m -d /app/mainnet/sentinel-wireguard -s /bin/zsh sentinel-wireguard
chown sentinel-wireguard:sentinel-wireguard -R /app/mainnet/sentinel-wireguard
cd /app/mainnet/sentinel-wireguard
chown root:root -R .sentinelnode
setfacl -m u:sentinel-wireguard:rw -R .sentinelnode
usermod -aG docker sentinel-wireguard
```

After Migrated done, update your version to
```
chmod +x sentinel-node.sh 
./sentinel-node.sh wireguard update v0.7.1
```
