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
git clone git@github.com:roomit-xyz/sentinel-node.git
cd sentinel-node
sudo su -
```

Execute
```
INSTALLATION
    ./sentinel-node.sh [options] [instruction]
    ./sentinel-node.sh [wireguard|v2ray|spawner] [install|remove]
Deploy Wireguard
    ./sentinel-node.sh wireguard install
Deploy V2Ray
    ./sentinel-node.sh v2ray install
Deploy spawner
    ./sentinel-node.sh spawner install
```