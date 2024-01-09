# Installation DVPN

visit : [https://github.com/roomit-xyz/sentinel-node](https://github.com/roomit-xyz/sentinel-node)

Last Version | 0.7.1

### Support

<pre><code>Wireguard and V2Ray
<strong>- Architecure 
</strong>  🖥️ X86_64
     - Ubuntu 22.04
     - Rocky Linux
     - Fedora Server

  💻 ARMv7 
     - RaspberryPI 4 Debian
     
  💻 ARM64/aarch64 
     - Ubuntu
</code></pre>

Script can detect Architecure and OS what we used, so with one command we can deploy service dvpn easily.&#x20;

### Installation Node

**How to Install Wireguard**\
We assume you have a VPS and can login to your VPS and running as root. example for install wireguard service Decentralize VPN Sentinel

```
sudo su -
wget -c https://raw.githubusercontent.com/roomit-xyz/sentinel-node/main/sentinel-node.sh
chmod +x sentinel-node.sh 
./sentinel-node.sh wireguard install
```

Then you will must fill data, following :&#x20;

* Moniker, Is your name node dvpn.
* Enable Wallet Import, If you fill with true, the script assumed you have a seed key before and want recovery your node. If youd fill false, the script assumed you have not a seed, then script will be generate new seed key and will show you after installation finished.

**How to install v2ray**

The step downloading same with the wireguard, but for execution we can use

```
./sentinel-node.sh v2ray install
```

### **Update Node**

**How to Upgrade Sentinel DVPN**

Assume existing version 0.7.0 and will upgrade to 0.7.1, you can chek version use api

```
curl https://localhost:7777/status    
```

Port 7777/tcp is you API Port, just adjust with your Port.

For Update Wireguard

```
./sentinel-node.sh wireguard update v.0.7.1
```

For Update v2ray

```
./sentinel-node.sh v2ray update v.0.7.1
```

### Remove Node

For Update Wireguard

```
./sentinel-node.sh wireguard remove 
```

For Update v2ray

```
./sentinel-node.sh v2ray remove
```

### Demo

![Demo](sentinel-demo.gif)
