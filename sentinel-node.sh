#!/bin/bash
#
#
# RoomIT Validator
# https://roomit.xyz
# If this script useful and you will visit cikarang indonesia, 
# Let's drink coffee and talk about blockchain
#



KIND=$1
INSTRUCTION=$2
IMAGES_VERSION="v0.7.1"

######## OS ENVIRONMENT ######
USER_SENTINEL="sentinel-${KIND}"
HOME_STAGE="/app/mainnet"
HOME_NODE="${HOME_STAGE}/${USER_SENTINEL}"


function format:color(){
    NOCOLOR='\033[0m'
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    ORANGE='\033[0;33m'
    BLUE='\033[0;34m'
    PURPLE='\033[0;35m'
    CYAN='\033[0;36m'
    LIGHTGRAY='\033[0;37m'
    DARKGRAY='\033[1;30m'
    LIGHTRED='\033[1;31m'
    LIGHTGREEN='\033[1;32m'
    YELLOW='\033[1;33m'
    LIGHTBLUE='\033[1;34m'
    LIGHTPURPLE='\033[1;35m'
    LIGHTCYAN='\033[1;36m'
    WHITE='\033[1;37m'
}



function detect:ubuntu() {
    version=$(lsb_release -rs)
    if [[ "$version" == "20."* || "$version" == "21."* || "$version" == "22."* || "$version" == "23."* ]]; then
        return 0  
    else
        return 1  
    fi
}


function detect:fedora:rocky() {
    if [[ -f "/etc/fedora-release" || -f "/etc/rocky-release" ]]; then
        return 0  
    else
        return 1 
    fi
}

function detect:raspbianpi() {
   raspbian_check=$(cat /etc/*-release | grep "ID=raspbian" | wc -l)
   if [ ${raspbian_check} == 1 ]
   then
        return 0  
    else
        return 1 
    fi
}

function check:command() {
    if command -v "$1" &> /dev/null; then
       echo "$1 is installed"
    else
       echo "$1 is not installed"
       exit 1
    fi
}

function depedency:ubuntu:x86_64(){
        apt-get update
        apt-get install -y jq telegraf curl ca-certificates curl gnupg  lsb-release -y
        mkdir -p /etc/apt/keyrings
        if [ -f /etc/apt/keyrings/docker.gpg ]
        then
           echo "GPG Available"
        else
           curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        fi
        if [ -f /etc/apt/sources.list.d/docker.list ]
        then
            echo Directory Already Created
         else
            echo \
            "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
            $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
         fi
         apt-get update -y
         apt-get install telegraf acl htop wget tcpdump jq python3-pip lsof  bind9-dnsutils telnet unzip docker-compose zsh docker-ce docker-ce-cli containerd.io docker-compose-plugin git ufw -y
         systemctl start docker
         echo "Check Tools Depedencies"
         for x in `echo "jq docker ufw setfacl telegraf"`
         do
             check:command "${x}"
         done

}


function depedency:raspbian:armv7(){
         apt-get update
         apt-get install ca-certificates curl gnupg -y
         install -m 0755 -d /etc/apt/keyrings
         curl -fsSL https://download.docker.com/linux/raspbian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
         chmod a+r /etc/apt/keyrings/docker.gpg

         echo \
         "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/raspbian \
         $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
         tee /etc/apt/sources.list.d/docker.list > /dev/null
         apt-get update -y
         apt-get install htop acl docker-ce docker-ce-cli python3-pip containerd.io docker-buildx-plugin docker-compose-plugin jq ufw lsof acl   telnet unzip -y
         systemctl start docker
         echo "Check Tools Depedencies"
         for x in `echo "jq docker ufw setfacl telegraf"`
         do
             check:command "${x}"
         done
}
function depedency:fedora:aarch64(){
         sudo dnf -y install dnf-plugins-core
         sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
         sudo dnf install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin jq curl telegraf acl lsof unzip telnet
         systemctl start docker
         echo "Check Tools Depedencies"
         for x in `echo "jq docker ufw setfacl telegraf"`
         do
             check:command "${x}"
         done
}


function depedency:ubuntu:aarch64(){
        # Add Docker's official GPG key:
        apt-get update 
        apt-get install ca-certificates curl gnupg -y
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/debian/gpg |  gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        chmod a+r /etc/apt/keyrings/docker.gpg

        # Add the repository to Apt sources:
        echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
        $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
        tee /etc/apt/sources.list.d/docker.list > /dev/null
        apt-get update
        apt-get install telegraf acl htop wget tcpdump jq python3-pip lsof  bind9-dnsutils telnet unzip docker-compose zsh docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin git ufw -y
        systemctl start docker
        for x in `echo "jq docker ufw setfacl telegraf"`
        do
             check:command "${x}"
        done
}

function depedency:fedora:rocky:x86_64(){
         echo "Detected Fedora or Rocky Linux. Installing jq and telegraf..."
         dnf -y install dnf-plugins-core
         dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
         dnf install -y jq telegraf curl docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin firewalld telnet unzip lsof acl
         systemctl start docker
         for x in `echo "jq docker ufw setfacl telegraf"`
         do
             check:command "${x}"
         done
}


function images:dvpn:x86_64(){
    if [ "${INSTRUCTION}" == "update" ]
    then
       sudo -u ${USER_SENTINEL} bash -c 'docker pull ghcr.io/sentinel-official/dvpn-node:'${VERSION_NEW}''
        check_images=$(docker images | grep "dvpn-node" | grep "${VERSION_NEW}" | wc -l)
       if [ ${check_images} == 0 ]
       then 
          echo "Images Can not Pulling"
          exit 1;
       fi
       sudo -u ${USER_SENTINEL} bash -c 'docker tag ghcr.io/sentinel-official/dvpn-node:'${VERSION_NEW}' sentinel-dvpn-node'
    else
       sudo -u ${USER_SENTINEL} bash -c 'docker pull ghcr.io/sentinel-official/dvpn-node:'${IMAGES_VERSION}''
       check_images=$(docker images | grep "dvpn-node" | grep "${IMAGES_VERSION}" | wc -l)
       if [ ${check_images} == 0 ]
       then 
          echo "Images Can not Pulling"
          exit 1;
       fi
       sudo -u ${USER_SENTINEL} bash -c 'docker tag ghcr.io/sentinel-official/dvpn-node:'${IMAGES_VERSION}' sentinel-dvpn-node'
    fi
}

function images:dvpn:armv7(){
    if [ "${INSTRUCTION}" == "update" ]
    then
       sudo -u ${USER_SENTINEL} bash -c 'docker pull wajatmaka/sentinel-arm7-debian:'${VERSION_NEW}''
       check_images=$(docker images | grep "sentinel-arm" | grep "${VERSION_NEW}" | wc -l)
       if [ ${check_images} == 0 ]
       then 
          echo "Images Can not Pulling"
          exit 1;
       fi
       sudo -u ${USER_SENTINEL} bash -c 'docker tag wajatmaka/sentinel-arm7-debian:'${VERSION_NEW}' sentinel-dvpn-node'
    else
       sudo -u ${USER_SENTINEL} bash -c 'docker pull wajatmaka/sentinel-arm7-debian:'${IMAGES_VERSION}''
       check_images=$(docker images | grep "sentinel-arm" | grep "${IMAGES_VERSION}" | wc -l)
       if [ ${check_images} == 0 ]
       then 
          echo "Images Can not Pulling"
          exit 1;
       fi
       sudo -u ${USER_SENTINEL} bash -c 'docker tag wajatmaka/sentinel-arm7-debian:'${IMAGES_VERSION}' sentinel-dvpn-node'
    fi
}

function images:dvpn:aarch64(){
    if [ "${INSTRUCTION}" == "update" ]
    then
       sudo -u ${USER_SENTINEL} bash -c 'docker pull wajatmaka/sentinel-aarch64-alpine:'${VERSION_NEW}''
       check_images=$(docker images | grep "sentinel-aarch" | grep "${VERSION_NEW}" | wc -l)
       if [ ${check_images} == 0 ]
       then 
          echo "Images Can not Pulling"
          exit 1;
       fi
       sudo -u ${USER_SENTINEL} bash -c 'docker tag wajatmaka/sentinel-aarch64-alpine:'${VERSION_NEW}' sentinel-dvpn-node'
    else
       sudo -u ${USER_SENTINEL} bash -c 'docker pull wajatmaka/sentinel-aarch64-alpine:'${IMAGES_VERSION}''
       check_images=$(docker images | grep "sentinel-aarch" | grep "${IMAGES_VERSION}" | wc -l)
       if [ ${check_images} == 0 ]
       then 
          echo "Images Can not Pulling"
          exit 1;
       fi
       sudo -u ${USER_SENTINEL} bash -c 'docker tag wajatmaka/sentinel-aarch64-alpine:'${IMAGES_VERSION}' sentinel-dvpn-node'
    fi
}

function setup:dvpn(){
    sudo -u ${USER_SENTINEL} bash -c 'docker run --rm \
                                        --volume '${HOME_NODE}'/.sentinelnode:/root/.sentinelnode \
                                        sentinel-dvpn-node process config init'
    [ -f ${HOME_NODE}/.sentinelnode/config.toml ] && echo "File Config Found" || echo "File Config Not Found" | exit 1;
    if [ "${KIND}" == "wireguard" ]
    then
      sudo -u ${USER_SENTINEL} bash -c 'docker run --rm \
                                          --volume '${HOME_NODE}'/.sentinelnode:/root/.sentinelnode \
                                          sentinel-dvpn-node process wireguard config init'
      [ -f ${HOME_NODE}/.sentinelnode/wireguard.toml ] && echo "File Config Found" || echo "File Config Not Found" | exit 1;
    else
      sudo -u ${USER_SENTINEL} bash -c 'docker run --rm \
                                          --volume '${HOME_NODE}'/.sentinelnode:/root/.sentinelnode \
                                          sentinel-dvpn-node process v2ray config init'                                  
      [ -f ${HOME_NODE}/.sentinelnode/v2ray.toml ] && echo "File Config Found" || echo "File Config Not Found" | exit 1;
    fi
    if [ -d ${HOME_NODE}/.sentinelnode ]
    then
      cp -rf ${HOME_NODE}/CERT/tls.key ${HOME_NODE}/.sentinelnode/tls.key 
      cp -rf ${HOME_NODE}/CERT/tls.crt ${HOME_NODE}/.sentinelnode/tls.crt 
    else
      echo "Sentinelnode diractory not found"
      exit 1;
    fi
}

function firewall(){
   echo "Setting Firewall"
   if [ "${FIREWALL}" == "ufw" ]
   then
      ufw allow 22/tcp
      if [ -f ${HOME_NODE}/.sentinelnode/wireguard.toml ]
      then
         WIREGUARD_PORT=$(cat ${HOME_NODE}/.sentinelnode/wireguard.toml | grep listen_port | awk -F"=" '{print $2}' | sed "s/ //")
         ufw allow ${WIREGUARD_PORT}/udp
         ufw allow 7777/tcp
      fi 
   
      if [ -f ${HOME_NODE}/.sentinelnode/v2ray.toml ]
      then
         V2RAY_PORT=$(cat ${HOME_NODE}/.sentinelnode/v2ray.toml | grep listen_port | awk -F"=" '{print $2}' | sed "s/ //")
         ufw allow ${V2RAYPORT}/udp
         ufw allow 7776/tcp
      fi
   else
     echo "For RPM Based Firewalld still not available"
   fi
}

function controller() {
    if detect:ubuntu; then
        FIREWALL="ufw"
        if [[ $(arch) == "arm"* ]]; then
            ARCH="arm"
            echo "Ubuntu Raspberry Pi architecture detected"
            if [ "${INSTRUCTION}" == "install" ]; then
               depedency:raspbian:armv7;
            fi
            images:dvpn:armv7;
        elif [[ $(arch) == "x86_64" ]]; then
            echo "Ubuntu x86_64 architecture detected"
            if [ "${INSTRUCTION}" == "install" ]; then
               depedency:ubuntu:x86_64;
            fi
            images:dvpn:x86_64;
        elif [[ $(arch) == "aarch64" ]] || [[ $(arch) == "arm64" ]]; then
            echo "Ubuntu arm64/aarch64 architecture detected"
            if [ "${INSTRUCTION}" == "install" ]; then
               depedency:ubuntu:aarch64;
            fi
            images:dvpn:aarch64;
        else
            echo "Sorry, Our script  support x86_64, armv7, arm64 only for Ubuntu Server"
            echo "Unknown architecture"
            exit 1;
        fi
    elif detect:raspbianpi; then
        FIREWALL="ufw"
        if [[ $(arch) == "arm"* ]]; then
            ARCH="arm"
            echo "Ubuntu Raspberry Pi architecture detected"
            if [ "${INSTRUCTION}" == "install" ]; then
                depedency:raspbian:armv7;
            fi
            images:dvpn:armv7;
        else
            echo "Sorry, Our script  support armv7 only for RaspberryPI OS 32bit"
            exit 1;
        fi
    elif detect:fedora:rocky; then
        FIREWALL="firewalld"
        if [[ $(arch) == "arm"* ]]; then
            echo "Sorry, Our script not support Fedora Server ARMv7, Please use raspberry PI OS FOr ARMv7"
            exit 1;
        elif [[ $(arch) == "x86_64" ]]; then
            arch=$(uname -m)
            echo "Fedora or Rocky Linux detected"
            echo "Architecture: $arch"
            if [ "${INSTRUCTION}" == "install" ]; then
               depedency:fedora:rocky:x86_64;
            fi
            images:dvpn:x86_64;
        elif [[ $(arch) == "aarch64" ]] || [[ $(arch) == "arm64" ]]; then
            echo "Fedora or Rocky ARM64 amd AARCH64"
            if [ "${INSTRUCTION}" == "install" ]; then
               depedency:fedora:aarch64;
            fi
            images:dvpn:aarch64;
        else
            echo "Unknown architecture"
            echo "Sorry, Our script  support x86_64 and arm64 only for Fedora OS"
            exit 1;
        fi
    else
        echo "Not running Debian, Ubuntu 18 to 23, Fedora, or Rocky Linux"
        return 1
    fi
}



function create:user(){
    mkdir -p ${HOME_NODE}
    check_admin_group=$(getent group admin | wc -l)
    if [ ${check_admin_group} == 0 ]
    then
        groupadd admin  2> /dev/null
    fi
    check_docker_group=$(getent group docker | wc -l)
    if [ ${check_docker_group} == 0 ]
    then
        groupadd docker 2> /dev/null
    fi
    useradd -m -d ${HOME_NODE} -G admin,sudo,docker  -s /bin/bash ${USER_SENTINEL} 2> /dev/null
    usermod -aG docker ${USER_SENTINEL} 2> /dev/null
}



function get:ip_public(){
    IP_PUBLIC=$(ip addr show $(ip route get 8.8.8.8 | grep -oP '(?<=dev )(\S+)') | grep inet | grep -v inet6 | awk '{print $2}' | awk -F"/" '{print $1}')
    IP_PRIVATE=$(echo "${IP_PUBLIC}" | awk -F'.' '$1 == 10 || $1 == 172 && $2 >= 16 && $2 <= 31 || $1 == 192 && $2 == 168 {print "true"}')

    if [[ "$IP_PRIVATE" == "true" ]]; then
        echo "Private IP address detected: $IP_PRIVATE"
        IP_PUBLIC=$(curl -s https://ifconfig.me)
    fi
}

function setup:certificates(){
    get:ip_public;
    response=$(curl -s http://ip-api.com/json/${IP_PUBLIC})
    COUNTRY=$(echo $response | jq -r ".countryCode")
    if [ -z "$COUNTRY" ]; then
        COUNTRY="Unknown"
    fi

    STATE=$(echo $response | jq -r ".country")
    if [ -z "$STATE" ]; then
        STATE="Unknown"
    fi

    CITY=$(echo $response | jq -r ".city")
    if [ -z "$CITY" ]; then
        CITY="Unknown"
    fi
    ORGANIZATION="Sentinel DVPN"
    ORGANIZATION_UNIT="IT Department"
    mkdir -p ${HOME_NODE}/CERT
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -x509 -sha256  -days 365 -nodes -keyout ${HOME_NODE}/CERT/tls.key -out ${HOME_NODE}/CERT/tls.crt -subj "/C=${COUNTRY}/ST=${STATE}/L=${CITY}/O=${ORGANIZATION}/OU=${ORGANIZATION_UNIT}/CN=."
    if [ $? -neq 0 ];then
      echo "Sorry, Certificate Creation Failed" 
      exit 1;
    else
      chown root:root ${HOME_NODE}/.sentinelnode
      [ -f ${HOME_NODE}/.sentinelnode/tls.key ] && echo "File CERT KEY Found" || echo "File CERT KEY Not Found" | exit 1;
      [ -f ${HOME_NODE}/.sentinelnode/tls.crt ] && echo "File CRT CERT Found" || echo "File CRT CERT Not Found" | exit 1;
    fi
}


function setup:config(){
    get:ip_public;
   
    echo "Change Keyring to test"
    sed -i 's/backend = "[^"]*"/backend = "test"/' ${HOME_NODE}/.sentinelnode/config.toml

  
    echo "Change RPC"
    sed -i 's/rpc_addresses = "[^"]*"/rpc_addresses = "https:\/\/rpc.dvpn.roomit.xyz:443"/' ${HOME_NODE}/.sentinelnode/config.toml

 
    echo "Change RPC Timeout"
    sed -i 's/rpc_query_timeout = [0-9]*/rpc_query_timeout = 15/' ${HOME_NODE}/.sentinelnode/config.toml
    
 
    echo "Change IP Public | ${IP_PUBLIC}"
    sed -i 's/ipv4_address = "[^"]*"/ipv4_address = "'${IP_PUBLIC}'"/' ${HOME_NODE}/.sentinelnode/config.toml


    echo "Change API"
    if [ "${KIND}" == "wireguard" ]
    then
      sed -i 's/listen_on = "[^"]*"/listen_on = "0.0.0.0:7777"/' ${HOME_NODE}/.sentinelnode/config.toml
    else
      sed -i 's/listen_on = "[^"]*"/listen_on = "0.0.0.0:7776"/' ${HOME_NODE}/.sentinelnode/config.toml
    fi

   
    echo "Change Remote URL"
    if [ "${KIND}" == "wireguard" ]
    then
       sed -i 's/remote_url = "[^"]*"/remote_url = "https:\/\/'"${IP_PUBLIC}"':7777"/' ${HOME_NODE}/.sentinelnode/config.toml
    else
        sed -i 's/remote_url = "[^"]*"/remote_url = "https:\/\/'"${IP_PUBLIC}"':7776"/' ${HOME_NODE}/.sentinelnode/config.toml
    fi

 
    echo "Set Moniker Node | ${MONIKER}"
    sed -i 's/moniker = "[^"]*"/moniker = "'"${MONIKER}"'"/' ${HOME_NODE}/.sentinelnode/config.toml

    echo "Update GAS"
    sed -i -e 's|^gigabyte_prices *=.*|gigabyte_prices = "52573ibc/31FEE1A2A9F9C01113F90BD0BBCCE8FD6BBB8585FAF109A2101827DD1D5B95B8,9204ibc/A8C2D23A1E6F95DA4E48BA349667E322BD7A6C996D8A4AAE8BA72E190F3D1477,1180852ibc/B1C0DDB14F25279A2026BC8794E12B259F8BDA546A3C5132CCAEE4431CE36783,122740ibc/ED07A3391A112B175915CD8FAF43A2DA8E4790EDE12566649D0C2F97716B8518,15342624udvpn"|'  ${HOME_NODE}/.sentinelnode/config.toml 
    sed -i -e 's|^hourly_prices *=.*|hourly_prices = "18480ibc/31FEE1A2A9F9C01113F90BD0BBCCE8FD6BBB8585FAF109A2101827DD1D5B95B8,770ibc/A8C2D23A1E6F95DA4E48BA349667E322BD7A6C996D8A4AAE8BA72E190F3D1477,1871892ibc/B1C0DDB14F25279A2026BC8794E12B259F8BDA546A3C5132CCAEE4431CE36783,18897ibc/ED07A3391A112B175915CD8FAF43A2DA8E4790EDE12566649D0C2F97716B8518,4160000udvpn"|' ${HOME_NODE}/.sentinelnode/config.toml
    

    echo "Update RPC"
    sed -i -e 's|^gigabyte_prices *=.*|gigabyte_prices = "52573ibc/31FEE1A2A9F9C01113F90BD0BBCCE8FD6BBB8585FAF109A2101827DD1D5B95B8,9204ibc/A8C2D23A1E6F95DA4E48BA349667E322BD7A6C996D8A4AAE8BA72E190F3D1477,1180852ibc/B1C0DDB14F25279A2026BC8794E12B259F8BDA546A3C5132CCAEE4431CE36783,122740ibc/ED07A3391A112B175915CD8FAF43A2DA8E4790EDE12566649D0C2F97716B8518,15342624udvpn"|'  ${HOME_NODE}/.sentinelnode/config.toml 
    
    echo "Update Kind Service"
    sed -i 's/type = "[^"]*"/type = "'"${KIND}"'"/' ${HOME_NODE}/.sentinelnode/config.toml

    echo "Update Handshake"
    if [ "${KIND}" == "wireguard" ]
    then
       sed -i 's/enable = [^"]*/enable = true/' ${HOME_NODE}/.sentinelnode/config.toml
    else
       sed -i 's/enable = [^"]*/enable = false/' ${HOME_NODE}/.sentinelnode/config.toml
    fi

    echo "Change Owner"
    setfacl -m u:${USER_SENTINEL}:rwx -R ${HOME_NODE}/.sentinelnode

}

function run:container(){
if [ -f ${HOME_NODE}/.sentinelnode/wireguard.toml ]
then
   GET_PORT_WIREGUARD=$(cat ${HOME_NODE}/.sentinelnode/wireguard.toml  | grep listen_port | awk -F"=" '{print $2}' | sed "s/ //")
   CHECK_PORT=$(ss -tulpn | egrep "7777|${GET_PORT_WIREGUARD}" | wc -l)
fi

if [ -f ${HOME_NODE}/.sentinelnode/v2ray.toml ]
then
   GET_PORT_V2RAY=$(cat ${HOME_NODE}/.sentinelnode/v2ray.toml  | grep listen_port | awk -F"=" '{print $2}' | sed "s/ //")
   CHECK_PORT=$(ss -tulpn | egrep "7776|${GET_PORT_V2RAY}" | wc -l)
fi



if [ ${CHECK_PORT} -ne 0 ]
then
   echo "Creating Container Cancelling" 
   echo "due we have issue about conflicting the ports"
   echo "please check port existing 7777/tcp|7776/tcp|${GET_PORT_WIREGUARD}/udp|${GET_PORT_V2RAY}/tcp in your server already listened"
   exit 1
fi

if [ "${KIND}" == "wireguard" ]
then
    if [ "${ARCH}" == "arm" ]
    then
    wget -c https://gist.githubusercontent.com/roomit-xyz/6f1344adffe54b0e4f20ff14ae0818b7/raw/938368b2474c4a29d2fb61944a89179c10d120a4/default.json -O ${HOME_NODE}/default.json
    chown ${USER_SENTINEL}:${USER_SENTINEL} ${HOME_NODE}/default.json
    sudo -u ${USER_SENTINEL} bash -c 'docker run -d \
        --name sentinel-wireguard \
        --restart unless-stopped \
        --security-opt "seccomp='${HOME_NODE}'/default.json" \
        --volume '${HOME_NODE}'/.sentinelnode:/root/.sentinelnode \
        --volume /lib/modules:/lib/modules \
        --cap-drop ALL \
        --cap-add NET_ADMIN \
        --cap-add NET_BIND_SERVICE \
        --cap-add NET_RAW \
        --cap-add SYS_MODULE \
        --sysctl net.ipv4.ip_forward=1 \
        --sysctl net.ipv6.conf.all.disable_ipv6=0 \
        --sysctl net.ipv6.conf.all.forwarding=1 \
        --sysctl net.ipv6.conf.default.forwarding=1 \
        --publish '${GET_PORT_WIREGUARD}':'${GET_PORT_WIREGUARD}'/udp \
        --publish 7777:7777/tcp \
        sentinel-dvpn-node process start'
    else
    sudo -u ${USER_SENTINEL} bash -c 'docker run -d \
        --name sentinel-wireguard \
        --restart unless-stopped \
        --volume '${HOME_NODE}'/.sentinelnode:/root/.sentinelnode \
        --volume /lib/modules:/lib/modules \
        --cap-drop ALL \
        --cap-add NET_ADMIN \
        --cap-add NET_BIND_SERVICE \
        --cap-add NET_RAW \
        --cap-add SYS_MODULE \
        --sysctl net.ipv4.ip_forward=1 \
        --sysctl net.ipv6.conf.all.disable_ipv6=0 \
        --sysctl net.ipv6.conf.all.forwarding=1 \
        --sysctl net.ipv6.conf.default.forwarding=1 \
        --publish '${GET_PORT_WIREGUARD}':'${GET_PORT_WIREGUARD}'/udp \
        --publish 7777:7777/tcp \
        sentinel-dvpn-node process start'
    fi
elif [ "${KIND}" == "v2ray" ]
then
   if [ "${ARCH}" == "arm" ]
   then
       wget -c https://gist.githubusercontent.com/roomit-xyz/6f1344adffe54b0e4f20ff14ae0818b7/raw/938368b2474c4a29d2fb61944a89179c10d120a4/default.json -O ${HOME_NODE}/default.json
       chown ${USER_SENTINEL}:${USER_SENTINEL} ${HOME_NODE}/default.json
       sudo -u ${USER_SENTINEL} bash -c 'docker run -d \
        --name sentinel-v2ray \
        --security-opt "seccomp='${HOME_NODE}'/default.json" \
        --restart unless-stopped \
        --volume '${HOME_NODE}'/.sentinelnode:/root/.sentinelnode \
        --publish 7776:7776/tcp \
        --publish '${GET_PORT_V2RAY}':'${GET_PORT_V2RAY}'/tcp \
        sentinel-dvpn-node process start'
   else
       sudo -u ${USER_SENTINEL} bash -c 'docker run -d \
        --name sentinel-v2ray \
        --restart unless-stopped \
        --volume '${HOME_NODE}'/.sentinelnode:/root/.sentinelnode \
        --publish 7776:7776/tcp \
        --publish '${GET_PORT_V2RAY}':'${GET_PORT_V2RAY}'/tcp \
        sentinel-dvpn-node process start'
  fi
else
   echo spawner
fi
}


function wallet:creation(){
    if [ "${WALLET_IMPORT_ENABLE}" == "true" ] || [ "${WALLET_IMPORT_ENABLE}" == "yes" ] || [ "${WALLET_IMPORT_ENABLE}" == "y" ] || [ "${WALLET_IMPORT_ENABLE}" == "Y" ] || [ "${WALLET_IMPORT_ENABLE}" == "True" ] || [ "${WALLET_IMPORT_ENABLE}" == "Yes" ]
    then
        sudo -u ${USER_SENTINEL} bash -c 'docker run --rm \
                                            --interactive \
                                            --tty \
                                            --volume '${HOME_NODE}'/.sentinelnode:/root/.sentinelnode \
                                            sentinel-dvpn-node process keys add  --recover'
    else
        sudo -u ${USER_SENTINEL} bash -c 'docker run --rm \
                                            --interactive \
                                            --tty \
                                            --volume '${HOME_NODE}'/.sentinelnode:/root/.sentinelnode \
                                            sentinel-dvpn-node process keys add' > /tmp/wallet.txt
    fi
}


function get:informations(){
    function get:informations:messages(){
        clear;
        format:color;
        echo ""
        echo -e "\e[106m   \e[49m\e[105m   \e[103m   \e[102m   \e[101m   \e[46m    \e[43m    \e[97m\e[44m\e[1m   SENTINEL NODE INFORMATIONS  \e[0m"
        if [ "${WALLET_IMPORT_ENABLE}" == "false" ] || [ "${WALLET_IMPORT_ENABLE}" == "False" ] || [ "${WALLET_IMPORT_ENABLE}" == "FALSE" ]
        then
        echo "Save your Seeds and Dont Lose, Your seed is your asset"
        echo -e "${GREEN}SEED:${NOCOLOR}"
        SEED_KEY=$(cat /tmp/wallet.txt | grep -v "^*" | head -n1)
        echo -e "${RED}${SEED_KEY}${NOCOLOR}"
        fi
        echo ""
        NODE_ADDRESS=$( cat /tmp/wallet.txt | grep operator | awk '{print $2}')
        WALLET_ADDRESS=$( cat /tmp/wallet.txt | grep operator | awk '{print $3}')
        WALLET_NAME=$( cat /tmp/wallet.txt | grep operator | awk '{print $1}')
        echo -e "${GREEN}Your Node Address   :${NOCOLOR} ${RED}${NODE_ADDRESS}${NOCOLOR}"
        echo -e "${GREEN}Your Wallet Name    :${NOCOLOR} ${RED}${WALLET_NAME}${NOCOLOR}"
        echo -e "${GREEN}Your Wallet Address :${NOCOLOR} ${RED}${WALLET_ADDRESS}${NOCOLOR}"
        echo -e "${GREEN}Your User           :${NOCOLOR} ${RED}${USER_SENTINEL}${NOCOLOR}"
        echo -e "${GREEN}Your Config Path    :${NOCOLOR} ${RED}${HOME_NODE}/.sentinel${NOCOLOR}"
        if [ ${KIND} == "wireguard" ]
        then
        echo -e "${GREEN}Your EndPoint Node  :${NOCOLOR} ${RED}https://"${IP_PUBLIC}":7777${NOCOLOR}"
        echo -e "${GREEN}Your Port Wireguard :${NOCOLOR} ${RED}${GET_PORT_WIREGUARD}${NOCOLOR}"
        else
        echo -e "${GREEN}Your EndPoint Node  :${NOCOLOR} ${RED}https://"${IP_PUBLIC}":7776${NOCOLOR}"
        echo -e "${GREEN}Your Port Wireguard :${NOCOLOR} ${RED}${GET_PORT_V2RAY}${NOCOLOR}"
        fi
        echo ""
        echo "Please send 50 dVPN for activation to your wallet ${WALLET_ADDRESS}"
        echo -e "restart service after sent balance with  command ${GREEN}docker restart sentinel-wireguard${NOCOLOR}"
    }
    if [ "${WALLET_IMPORT_ENABLE}" == "false" ] || [ "${WALLET_IMPORT_ENABLE}" == "False" ] || [ "${WALLET_IMPORT_ENABLE}" == "FALSE" ]
    then
        get:informations:messages;
    else
        sudo -u ${USER_SENTINEL} bash -c 'docker run  \
                                            --interactive \
                                            --tty \
                                            sentinel-dvpn-node process keys list' > /tmp/wallet.txt
       get:informations:messages;
    fi
}

function help(){
    # clear;
    format:color;
    echo ""
    echo -e "\e[106m   \e[49m\e[105m   \e[103m   \e[102m   \e[101m   \e[46m    \e[43m    \e[97m\e[44m\e[1m   SENTINEL NODE HELPER  \e[0m"
    echo -e "${LIGHTBLUE}INSTALLATION${NOCOLOR}"
    echo -e "${LIGHTGREEN}    ./sentinel-node.sh [options] [instruction]${NOCOLOR}"
    echo -e "${LIGHTGREEN}    ./sentinel-node.sh [wireguard|v2ray|spawner] [install|remove|update]${NOCOLOR}"
    echo -e "${LIGHTBLUE}Deploy Wireguard${NOCOLOR}"
    echo -e "${LIGHTGREEN}    ./sentinel-node.sh wireguard install${NOCOLOR}"
    echo -e "${LIGHTBLUE}Update Wireguard${NOCOLOR}"
    echo -e "${LIGHTGREEN}    ./sentinel-node.sh wireguard update ${IMAGES_VERSION}${NOCOLOR}"
    echo -e "${LIGHTBLUE}Deploy V2Ray${NOCOLOR}"
    echo -e "${LIGHTGREEN}    ./sentinel-node.sh v2ray install${NOCOLOR}"
    echo -e "${LIGHTBLUE}Update V2Ray${NOCOLOR}"
    echo -e "${LIGHTGREEN}    ./sentinel-node.sh v2ray update ${IMAGES_VERSION}${NOCOLOR}"
    echo -e "${LIGHTBLUE}Deploy spawner${NOCOLOR}"
    echo -e "${LIGHTGREEN}    ./sentinel-node.sh spawner install${NOCOLOR}"
}

function ask:config(){
    clear;
    format:color;
    echo ""
    echo -e "\e[106m   \e[49m\e[105m   \e[103m   \e[102m   \e[101m   \e[46m    \e[43m    \e[97m\e[44m\e[1m   FORM REGISTRATION SENTINEL  \e[0m"

    read -p "Enter Moniker (default: DVPN SENTINEL): " MONIKER_INPUT
    MONIKER=${MONIKER_INPUT:-"DVPN SENTINEL"}

    read -p "Enable wallet import? (true/false, default: false): " WALLET_IMPORT_ENABLE_INPUT
    WALLET_IMPORT_ENABLE=${WALLET_IMPORT_ENABLE_INPUT:-"false"}
}


function remove:sentinel(){
    read -p "We Assume You Have a Backup! Type everthing for continue " REMOVE_SENTINEL
    if [ "${KIND}" == "wireguard" ]
    then
       docker stop sentinel-wireguard
       docker rm sentinel-wireguard
    fi
    if [ "${KIND}" == "v2ray" ]
    then
       docker stop sentinel-v2ray
       docker rm sentinel-v2ray
    fi
    if [ "${KIND}" == "spawner" ]
    then
       docker stop sentinel-spawner
       docker rm sentinel-spawner
    fi
    rm -rf ${HOME_NODE}/.sentinelnode
    userdel ${USER_SENTINEL}
    rm -rf ${HOME_STAGE}/${USER_SENTINEL}
    echo -e "${RED}Remove Sentinel Successfully${NOCOLOR}"
}

function update:sentinel(){
     if [ "${KIND}" == "wireguard" ]
    then
       docker stop sentinel-wireguard
       docker rm sentinel-wireguard
    fi
    if [ "${KIND}" == "v2ray" ]
    then
       docker stop sentinel-v2ray
       docker rm sentinel-v2ray
    fi
    if [ "${KIND}" == "spawner" ]
    then
       docker stop sentinel-spawner
       docker rm sentinel-spawner
    fi
    controller;
    run:container
}

function deploy(){
       ask:config;
       [ $? != 0 ] && exit 1;
       create:user;
       [ $? != 0 ] && exit 1;
       controller;
       [ $? != 0 ] && exit 1;
       setup:certificates;
       [ $? != 0 ] && exit 1;
       setup:dvpn;
       [ $? != 0 ] && exit 1;
       setup:config;
       [ $? != 0 ] && exit 1;
       wallet:creation;
       [ $? != 0 ] && exit 1;
       run:container;
       [ $? != 0 ] && exit 1;
       firewall;
       [ $? != 0 ] && exit 1;
       get:informations;
       [ $? != 0 ] && exit 1;
}

if [[ $(/usr/bin/id -u) -ne 0 ]]; then
    echo "Aborting: run as root user!"
    exit 1
fi



case "${KIND}" in
 wireguard|v2ray)
    case "${INSTRUCTION}" in
    install)
       deploy;
       ;;
    remove)
       remove:sentinel;
       ;;
    update)
       VERSION_NEW=$3
       if [ -z ${VERSION_NEW} ]
       then
          echo "Please Provide new version example ${IMAGES_VERSION} or 0.7.1"
          exit 1
       fi
       update:sentinel;
       ;;
    *)
       help;
       ;;
    esac
 ;;
 spawner)
    echo "Ups Sorry, under testing"
 ;;
 *)
    help;
 ;;
esac



