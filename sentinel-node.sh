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


function depedency:ubuntu(){
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
}


function depedency:raspbian(){
         sudo apt-get update
         sudo apt-get install ca-certificates curl gnupg
         sudo install -m 0755 -d /etc/apt/keyrings
         curl -fsSL https://download.docker.com/linux/raspbian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
         sudo chmod a+r /etc/apt/keyrings/docker.gpg

         echo \
         "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/raspbian \
         $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
         sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
         sudo apt-get update -y
         sudo apt-get install htop docker-ce docker-ce-cli python3-pip  containerd.io docker-buildx-plugin docker-compose-plugin jq ufw lsof acl telegraf bind9-dnsutils telnet unzip -y
}

function depedency:fedora:rocky(){
         echo "Detected Fedora or Rocky Linux. Installing jq and telegraf..."
         dnf -y install dnf-plugins-core
         dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
         dnf install -y jq telegraf curl docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin firewalld telnet unzip lsof acl
}


function images:dvpn:x86(){
    sudo -u ${USER_SENTINEL} bash -c 'docker pull ghcr.io/sentinel-official/dvpn-node:v0.7.0'
    sudo -u ${USER_SENTINEL} bash -c 'docker tag ghcr.io/sentinel-official/dvpn-node:v0.7.0 sentinel-dvpn-node'
}

function images:dvpn:arm(){
    sudo -u ${USER_SENTINEL} bash -c 'docker pull wajatmaka/sentinel-arm7-debian:0.7.0'
    sudo -u ${USER_SENTINEL} bash -c 'docker tag wajatmaka/sentinel-arm7-debian:0.7.0 sentinel-dvpn-node'
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
}

function attach() {
    if detect:ubuntu; then
        if [[ $(arch) == "arm"* ]]; then
            ARCH="arm"
            echo "Ubuntu Raspberry Pi architecture detected"
            depedency:raspbian;
            images:dvpn:arm;
        elif [[ $(arch) == "x86_64" ]]; then
            echo "Ubuntu x64 architecture detected"
            depedency:ubuntu;
            images:dvpn:x86;
        else
            echo "Unknown architecture"
            exit 1;
        fi
    elif detect:fedora:rocky; then
        arch=$(uname -m)
        echo "Fedora or Rocky Linux detected"
        echo "Architecture: $arch"
        depedency:fedora:rocky;
        images:dvpn:x86;
    else
        echo "Not running Debian, Ubuntu 18 to 23, Fedora, or Rocky Linux"
        return 1
    fi
}



function create:user(){
    mkdir -p ${HOME_NODE}
    groupadd admin
    useradd -m -d ${HOME_NODE} -G admin,docker -U  -s /bin/bash ${USER_SENTINEL}
}



function get:ip_public(){
    IP_PUBLIC=$(ip addr show $(ip route get 8.8.8.8 | grep -oP '(?<=dev )(\S+)') | grep inet | grep -v inet6 | awk '{print $2}' | awk -F"/" '{print $1}')
    IP_PRIVATE=$(echo "${IP_PUBLIC}" | awk -F'.' '$1 == 10 || $1 == 172 && $2 >= 16 && $2 <= 31 || $1 == 192 && $2 == 168 {print "true"}')

    if [[ "$IP_PRIVATE" == "true" ]]; then
        echo "Private IP address detected: $IP_PRIVATE"
        IP_PUBLIC=$(curl -s https://ifconfig.me)
    else
        echo "Public IP address: $IP_PUBLIC"
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

    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -x509 -sha256  -days 365 -nodes -keyout ${HOME_NODE}/.sentinelnode/tls.key -out ${HOME_NODE}/.sentinelnode/tls.crt -subj "/C=${COUNTRY}/ST=${STATE}/L=${CITY}/O=${ORGANIZATION}/OU=${ORGANIZATION_UNIT}/CN=."
    chown root:root ${HOME_NODE}/.sentinelnode

    [ -f ${HOME_NODE}/.sentinelnode/tls.key ] && echo "File CERT KEY Found" || echo "File CERT KEY Not Found" | exit 1;
    [ -f ${HOME_NODE}/.sentinelnode/tls.crt ] && echo "File CRT CERT Found" || echo "File CRT CERT Not Found" | exit 1;
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
    sed -i -e 's|^hourly_prices *=.*|hourly_prices = "18480ibc/31FEE1A2A9F9C01113F90BD0BBCCE8FD6BBB8585FAF109A2101827DD1D5B95B8,770ibc/A8C2D23A1E6F95DA4E48BA349667E322BD7A6C996D8A4AAE8BA72E190F3D1477,1871892ibc/B1C0DDB14F25279A2026BC8794E12B259F8BDA546A3C5132CCAEE4431CE36783,18897ibc/ED07A3391A112B175915CD8FAF43A2DA8E4790EDE12566649D0C2F97716B8518,13557200udvpn"|' ${HOME_NODE}/.sentinelnode/config.toml
    

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
fi

if [ -f ${HOME_NODE}/.sentinelnode/v2ray.toml ]
then
   GET_PORT_V2RAY=$(cat ${HOME_NODE}/.sentinelnode/v2ray.toml  | grep listen_port | awk -F"=" '{print $2}' | sed "s/ //")
fi

if [ "${KIND}" == "wireguard" ]
then
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
elif [ "${KIND}" == "v2ray" ]
then
    sudo -u ${USER_SENTINEL} bash -c 'docker run -d \
        --name sentinel-v2ray \
        --restart unless-stopped \
        --volume '${HOME_NODE}'/.sentinelnode:/root/.sentinelnode \
        --publish 7776:7776/tcp \
        --publish '${GET_PORT_V2RAY}':'${GET_PORT_V2RAY}'/tcp \
        sentinel-dvpn-node process start'
else
   echo spawner
fi
}


function wallet:creation(){
    if [ "${WALLET_IMPORT_ENABLE}" == "true" ]
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
    if [ "${WALLET_IMPORT_ENABLE}" == "false" ] || [ "${WALLET_IMPORT_ENABLE}" == "False" ] || [ "${WALLET_IMPORT_ENABLE}" == "FALSE" ]
    then
        # clear;
        echo ""
        echo -e "\e[106m   \e[49m\e[105m   \e[103m   \e[102m   \e[101m   \e[46m    \e[43m    \e[97m\e[44m\e[1m   SENTINEL NODE INFORMATIONS  \e[0m"
        echo "Save your Seeds and Dont Lose, Your seed is your asset"
        echo -e "${GREEN}SEED:${NOCOLOR}"
        SEED_KEY=$(cat /tmp/wallet.txt | grep -v "^*" | head -n1)
        echo -e "${RED}${SEED_KEY}${NOCOLOR}"
        echo ""
        NODE_ADDRESS=$( cat /tmp/wallet.txt | grep operator | awk '{print $2}')
        WALLET_ADDRESS=$( cat /tmp/wallet.txt | grep operator | awk '{print $3}')
        WALLET_NAME=$( cat /tmp/wallet.txt | grep operator | awk '{print $1}')
        echo -e "${GREEN}Your Node Address :${NOCOLOR} ${RED}${NODE_ADDRESS}${NOCOLOR}"
        echo -e "${GREEN}Your Wallet Address :${NOCOLOR} ${RED}${NODE_ADDRESS}${NOCOLOR}"
        echo -e "${GREEN}Your Wallet Address :${NOCOLOR} ${RED}${WALLET_NAME}${NOCOLOR}"
        echo -e "${GREEN}Your User           :${NOCOLOR} ${RED}${USER_SENTINEL}${NOCOLOR}"
        echo -e "${GREEN}Your Config Path    :${NOCOLOR} ${RED}${HOME_NODE}/.sentinel${NOCOLOR}"
        if [ ${KIND} == "wireguard" ]
        then
        echo -e "${GREEN}Your EndPoint Node  :${NOCOLOR} ${RED}https://"${IP_PUBLIC}":7777${NOCOLOR}"
        echo -e "${GREEN}Your Port Wireguard :${NOCOLOR} ${RED}${GET_PORT_WIREGUARD}${NOCOLOR}"
        else
        echo -e "${GREEN}Your EndPoint Node  :${NOCOLOR} ${RED}https:\/\/'"${IP_PUBLIC}"':7776${NOCOLOR}"
        echo -e "${GREEN}Your Port Wireguard :${NOCOLOR} ${RED}${GET_PORT_V2RAY}${NOCOLOR}"
        fi
        echo ""
        echo "Please send 50 dVPN for activation to your wallet ${WALLET_ADDRESS}"
        echo -e "restart service after sent balance with  command ${GREEN}docker restart sentinel-wireguard${NOCOLOR}"
    fi
}

function help(){
    # clear;
    format:color;
    echo ""
    echo -e "\e[106m   \e[49m\e[105m   \e[103m   \e[102m   \e[101m   \e[46m    \e[43m    \e[97m\e[44m\e[1m   SENTINEL NODE HELPER  \e[0m"
    echo -e "${LIGHTBLUE}INSTALLATION${NOCOLOR}"
    echo -e "${LIGHTGREEN}    ./sentinel-node.sh [options] [instruction]${NOCOLOR}"
    echo -e "${LIGHTGREEN}    ./sentinel-node.sh [wireguard|v2ray|spawner] [install|remove]${NOCOLOR}"
    echo -e "${LIGHTBLUE}Deploy Wireguard${NOCOLOR}"
    echo -e "${LIGHTGREEN}    ./sentinel-node.sh wireguard install${NOCOLOR}"
    echo -e "${LIGHTBLUE}Deploy V2Ray${NOCOLOR}"
    echo -e "${LIGHTGREEN}    ./sentinel-node.sh v2ray install${NOCOLOR}"
    echo -e "${LIGHTBLUE}Deploy spawner${NOCOLOR}"
    echo -e "${LIGHTGREEN}    ./sentinel-node.sh spawner install${NOCOLOR}"
}

function ask:config(){
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


function deploy(){
       ask:config;
       attach;
       create:user;
       setup:dvpn;
       setup:certificates;
       setup:config;
       wallet:creation;
       run:container;
       get:informations;
}

if [[ $(/usr/bin/id -u) -ne 0 ]]; then
    echo "Aborting: run as root user!"
    exit 1
fi



case "${KIND}" in
 wireguard|wg)
    case "${INSTRUCTION}" in
    install)
       deploy;
       ;;
    remove)
       remove:sentinel;
       ;;
    *)
       help;
       ;;
    esac
 ;;
 v2ray)
    case "${INSTRUCTION}" in
    install)
       deploy;
       ;;
    remove)
       remove:sentinel;
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



