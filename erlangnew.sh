#!/bin/bash
# Automatic interactive installer for mtproto proxy
# Modified to use fork with domain restriction support
# Original: https://github.com/seriyps/mtproto_proxy
# Fork: https://github.com/hesiadmin-maker/mtproto_proxy
#
# Supported OS:
# - Ubuntu 26.xx
# - Ubuntu 24.xx
# - Ubuntu 23.xx
# - Ubuntu 22.xx
# - Ubuntu 20.xx
# - Debian 11 bullseye

RED='\033[0;31m'
GR='\033[0;32m'
YE='\033[0;33m'
NC='\033[0m'
WORKDIR=`pwd`
SRC_DIR=mtproto_proxy
SELF="$0"

# ============================================================
# CHANGE THIS to your fork URL
# ============================================================
FORK_URL="https://github.com/hesiadmin-maker/mtproto_proxy/archive/refs/heads/master.tar.gz"

info() {
    echo -e "${GR}INFO${NC}: $1"
}
warn() {
    echo -e "${YE}WARNING${NC}: $1"
}
error() {
    echo -e "${RED}ERROR${NC}: $1" 1>&2
    exit 1
}

usage() {
    echo "MTProto proxy installer. Install proxy:
    ${SELF} -p <port> -s <secret> -t <ad tag> -a dd -a tls -d <fake-tls domain>

    Upgrade code to the latest version and restart, keeping config unchanged:
    ${SELF} upgrade

    Interactively generate new config and reload proxy settings:
    ${SELF} reconfigure -p <port> -s <secret> -t <ad tag> -a dd -a tls -d <fake-tls domain>

    Reload proxy settings after manual changes in config/prod-sys.cnfig:
    ${SELF} reload
    "
}

to_hex() {
    od -A n -t x1 -w128 | sed 's/ //g'
}

case "$1" in
    reconfigure|reload|upgrade|install)
        CMD="$1"
        shift
        ;;
    *)
        CMD="install"
esac

PORT=${MTP_PORT:-""}
SECRET=${MTP_SECRET:-""}
TAG=${MTP_TAG:-""}
DD_ONLY=${MTP_DD_ONLY:-""}
TLS_ONLY=${MTP_TLS_ONLY:-""}
TLS_DOMAIN=${MTP_TLS_DOMAIN:-""}
ALLOWED_TLS_DOMAINS=${MTP_ALLOWED_TLS_DOMAINS:-""}  # NEW: comma-separated list of allowed domains

# check command line options
while getopts "p:s:t:a:d:l:h" o; do
    case "${o}" in
        p)
            PORT=${OPTARG}
            ;;
        s)
            SECRET=${OPTARG}
            ;;
        t)
            TAG=${OPTARG}
            ;;
        a)
            case "${OPTARG}" in
                "dd")
                    DD_ONLY="y"
                    ;;
                "tls")
                    TLS_ONLY="y"
                    ;;
                *)
                    error "Invalid -a value: '${OPTARG}'"
            esac
            ;;
        d)
            TLS_DOMAIN=${OPTARG}
            ;;
        l)
            # NEW: List of allowed domains (comma-separated)
            ALLOWED_TLS_DOMAINS=${OPTARG}
            ;;
        h)
            usage
            exit 0
    esac
done

echo "Interactive MTProto proxy installer (with domain restriction support)."
echo "You can make the process fully automated by calling this script as 'echo \"y\ny\ny\ny\ny\ny\" | $0'."
echo "Try $0 -h for more options."
echo ""
echo "Fork URL: ${FORK_URL}"

set -e
source /etc/os-release
info "Detected OS is ${ID} ${VERSION_ID}"

do_configure_os() {
    # We need at least 'make' 'sed' 'diff' 'od' 'install' 'tar' 'base64' 'awk'
    case "${ID}-${VERSION_ID}" in
        ubuntu-20.*)
            info "Installing Erlang for Ubuntu 20.04"
            sudo apt update
            sudo apt install -y wget gnupg2 curl build-essential libncurses5-dev libssl-dev
            
            # روش جایگزین: کامپایل از سورس
            info "Downloading and compiling Erlang from source (this will take a few minutes)"
            cd /tmp
            wget https://github.com/erlang/otp/releases/download/OTP-25.3.2/otp_src_25.3.2.tar.gz
            tar -xzf otp_src_25.3.2.tar.gz
            cd otp_src_25.3.2
            ./configure
            make -j$(nproc)
            sudo make install
            cd /tmp
            
            sudo apt install -y make sed diffutils tar
            cd $WORKDIR
            ;;
        ubuntu-22.*|ubuntu-23.*|ubuntu-24.*|ubuntu-26.*|debian-11)
            info "Installing required APT packages"
            sudo apt update
            sudo apt install -y erlang-nox erlang-dev make sed diffutils tar
            ;;
        centos-7)
            info "Installing extra repositories"
            sudo yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm \
                wget \
                https://packages.erlang-solutions.com/erlang-solutions-1.0-1.noarch.rpm
            info "Installing required RPM packages"
            sudo yum install chrony erlang-compiler erlang-erts erlang-kernel erlang-stdlib erlang-syntax_tools \
                erlang-crypto erlang-inets erlang-sasl erlang-ssl
            ;;
        *)
            error "Your OS ${ID} ${VERSION_ID} is not supported!"
    esac

    info "Making sure clock synchronization is enabled"
    if [ `systemctl is-active ntp` = "active" ]; then
        info "Replacing ntpd with systemd-timesyncd"
        systemctl disable ntp
        systemctl stop ntp
    fi
    sudo timedatectl set-ntp on
    info "Current time: `date`"
}

do_get_source() {
    info "Downloading proxy source code from your fork"
    curl -L "${FORK_URL}" -o mtproto_proxy.tar.gz
    info "Unpacking source code"
    tar -xaf mtproto_proxy.tar.gz
    
    # Handle different folder naming (GitHub may use branch name)
    EXTRACTED_DIR=$(tar -tzf mtproto_proxy.tar.gz | head -1 | cut -f1 -d"/")
    mv -T --backup=t "$EXTRACTED_DIR" $SRC_DIR
    
    case "${ID}-${VERSION_ID}" in
        ubuntu-20.*|ubuntu-22.*)
            info "Downgrade rebar3 to 3.23.0"
            curl -L -o $SRC_DIR/rebar3 https://github.com/erlang/rebar3/releases/download/3.23.0/rebar3
            chmod +x $SRC_DIR/rebar3
            ;;
        *)
            ;;
    esac
}

# cd mtproto_proxy/
do_build_config() {
    info "Interactively generating config-file"
    # So, we ask for port/secret/ad_tag/protocols only if they are not specified via
    # command-line or env vars
    if [ -z "${PORT}" ]; then
        PORT=443
        read -p "Use default proxy port 443? [y/n] " yn
        case $yn in
            [Nn]*)
                read -p "Enter port number: 1-32000: " PORT
                ;;
            *)
                info "Using default port 443"
                ;;
        esac
    fi

    if [ "${ID}" = "centos" -a "`sudo firewall-cmd --state 2>&1`" = "running" ]; then
        read -p "Should I configure firewall? 'd' to disable firewall completely 'n' if you will setup firewall by yourself [y/n/d] " yn
        case $yn in
            [Yy]*)
                info "Opening ${PORT} port"
                sudo firewall-cmd --zone=public --add-port=${PORT}/tcp --permanent
                sudo firewall-cmd --reload
                ;;
            [Dd]*)
                warn "Stopping firewalld"
                sudo systemctl stop firewalld
                sudo systemctl disable firewalld
                ;;
            *)
                warn "Please make sure proxy port ${PORT} is open on firewall! Use smth like: firewall-cmd --zone=public --add-port=${PORT}/tcp --permanent firewall-cmd --reload"
                ;;
        esac
    fi

    if [ -z "${SECRET}" ]; then
        SECRET=`head -c 16 /dev/urandom | to_hex`
        read -p "Use randomly generated secret '${SECRET}'? [y/n] " yn
        case $yn in
            [Nn]*)
                read -p "Enter your secret: 16 hex characters 0-9a-f: " SECRET
                ;;
            *)
                info "Using random secret ${SECRET}"
                ;;
        esac
    fi

    if [ -z "${TAG}" ]; then
        TAG="8b081275ec12abd306faeb2f13efbdcb"
        read -p "Use empty @MTProxybot AD TAG? Answer 'n' to set AD TAG [y/n] " yn
        case $yn in
            [Nn]*)
                read -p "Enter your ad tag from @MTProxybot: " TAG
                ;;
            *)
                info "Using no AD TAG"
        esac
    fi

    if [ -z "${DD_ONLY}" ]; then
        DD_ONLY="y"
        read -p "Enable dd-only mode? (recommended) [y/n] " yn
        case $yn in
            [Nn]*)
                DD_ONLY=""
                warn "dd-only mode disabled"
                ;;
            *)
                info "Using dd-only mode"
        esac
    fi

    if [ -z "${TLS_ONLY}" ]; then
        TLS_ONLY="y"
        read -p "Enable TLS-only mode? (recommended) [y/n] " yn
        case $yn in
            [Nn]*)
                TLS_ONLY=""
                warn "TLS-only mode disabled"
                ;;
            *)
                info "Using TLS-only mode"
        esac
    fi

    if [ -z "${TLS_DOMAIN}" -a \( -n "${TLS_ONLY}" -o -z "${DD_ONLY}" \) ]; then
        # If tls_domain is not set and fake-tls is enabled, ask for domain
        TLS_DOMAIN="s3.amazonaws.com"
        read -p "Use '${TLS_DOMAIN}' as domain name for fake-tls? Answer 'n' to change to another [y/n] " yn
        case $yn in
            [Nn]*)
                read -p "Enter domain name: " TLS_DOMAIN
                ;;
            *)
                ;;
        esac
        info "Using '${TLS_DOMAIN}' for fake-TLS SNI"
    fi

    # NEW: Ask for allowed domains (for domain restriction)
    if [ -z "${ALLOWED_TLS_DOMAINS}" -a \( -n "${TLS_ONLY}" -o -z "${DD_ONLY}" \) ]; then
        echo ""
        info "Domain Restriction Configuration"
        echo "You can restrict which SNI domains clients are allowed to use."
        echo "By default, only the fake-TLS domain you specified above is allowed."
        echo "Leave empty to allow only the specified domain, or enter a comma-separated list."
        echo "Supports wildcards like: *.amazonaws.com"
        echo ""
        read -p "Allowed domains (comma-separated, default: only '${TLS_DOMAIN}'): " ALLOWED_TLS_DOMAINS
        
        if [ -z "${ALLOWED_TLS_DOMAINS}" ]; then
            ALLOWED_TLS_DOMAINS="${TLS_DOMAIN}"
        fi
        info "Allowed domains: ${ALLOWED_TLS_DOMAINS}"
    fi

    PROTO_ARG=""
    if [ -n "${DD_ONLY}" -a -n "${TLS_ONLY}" ]; then
        PROTO_ARG='{allowed_protocols, [mtp_fake_tls,mtp_secure]},'
    elif [ -n "${DD_ONLY}" ]; then
        PROTO_ARG='{allowed_protocols, [mtp_secure]},'
    elif [ -n "${TLS_ONLY}" ]; then
        PROTO_ARG='{allowed_protocols, [mtp_fake_tls]},'
    fi

    FRONTING_ARG=""
    if [ -n "${TLS_DOMAIN}" ]; then
        FRONTING_ARG='{domain_fronting, "'${TLS_DOMAIN}':443"},'
    fi

    # NEW: Allowed domains argument
    ALLOWED_DOMAINS_ARG=""
    if [ -n "${ALLOWED_TLS_DOMAINS}" ]; then
        # Convert comma-separated to Erlang list of binaries
        IFS=',' read -ra DOMAINS <<< "${ALLOWED_TLS_DOMAINS}"
        DOMAIN_LIST=""
        for domain in "${DOMAINS[@]}"; do
            # Trim whitespace
            domain=$(echo "$domain" | xargs)
            if [ -z "${DOMAIN_LIST}" ]; then
                DOMAIN_LIST="<<\"${domain}\">>"
            else
                DOMAIN_LIST="${DOMAIN_LIST}, <<\"${domain}\">>"
            fi
        done
        ALLOWED_DOMAINS_ARG='{allowed_tls_domains, ['${DOMAIN_LIST}']},'
    fi

    [ -z "${PORT}" -o -z "${SECRET}" -o -z "${TAG}" ] && \
        error "Not enough options: port='${PORT}' secret='${SECRET}' ad_tag='${TAG}'"

    [ ${PORT} -gt 0 -a ${PORT} -lt 65535 ] || \
        error "Invalid port value: ${PORT}"

    [ -n "`echo $SECRET | grep -x '[[:xdigit:]]\{32\}'`" ] || \
        error "Invalid secret. Should be 32 chars of 0-9 a-f"

    [ -n "`echo $TAG | grep -x '[[:xdigit:]]\{32\}'`" ] || \
        error "Invalid tag. Should be 32 chars of 0-9 a-f"

    [ -z "${TLS_DOMAIN}" -o -n "`echo $TLS_DOMAIN | grep -xE '^([0-9a-z_-]+\.)+[a-z]{2,6}$'`" ] || \
        error "Invalid TLS domain '${TLS_DOMAIN}'. Should be valid domain name!"

    # Create config directory if not exists
    mkdir -p config

    echo '  %% -*- mode: erlang -*-
[
 {mtproto_proxy,
    %% see src/mtproto_proxy.app.src for examples.
    [
        '${PROTO_ARG}'
        '${FRONTING_ARG}'
        '${ALLOWED_DOMAINS_ARG}'
        {ports,
            [#{name => mtp_handler_1,
               listen_ip => "0.0.0.0",
               port => '${PORT}',
               secret => <<"'${SECRET}'">>,
               tag => <<"'${TAG}'">>}
            ]}
    ]},
    %% Logging config
    {kernel,
        [{logger_level, info},
         {logger,
            [{handler, default, logger_std_h,
                #{level => info,
                  formatter => {logger_formatter, #{single_line => true}},
                  config => #{type => file,
                              file => "/var/log/mtproto-proxy/application.log",
                              max_no_bytes => 104857600, % 100MB
                              max_no_files => 10,
                              filesync_repeat_interval => no_repeat}}},
             {handler, console, logger_std_h,
                #{level => critical,
                  config => #{type => standard_io}}}
            ]}]},
    {sasl,
        [{errlog_type, error}]}
].
' >config/prod-sys.config

    info "Config is generated with following properties:"
    info "  port=${PORT}"
    info "  secret=${SECRET}"
    info "  tag=${TAG}"
    info "  tls_only=${TLS_ONLY}"
    info "  dd_only=${DD_ONLY}"
    info "  domain=${TLS_DOMAIN}"
    info "  allowed_domains=${ALLOWED_TLS_DOMAINS}"
}

do_backup_config() {
    if [ -f "$SRC_DIR/config/prod-sys.config" ]; then
        cp $SRC_DIR/config/prod-sys.config $WORKDIR/prod-sys.config.bak
    fi
}

do_restore_config() {
    if [ -f "$WORKDIR/prod-sys.config.bak" ]; then
        cp $WORKDIR/prod-sys.config.bak config/prod-sys.config
    fi
}

do_reload_config() {
    sudo make update-sysconfig
    sudo systemctl reload mtproto-proxy
}

do_build() {
    info "Generating Erlang interpreter options"
    make config/prod-vm.args
    info "Compiling"
    make
}

do_install() {
    # Try to stop proxy in case this script is run not for the first time
    sudo systemctl stop mtproto-proxy 2>/dev/null || true
    info "Installing"
    sudo make install
    info "Starting"
    sudo systemctl enable mtproto-proxy
    sudo systemctl start mtproto-proxy
}

do_print_links() {
    info "Detecting IP address"
    IP=`curl -s -4 -m 10 http://ipv4.seriyps.com || curl -s -4 -m 10 https://digitalresistance.dog/myIp`
    info "Detected external IP is ${IP}"
    URL_PREFIX="https://t.me/proxy?server=${IP}&port=${PORT}&secret="
    ESCAPED_SECRET=$(echo -n $SECRET | sed 's/../\\x&/g') # bytes
    ESCAPED_TLS_SECRET="\xee${ESCAPED_SECRET}"${TLS_DOMAIN}
    BASE64_TLS_SECRET=`echo -ne $ESCAPED_TLS_SECRET | base64 -w 0 | tr '+/' '-_'`
    HEX_TLS_SECRET=`echo -ne $ESCAPED_TLS_SECRET | to_hex`

    info "Logs: /var/log/mtproto-proxy/application.log"
    info "Secret: ${SECRET}"
    info "Proxy links:
    Normal: ${URL_PREFIX}${SECRET}
    Secure: ${URL_PREFIX}dd${SECRET}
    Fake-TLS hex: ${URL_PREFIX}${HEX_TLS_SECRET}
    Fake-TLS base64: ${URL_PREFIX}${BASE64_TLS_SECRET}
    "
    if [ -n "${ALLOWED_TLS_DOMAINS}" ]; then
        info "Allowed TLS domains: ${ALLOWED_TLS_DOMAINS}"
    fi
}

# info "Executing $CMD"
case "$CMD" in
    "install")
        do_configure_os
        do_get_source
        cd $SRC_DIR/
        do_build_config
        do_build
        do_install
        do_print_links
        info "Proxy is ready"
        ;;
    "reconfigure")
        cd $SRC_DIR/
        do_build_config
        do_reload_config
        do_print_links
        info "Config updated"
        ;;
    "reload")
        cd $SRC_DIR/
        do_reload_config
        info "Config updated"
        ;;
    "upgrade")
        do_backup_config
        do_get_source
        cd $SRC_DIR/
        do_restore_config
        do_build
        do_install
        info "Code upgraded"
esac
