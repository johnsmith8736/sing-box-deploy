#!/bin/bash

# 设置语言
export LANG=en_US.UTF-8

# 显示帮助信息
show_help() {
    echo "Sing-box 部署脚本使用说明："
    echo "使用方法: $0 [命令]"
    echo
    echo "可用命令："
    echo "  无参数     - 安装或更新 sing-box"
    echo "  status     - 查看服务状态"
    echo "  restart    - 重启服务"
    echo "  uninstall  - 卸载 sing-box"
    echo
    echo "示例："
    echo "  $0         - 安装或更新"
    echo "  $0 status  - 查看状态"
    echo
    echo "注意事项："
    echo "1. 需要 root 权限运行"
    echo "2. 支持的系统：Ubuntu、Debian、CentOS"
    echo "3. 配置文件位置：/etc/sing-box/config.json"
    echo "4. 日志文件位置：/var/log/sing-box.log"
}

# 定义颜色
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;36m'
bblue='\033[0;34m'
plain='\033[0m'

# 定义颜色函数
red() { echo -e "${red}$1${plain}"; }
green() { echo -e "${green}$1${plain}"; }
yellow() { echo -e "${yellow}$1${plain}"; }
blue() { echo -e "${blue}$1${plain}"; }

# 清理函数
cleanup() {
    rm -f warp-reg.log warp-reg.sh
    if [ $? -ne 0 ]; then
        yellow "清理临时文件失败"
    fi
}

# 设置退出时清理
trap cleanup EXIT

# 获取IP地址
get_ip() {
    # 添加超时和重试机制
    IP=$(curl -s4m8 --retry 3 --retry-delay 2 ip.sb || 
         curl -s4m8 --retry 3 --retry-delay 2 ifconfig.me || 
         curl -s4m8 --retry 3 --retry-delay 2 api.ipify.org)
    if [ -z "$IP" ]; then
        red "无法获取服务器IP地址"
        exit 1
    fi
    echo "$IP"
}

# 检查系统资源
check_system_resources() {
    yellow "检查系统资源..."
    
    # 检查内存
    local total_mem=$(free -m | awk '/^Mem:/{print $2}')
    if [ -n "$total_mem" ] && [ "$total_mem" -lt 512 ]; then
        yellow "警告: 系统内存小于512MB，可能会影响性能"
    fi
    
    # 检查磁盘空间
    local check_dir="${WORK_DIR:-/etc/sing-box}"
    if [ ! -d "$check_dir" ]; then
        check_dir="/"
    fi
    local free_space=$(df -m "$check_dir" 2>/dev/null | awk 'NR==2 {print $4}')
    if [ -z "$free_space" ]; then
        free_space=0
    fi
    if [ "$free_space" -lt 100 ]; then
        red "错误: 可用磁盘空间不足100MB"
        exit 1
    fi
    
    # 检查 bc 是否安装
    if ! command -v bc >/dev/null 2>&1; then
        red "缺少 bc 工具，请先安装 bc (Debian/Ubuntu: apt install -y bc, CentOS: yum install -y bc)"
        exit 1
    fi
    
    # 检查系统负载
    local load=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{print $1}')
    if [ -n "$load" ] && [ $(echo "$load > 2" | bc -l) -eq 1 ]; then
        yellow "警告: 系统负载较高: $load"
    fi
}

# 检查网络环境
check_network() {
    yellow "检查网络环境..."
    
    # 检查DNS解析
    local dns_retry=0
    while ! nslookup github.com >/dev/null 2>&1; do
        dns_retry=$((dns_retry + 1))
        if [ $dns_retry -eq 2 ]; then
            yellow "尝试自动修复 DNS 配置..."
            # 处理 /etc/resolv.conf 可能为符号链接的情况
            if [ -L /etc/resolv.conf ]; then
                sudo rm -f /etc/resolv.conf
                sudo touch /etc/resolv.conf
            fi
            # 解除保护
            sudo chattr -i /etc/resolv.conf 2>/dev/null
            echo -e "nameserver 8.8.8.8\nnameserver 1.1.1.1" | sudo tee /etc/resolv.conf
            # 加保护防止被DHCP覆盖
            sudo chattr +i /etc/resolv.conf 2>/dev/null
            sleep 1
        fi
        if [ $dns_retry -ge 3 ]; then
            red "DNS解析失败，请检查系统DNS配置。当前 /etc/resolv.conf 内容如下："
            cat /etc/resolv.conf
            red "你可以尝试手动执行："
            echo "sudo chattr -i /etc/resolv.conf && echo -e 'nameserver 8.8.8.8\\nnameserver 1.1.1.1' | sudo tee /etc/resolv.conf && sudo chattr +i /etc/resolv.conf"
            exit 1
        fi
        yellow "DNS解析重试 $dns_retry/3..."
        sleep 2
    done
    
    # 检查443端口是否被占用
    if netstat -tuln | grep -q ":443 "; then
        red "错误: 端口443已被占用"
        netstat -tuln | grep ":443 "
        exit 1
    fi
    
    # 检查与GitHub的连接
    local github_retry=0
    while ! curl -s --connect-timeout 5 https://github.com >/dev/null; do
        github_retry=$((github_retry + 1))
        if [ $github_retry -ge 3 ]; then
            yellow "警告: 无法连接到GitHub，可能会影响安装"
            break
        fi
        yellow "GitHub连接重试 $github_retry/3..."
        sleep 2
    done
    
    # 添加TCP连接测试
    yellow "测试外网连接..."
    local test_sites=("www.google.com" "www.cloudflare.com" "www.amazon.com")
    local success=0
    
    for site in "${test_sites[@]}"; do
        if timeout 5 bash -c "</dev/tcp/$site/443" 2>/dev/null; then
            success=$((success + 1))
        fi
    done
    
    if [ $success -eq 0 ]; then
        red "警告: 外网连接异常，可能会影响服务的正常使用"
    elif [ $success -lt ${#test_sites[@]} ]; then
        yellow "警告: 部分外网连接不稳定，建议检查网络环境"
    fi
    
    # 检查整体网络连通性
    local ping_target="8.8.8.8"
    if ! ping -c 1 -W 3 $ping_target >/dev/null 2>&1; then
        yellow "警告: 无法连接到 $ping_target，网络可能不稳定"
    fi
    
    # 检查网络延迟
    local ping_result=$(ping -c 3 8.8.8.8 2>/dev/null | tail -1 | awk '{print $4}' | cut -d '/' -f 2)
    if [ ! -z "$ping_result" ]; then
        if [ $(echo "$ping_result > 100" | bc -l) -eq 1 ]; then
            yellow "警告: 网络延迟较高 (${ping_result}ms)"
        fi
    fi
}

# 检查root权限
[[ $EUID -ne 0 ]] && yellow "请以root模式运行脚本" && exit 1

# 检测系统类型
if [[ -f /etc/redhat-release ]]; then
    release="Centos"
elif cat /etc/issue | grep -q -E -i "debian"; then
    release="Debian"
elif cat /etc/issue | grep -q -E -i "ubuntu"; then
    release="Ubuntu"
elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
    release="Centos"
elif cat /proc/version | grep -q -E -i "debian"; then
    release="Debian"
elif cat /proc/version | grep -q -E -i "ubuntu"; then
    release="Ubuntu"
elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
    release="Centos"
else
    red "不支持当前系统，请使用Ubuntu,Debian,Centos系统" && exit 1
fi

# 检测系统架构
case $(uname -m) in
    x86_64)  
        cpu="amd64"
        ;;
    aarch64)  
        cpu="arm64"
        ;;
    armv7l)  
        cpu="armv7"
        ;;
    *)
        red "不支持的CPU架构: $(uname -m)" && exit 1
        ;;
esac

# 获取最新 1.11.x 版本号
get_latest_1_11_x_version() {
    curl -s https://api.github.com/repos/SagerNet/sing-box/releases \
    | grep -o '"tag_name": *"v1\.11\.[0-9]\+"' \
    | grep -o '1.11.[0-9]\+' \
    | sort -V \
    | tail -n 1
}

# 设置变量
SING_BOX_VERSION="$(get_latest_1_11_x_version)"
if [ -z "$SING_BOX_VERSION" ]; then
    SING_BOX_VERSION="1.11.0" # 兜底
fi
WORK_DIR="/etc/sing-box"
BINARY_DIR="/usr/local/bin"

# 检查依赖
check_dependencies() {
    local dependencies=(
        "wget"
        "curl"
        "tar"
        "jq"
        "openssl"
        "uuid"
        "netstat"
        "iptables"
        "bc"
        "nslookup"
        "systemd"
    )

    yellow "检查并安装必要的依赖..."
    
    if [[ $release == "Centos" ]]; then
        # CentOS可能需要EPEL源
        if ! rpm -qa | grep -q epel-release; then
            yellow "安装EPEL源..."
            yum install -y epel-release
        fi
        
        for dep in "${dependencies[@]}"; do
            if ! command -v "$dep" &>/dev/null; then
                yellow "安装依赖: $dep"
                yum install -y "$dep"
            fi
        done
    else
        # 对于Debian/Ubuntu系统
        local apt_updated=false
        
        # 检查是否需要更新apt缓存
        if [ ! -f "/var/cache/apt/pkgcache.bin" ] || [ $(( $(date +%s) - $(stat -c %Y /var/cache/apt/pkgcache.bin) )) -gt 3600 ]; then
            yellow "更新软件包列表..."
            apt update
            apt_updated=true
        fi
        
        if ! dpkg -l | grep -q "^ii  dnsutils"; then
            if ! $apt_updated; then
                apt update
                apt_updated=true
            fi
            yellow "安装dnsutils..."
            apt install -y dnsutils
        fi
        
        for dep in "${dependencies[@]}"; do
            if ! command -v "$dep" &>/dev/null; then
                if ! $apt_updated; then
                    apt update
                    apt_updated=true
                fi
                yellow "安装依赖: $dep"
                apt install -y "$dep"
            fi
        done
    fi
    
    # 验证所有依赖是否安装成功
    local missing_deps=()
    for dep in "${dependencies[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    # 特别检查systemd
    if ! systemctl --version >/dev/null 2>&1; then
        red "系统未安装或未启用systemd"
        exit 1
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        red "以下依赖安装失败: ${missing_deps[*]}"
        exit 1
    fi
    
    green "所有依赖已安装"
}

# 安装前准备
prepare_installation() {
    yellow "开始安装 sing-box ${SING_BOX_VERSION} ..."
    mkdir -p ${WORK_DIR}
    mkdir -p ${BINARY_DIR}
}

# 下载并安装sing-box
download_and_install() {
    if ! wget -O sing-box.tar.gz "https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION}-linux-${cpu}.tar.gz"; then
        red "下载 sing-box 失败"
        exit 1
    fi
    
    if ! tar -xzf sing-box.tar.gz; then
        red "解压 sing-box 失败"
        rm -f sing-box.tar.gz
        exit 1
    fi
    
    cp "sing-box-${SING_BOX_VERSION}-linux-${cpu}/sing-box" ${BINARY_DIR}/
    chmod +x ${BINARY_DIR}/sing-box
    rm -rf sing-box.tar.gz "sing-box-${SING_BOX_VERSION}-linux-${cpu}"
    
    if ! command -v ${BINARY_DIR}/sing-box &>/dev/null; then
        red "sing-box 安装失败"
        exit 1
    fi
}

# 生成随机参数
generate_params() {
    UUID=$(uuid)
    KEY_PAIR=$(${BINARY_DIR}/sing-box generate reality-keypair)
    PRIVATE_KEY=$(echo "$KEY_PAIR" | grep "Private key:" | awk '{print $3}')
    PUBLIC_KEY=$(echo "$KEY_PAIR" | grep "Public key:" | awk '{print $3}')
    SHORT_ID=$(openssl rand -hex 8)
    SERVER_IP=$(get_ip)
    
    # 验证参数
    if [ -z "$UUID" ] || [ -z "$PRIVATE_KEY" ] || [ -z "$PUBLIC_KEY" ] || [ -z "$SHORT_ID" ] || [ -z "$SERVER_IP" ]; then
        red "生成配置参数失败"
        exit 1
    fi
}

# 获取WARP配置信息
get_warp_config() {
    yellow "正在获取WARP配置信息..."
    
    local max_retries=3
    local retry_count=0
    local success=false
    
    while [ $retry_count -lt $max_retries ] && [ $success = false ]; do
        if curl -sLo warp-reg.sh warp-reg.vercel.app; then
            if bash warp-reg.sh > warp-reg.log 2>&1; then
                # 从日志中提取配置信息
                if [ -f "warp-reg.log" ]; then
                    PRIVATE_KEY_WARP=$(grep "private_key" warp-reg.log | awk -F"[()]" '{print $2}')
                    WARP_ADDRESS_V4=$(grep "v4" warp-reg.log | awk -F"[()]" '{print $2}' | head -n 1)
                    WARP_ADDRESS_V6=$(grep "v6" warp-reg.log | awk -F"[()]" '{print $2}' | head -n 1)
                    WARP_RESERVED=$(grep "reserved" warp-reg.log | awk -F"[()]" '{print $2}')
                    
                    # 验证必要的配置信息是否获取成功
                    if [ -n "$PRIVATE_KEY_WARP" ] && [ -n "$WARP_ADDRESS_V4" ] && [ -n "$WARP_RESERVED" ]; then
                        success=true
                        green "WARP配置信息获取成功！"
                        break
                    fi
                fi
            fi
        fi
        
        retry_count=$((retry_count + 1))
        if [ $retry_count -lt $max_retries ]; then
            yellow "WARP配置获取失败，第 $retry_count 次重试..."
            sleep 3
        fi
    done
    
    if [ $success = false ]; then
        red "获取WARP配置失败！"
        if [ -f "warp-reg.log" ]; then
            red "错误日志："
            cat warp-reg.log
        fi
        cleanup
        exit 1
    fi
}

# 验证配置文件
validate_config() {
    yellow "验证配置文件..."
    
    # 检查配置文件是否存在
    if [ ! -f "${WORK_DIR}/config.json" ]; then
        red "配置文件不存在"
        exit 1
    fi
    
    # 检查配置文件权限
    local config_perms=$(stat -c %a "${WORK_DIR}/config.json")
    if [ "$config_perms" != "600" ]; then
        yellow "修正配置文件权限为600..."
        chmod 600 "${WORK_DIR}/config.json"
    fi
    
    # 检查配置目录权限
    local dir_perms=$(stat -c %a "${WORK_DIR}")
    if [ "$dir_perms" != "700" ]; then
        yellow "修正配置目录权限为700..."
        chmod 700 "${WORK_DIR}"
    fi
    
    # 检查所有者
    local owner=$(stat -c %U "${WORK_DIR}/config.json")
    if [ "$owner" != "root" ]; then
        yellow "修正配置文件所有者为root..."
        chown root:root "${WORK_DIR}/config.json"
    fi
    
    # 验证JSON语法
    if ! jq empty "${WORK_DIR}/config.json" 2>/dev/null; then
        red "配置文件JSON格式错误"
        exit 1
    fi
    
    # 验证必要的配置项
    if ! jq -e '.inbounds[].listen_port' "${WORK_DIR}/config.json" >/dev/null 2>&1; then
        red "配置文件缺少必要的端口配置"
        exit 1
    fi
    
    if ! jq -e '.inbounds[].type' "${WORK_DIR}/config.json" >/dev/null 2>&1; then
        red "配置文件缺少必要的入站类型配置"
        exit 1
    fi
    
    if ! jq -e '.outbounds' "${WORK_DIR}/config.json" >/dev/null 2>&1; then
        red "配置文件缺少出站配置"
        exit 1
    fi
    
    # 使用sing-box验证配置
    if ! ${BINARY_DIR}/sing-box check -c ${WORK_DIR}/config.json; then
        red "配置文件验证失败"
        exit 1
    fi
    
    # 检查关键配置项
    if ! jq -e '.experimental.clash_api.secret' "${WORK_DIR}/config.json" >/dev/null 2>&1; then
        yellow "警告: clash_api.secret未设置，建议设置密码以提高安全性"
    fi
    
    green "配置文件验证成功！"
}

# 生成随机密码
generate_random_password() {
    openssl rand -base64 16
}

# 创建配置文件
create_config() {
    # 获取WARP配置
    get_warp_config
    
    # 生成随机密码
    local CLASH_SECRET=$(generate_random_password)
    
    cat > ${WORK_DIR}/config.json << EOF
{
  "log": {
    "disabled": false,
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "alidns",
        "address": "https://223.5.5.5/dns-query",
        "strategy": "ipv4_only",
        "detour": "direct"
      },
      {
        "tag": "cloudflare",
        "address": "https://1.1.1.1/dns-query",
        "strategy": "ipv4_only",
        "detour": "direct"
      },
      {
        "tag": "block",
        "address": "rcode://success"
      }
    ],
    "rules": [
      {
        "rule_set": [
          "geosite-cn"
        ],
        "server": "alidns",
        "rule_set_ip_cidr_accept_empty": true
      },
      {
        "rule_set": [
          "geosite-category-ads-all"
        ],
        "server": "block",
        "rule_set_ip_cidr_accept_empty": true
      }
    ],
    "final": "cloudflare",
    "strategy": "ipv4_only",
    "disable_cache": false,
    "disable_expire": false
  },
  "inbounds": [
    { 
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": 443,
      "users": [
        {
          "uuid": "${UUID}",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "www.nhk.or.jp",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "www.nhk.or.jp",
            "server_port": 443
          },
          "private_key": "${PRIVATE_KEY}",
          "short_id": [
            "${SHORT_ID}"
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "endpoints": [
    {
      "type": "wireguard",
      "tag": "warp",
      "address": [
        "${WARP_ADDRESS_V4}/32",
        "${WARP_ADDRESS_V6}/128"
      ],
      "private_key": "${PRIVATE_KEY_WARP}",
      "peers": [
        {
          "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
          "allowed_ips": [
            "0.0.0.0/0",
            "::/0"
          ],
          "address": "162.159.192.4",
          "port": 2408,
          "reserved": ${WARP_RESERVED}
        }
      ],
      "mtu": 1280
    }
  ],
  "route": {
    "rules": [
      {
        "protocol": ["dns"],
        "action": "hijack-dns"
      },
      {
        "inbound": ["vless-in"],
        "action": "sniff"
      },
      {
        "rule_set": ["geosite-category-ads-all"],
        "action": "reject"
      },
      {
        "ip_is_private": true,
        "action": "route",
        "outbound": "direct"
      },
      {
        "rule_set": ["geoip-cn", "geosite-cn"],
        "action": "route",
        "outbound": "direct"
      },
      {
        "rule_set": ["geosite-openai"],
        "action": "route",
        "outbound": "warp"
      },
      {
        "rule_set": ["geosite-abema"],
        "action": "route",
        "outbound": "warp"
      }
    ],
    "rule_set": [
      {
        "tag": "geoip-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
        "download_detour": "direct",
        "update_interval": "1d"
      },
      {
        "tag": "geosite-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
        "download_detour": "direct",
        "update_interval": "1d"
      },
      {
        "tag": "geosite-category-ads-all",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
        "download_detour": "direct",
        "update_interval": "1d"
      },
      {
        "tag": "geosite-openai",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/openai.srs",
        "download_detour": "direct",
        "update_interval": "1d"
      },
      {
        "tag": "geosite-abema",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/abema.srs",
        "download_detour": "direct",
        "update_interval": "1d"
      }
    ],
    "auto_detect_interface": true,
    "final": "direct"
  },
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "external_ui": "dashboard",
      "secret": "${CLASH_SECRET}",
      "default_mode": "rule",
      "access_control_allow_origin": [
        "http://127.0.0.1",
        "http://yacd.haishan.me"
      ],
      "access_control_allow_private_network": true
    },
    "cache_file": {
      "enabled": true,
      "path": "cache.db",
      "cache_id": "mycacheid",
      "store_fakeip": true
    }
  }
}
EOF

    # 设置适当的权限
    chmod 600 ${WORK_DIR}/config.json
    chmod 700 ${WORK_DIR}
    chown root:root ${WORK_DIR}/config.json
}

# 创建日志轮转配置
create_logrotate_config() {
    cat > /etc/logrotate.d/sing-box << EOF
/var/log/sing-box.log {
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    create 640 root root
    postrotate
        systemctl reload sing-box.service >/dev/null 2>&1 || true
    endscript
}
EOF
    chmod 644 /etc/logrotate.d/sing-box
}

# 创建systemd服务
create_service() {
    cat > /etc/systemd/system/sing-box.service << EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
ExecStart=${BINARY_DIR}/sing-box run -c ${WORK_DIR}/config.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity
StandardOutput=append:/var/log/sing-box.log
StandardError=append:/var/log/sing-box.log

[Install]
WantedBy=multi-user.target
EOF

    # 创建日志文件并设置权限
    touch /var/log/sing-box.log
    chmod 640 /var/log/sing-box.log
    chown root:root /var/log/sing-box.log
    
    # 创建日志轮转配置
    create_logrotate_config
}

# 启动服务
start_service() {
    yellow "启动 sing-box 服务..."
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    
    # 增加更多检查
    sleep 2
    if ! systemctl is-active --quiet sing-box; then
        red "sing-box 服务启动失败"
        systemctl status sing-box
        yellow "使用以下命令查看详细日志："
        echo "journalctl -u sing-box -f"
        exit 1
    fi
    
    # 检查端口占用
    if ! netstat -tuln | grep -q ":443 "; then
        red "端口 443 未被正确监听"
        systemctl status sing-box
        exit 1
    fi
    
    # 检查进程状态
    if ! ps aux | grep -v grep | grep -q sing-box; then
        red "sing-box 进程未运行"
        systemctl status sing-box
        exit 1
    fi
    
    green "sing-box 服务启动成功!"
}

# 卸载功能
uninstall() {
    yellow "开始卸载sing-box..."
    
    # 停止并禁用服务
    systemctl stop sing-box 2>/dev/null
    systemctl disable sing-box 2>/dev/null
    
    # 备份当前配置
    if [ -f "${WORK_DIR}/config.json" ]; then
        backup_config
        green "当前配置已备份"
    fi
    
    # 备份日志文件
    if [ -f "/var/log/sing-box.log" ]; then
        local log_backup="/var/log/sing-box.log.backup-$(date +%Y%m%d_%H%M%S)"
        cp "/var/log/sing-box.log" "$log_backup"
        chmod 640 "$log_backup"
        green "日志文件已备份到: $log_backup"
    fi
    
    # 删除文件，保留备份目录
    find ${WORK_DIR} -type f ! -path "${WORK_DIR}/backups/*" -delete
    rm -f ${BINARY_DIR}/sing-box
    rm -f /etc/systemd/system/sing-box.service
    rm -f /etc/logrotate.d/sing-box
    rm -f /var/log/sing-box.log*
    
    # 重载systemd
    systemctl daemon-reload
    
    green "sing-box 已完全卸载"
    if [ -d "${WORK_DIR}/backups" ]; then
        blue "配置备份保留在: ${WORK_DIR}/backups"
    fi
    if [ -f "$log_backup" ]; then
        blue "日志备份保留在: $log_backup"
    fi
}

# 输出客户端信息
print_client_info() {
    local CLIENT_INFO="${HOME}/sing-box-client-info.txt"
    local CLIENT_CONFIG="${HOME}/sing-box-client.json"
    local SERVER_IP=$(get_ip)
    
    # 输出人类可读格式
    cat > "$CLIENT_INFO" << EOF
============= Sing-box 客户端配置信息 =============
服务器地址: ${SERVER_IP}
监听端口: 443
UUID: ${UUID}
传输协议: VLESS
加密方式: reality
Public Key: ${PUBLIC_KEY}
Short ID: ${SHORT_ID}

配置说明：
1. TUN模式配置（支持所有应用程序）：
   - 地址: 172.19.0.1/30
   - MTU: 1500
   - 自动路由: 已启用
   - HTTP代理: 127.0.0.1:2080

2. 混合代理模式：
   - 地址: 127.0.0.1
   - 端口: 2080

3. 路由规则：
   - 中国大陆IP和域名: 直连
   - OpenAI相关服务: 代理
   - Abema相关服务: 代理
   - 广告域名: 拦截
   - 其他流量: 代理

4. DNS配置：
   - 中国大陆域名: AliDNS (223.5.5.5)
   - 其他域名: Cloudflare (1.1.1.1)
   - 广告域名: 拦截

5. 安全提示：
   - 请妥善保管配置文件，其中包含敏感信息
   - 建议在导入到客户端后删除配置文件
   - 定期更新客户端和配置以获得更好的安全性

============================================
EOF

    # 输出JSON格式的客户端配置
    cat > "$CLIENT_CONFIG" << EOF
{
  "dns": {
    "servers": [
      {
        "tag": "alidns",
        "address": "https://223.5.5.5/dns-query",
        "strategy": "ipv4_only",
        "detour": "direct"
      },
      {
        "tag": "cloudflare",
        "address": "https://1.1.1.1/dns-query",
        "strategy": "ipv4_only",
        "detour": "proxy"
      },
      {
        "tag": "block",
        "address": "rcode://success"
      }
    ],
    "rules": [
      {
        "rule_set": [
          "geosite-cn"
        ],
        "server": "alidns",
        "rule_set_ip_cidr_accept_empty": true
      },
      {
        "rule_set": [
          "geosite-category-ads-all"
        ],
        "server": "block",
        "rule_set_ip_cidr_accept_empty": true
      }
    ],
    "final": "cloudflare",
    "strategy": "ipv4_only",
    "disable_cache": false,
    "disable_expire": false
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "address": "172.19.0.1/30",
      "mtu": 1500,
      "auto_route": true,
      "strict_route": true,
      "stack": "system",
      "platform": {
        "http_proxy": {
          "enabled": true,
          "server": "127.0.0.1",
          "server_port": 2080
        }
      }
    },
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
      "listen_port": 2080,
      "users": []
    }
  ],
  "outbounds": [
    {
      "tag": "proxy",
      "type": "selector",
      "outbounds": [
        "auto",
        "direct",
        "sing-box-reality"
      ]
    },
    {
      "type": "vless",
      "tag": "sing-box-reality",
      "server": "${SERVER_IP}",
      "server_port": 443,
      "uuid": "${UUID}",
      "flow": "xtls-rprx-vision",
      "tls": {
        "enabled": true,
        "server_name": "www.nhk.or.jp",
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        },
        "reality": {
          "enabled": true,
          "public_key": "${PUBLIC_KEY}",
          "short_id": "${SHORT_ID}"
        }
      },
      "packet_encoding": "xudp"
    },
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "tag": "auto",
      "type": "urltest",
      "outbounds": [
        "sing-box-reality"
      ],
      "url": "http://www.gstatic.com/generate_204",
      "interval": "1m",
      "tolerance": 50
    }
  ],
  "route": {
    "rules": [
      {
        "protocol": ["dns"],
        "action": "hijack-dns"
      },
      {
        "inbound": ["tun-in", "mixed-in"],
        "action": "sniff"
      },
      {
        "rule_set": ["geosite-category-ads-all"],
        "action": "reject"
      },
      {
        "ip_is_private": true,
        "action": "route",
        "outbound": "direct"
      },
      {
        "domain_suffix": [".cn"],
        "action": "route",
        "outbound": "direct"
      },
      {
        "rule_set": ["geoip-cn", "geosite-cn", "geosite-private"],
        "action": "route",
        "outbound": "direct"
      },
      {
        "rule_set": ["geosite-openai"],
        "action": "route",
        "outbound": "proxy"
      },
      {
        "rule_set": ["geosite-abema"],
        "action": "route",
        "outbound": "proxy"
      },
      {
        "clash_mode": "direct",
        "action": "route",
        "outbound": "direct"
      },
      {
        "clash_mode": "global",
        "action": "route",
        "outbound": "proxy"
      },
      {
        "domain": [
          "clash.razord.top",
          "yacd.metacubex.one",
          "yacd.haishan.me",
          "d.metacubex.one"
        ],
        "action": "route",
        "outbound": "direct"
      }
    ],
    "rule_set": [
      {
        "tag": "geoip-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
        "download_detour": "proxy",
        "update_interval": "1d"
      },
      {
        "tag": "geosite-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
        "download_detour": "proxy",
        "update_interval": "1d"
      },
      {
        "tag": "geosite-private",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-private.srs",
        "download_detour": "proxy",
        "update_interval": "1d"
      },
      {
        "tag": "geosite-category-ads-all",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
        "download_detour": "proxy",
        "update_interval": "1d"
      },
      {
        "tag": "geosite-openai",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/openai.srs",
        "download_detour": "proxy",
        "update_interval": "1d"
      },
      {
        "tag": "geosite-abema",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/abema.srs",
        "download_detour": "proxy",
        "update_interval": "1d"
      }
    ],
    "auto_detect_interface": true,
    "final": "proxy"
  },
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "external_ui": "dashboard",
      "secret": "",
      "default_mode": "rule",
      "access_control_allow_origin": [
        "http://127.0.0.1",
        "http://yacd.haishan.me"
      ],
      "access_control_allow_private_network": true
    },
    "cache_file": {
      "enabled": true,
      "path": "cache.db",
      "cache_id": "mycacheid",
      "store_fakeip": true
    }
  }
}
EOF

    if [ ! -f "$CLIENT_INFO" ] || [ ! -f "$CLIENT_CONFIG" ]; then
        red "生成客户端配置文件失败"
        exit 1
    fi

    # 设置配置文件权限
    chmod 600 "$CLIENT_INFO" "$CLIENT_CONFIG"

    green "安装完成！"
    blue "客户端配置信息已保存到：$CLIENT_INFO"
    blue "JSON格式客户端配置已保存到：$CLIENT_CONFIG"
    yellow "注意：配置文件包含敏感信息，请在使用后及时删除"
    yellow "建议使用以下命令查看配置信息："
    echo "cat $CLIENT_INFO"
    echo "cat $CLIENT_CONFIG"
}

# 备份配置文件
backup_config() {
    local backup_dir="${WORK_DIR}/backups"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="${backup_dir}/config_${timestamp}.json"
    local max_backups=5
    
    if [ -f "${WORK_DIR}/config.json" ]; then
        # 创建备份目录
        mkdir -p "$backup_dir"
        
        # 复制配置文件
        if cp "${WORK_DIR}/config.json" "$backup_file"; then
            chmod 600 "$backup_file"
            
            # 压缩备份
            if command -v gzip >/dev/null 2>&1; then
                gzip -c "$backup_file" > "${backup_file}.gz"
                rm -f "$backup_file"
                backup_file="${backup_file}.gz"
                green "配置文件已压缩备份到: $backup_file"
            else
                green "配置文件已备份到: $backup_file"
            fi
            
            # 创建备份清单
            echo "备份时间: $(date)" > "${backup_dir}/backup_${timestamp}.log"
            echo "源文件: ${WORK_DIR}/config.json" >> "${backup_dir}/backup_${timestamp}.log"
            echo "备份文件: $backup_file" >> "${backup_dir}/backup_${timestamp}.log"
            
            # 清理旧备份，只保留最近的几个
            local old_backups=($(ls -t "${backup_dir}"/config_*.json* 2>/dev/null))
            if [ ${#old_backups[@]} -gt $max_backups ]; then
                yellow "清理旧备份文件..."
                for ((i=$max_backups; i<${#old_backups[@]}; i++)); do
                    rm -f "${old_backups[$i]}"
                    rm -f "${backup_dir}/backup_$(basename "${old_backups[$i]}" .json).log"
                done
            fi
            
            # 显示备份统计
            local total_backups=$(ls -1 "${backup_dir}"/config_*.json* 2>/dev/null | wc -l)
            local total_size=$(du -sh "$backup_dir" 2>/dev/null | cut -f1)
            blue "备份统计:"
            blue "- 总备份数: $total_backups"
            blue "- 备份目录大小: $total_size"
            blue "- 最大保留数: $max_backups"
        else
            red "配置文件备份失败"
        fi
    fi
}

# 检查服务状态
check_service_status() {
    yellow "检查服务状态..."
    
    # 检查服务状态
    if ! systemctl is-active --quiet sing-box; then
        red "sing-box 服务未运行"
        systemctl status sing-box
        return 1
    fi
    
    # 检查端口监听
    if ! netstat -tuln | grep -q ":443 "; then
        red "端口 443 未被正确监听"
        netstat -tuln | grep ":443 "
        return 1
    fi
    
    # 检查进程状态
    local pid=$(pgrep sing-box)
    if [ -z "$pid" ]; then
        red "sing-box 进程未运行"
        return 1
    fi
    
    # 检查资源使用情况
    if [ -n "$pid" ]; then
        local cpu_usage=$(ps -p $pid -o %cpu | tail -n 1 | tr -d ' ')
        local mem_usage=$(ps -p $pid -o %mem | tail -n 1 | tr -d ' ')
        local uptime=$(ps -p $pid -o etime | tail -n 1 | tr -d ' ')
        local open_files=$(lsof -p $pid 2>/dev/null | wc -l)
        
        blue "进程状态:"
        blue "- PID: $pid"
        blue "- 运行时间: $uptime"
        blue "- CPU 使用率: ${cpu_usage}%"
        blue "- 内存使用率: ${mem_usage}%"
        blue "- 打开文件数: $open_files"
        
        # 资源使用预警
        if [ $(echo "$cpu_usage > 80" | bc -l) -eq 1 ]; then
            yellow "警告: CPU 使用率过高: ${cpu_usage}%"
        fi
        
        if [ $(echo "$mem_usage > 80" | bc -l) -eq 1 ]; then
            yellow "警告: 内存使用率过高: ${mem_usage}%"
        fi
        
        if [ $open_files -gt 1000 ]; then
            yellow "警告: 打开文件数量较多: $open_files"
        fi
    fi
    
    # 检查日志文件
    if [ -f "/var/log/sing-box.log" ]; then
        local log_size=$(du -h /var/log/sing-box.log | cut -f1)
        blue "日志状态:"
        blue "- 日志大小: $log_size"
        
        # 检查最近的错误日志
        local error_count=$(grep -i "error\|failed\|fatal" /var/log/sing-box.log | wc -l)
        if [ $error_count -gt 0 ]; then
            yellow "发现 $error_count 条错误日志，最近5条："
            grep -i "error\|failed\|fatal" /var/log/sing-box.log | tail -n 5
        fi
        
        # 检查日志大小
        if [ $(echo "$log_size" | sed 's/[^0-9]//g') -gt 100 ]; then
            yellow "警告: 日志文件较大，建议进行轮转"
        fi
    fi
    
    green "sing-box 服务运行正常"
    return 0
}

# 重启服务
restart_service() {
    yellow "重启 sing-box 服务..."
    
    systemctl restart sing-box
    sleep 2
    
    if check_service_status; then
        green "服务重启成功"
    else
        red "服务重启失败"
        return 1
    fi
}

# 修改主函数以支持新的命令
main() {
    case "$1" in
        uninstall)
            if [ -f "${WORK_DIR}/config.json" ]; then
                backup_config
                green "当前配置已备份"
            fi
            uninstall
            exit 0
            ;;
        restart)
            restart_service
            exit 0
            ;;
        status)
            check_service_status
            exit 0
            ;;
        *)
            check_system_resources
            check_network
            check_dependencies
            prepare_installation
            download_and_install
            generate_params
            
            # 如果存在旧配置，先备份
            if [ -f "${WORK_DIR}/config.json" ]; then
                backup_config
            fi
            
            create_config
            validate_config
            create_service
            start_service
            print_client_info
            ;;
    esac
}

# 修改命令行参数处理
case "$1" in
    uninstall)
        main uninstall
        ;;
    restart)
        main restart
        ;;
    status)
        main status
        ;;
    *)
        main
        ;;
esac 