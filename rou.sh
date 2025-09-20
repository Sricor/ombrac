#!/bin/bash
#__author__: cavivie
#__modifier__: Gemini

# Tun设备的网关IP (所有流量的默认目标)
DEFAULT_TUN_DEST="198.19.0.1" # 修改成 10.0.0.1

# 需要忽略（走原始网关）的IP段白名单
# 这里包含了常见的内网、环回和链路本地地址
BYPASS_SUBNETS=(
    "10.0.0.0/8"
    "172.16.0.0/12"
    "192.168.0.0/16"
    "169.254.0.0/16" # 链路本地地址
    "127.0.0.0/8"      # 环回地址
    "3.0.223.235/32"
)

# 添加路由的函数
function add_routes() {
    local tun_dest="${1:-$DEFAULT_TUN_DEST}"

    # 1. 自动获取当前的默认网关 (例如你的路由器IP)
    #    通过 grep -v 'utun' 排除掉可能的vpn接口，以防重复执行脚本出错
    ORIGINAL_GATEWAY=$(netstat -nr | grep default | grep -v 'utun' | awk '{print $2}' | head -n 1)

    if [ -z "${ORIGINAL_GATEWAY}" ]; then
        echo "错误：无法找到原始的默认网关。"
        exit 1
    fi
    echo "发现原始网关: ${ORIGINAL_GATEWAY}"

    # 2. 修改默认路由，让所有流量走向 tun 设备
    #    我们不直接修改 `default` 路由，而是添加两个优先级更高的 /1 路由。
    #    0.0.0.0/1 和 128.0.0.0/1 加起来就是整个互联网，这是一种更安全、更通用的做法。
    echo "正在添加路由，将默认流量导向TUN设备: ${tun_dest}..."
    sudo route add -net 0.0.0.0/1 ${tun_dest}
    sudo route add -net 128.0.0.0/1 ${tun_dest}

    # 3. 为白名单中的IP段添加路由，让它们走原始网关，从而绕过TUN
    echo "正在为内网IP段添加绕行路由，经由: ${ORIGINAL_GATEWAY}..."
    for subnet in "${BYPASS_SUBNETS[@]}"; do
        echo "  - 添加绕行: ${subnet}"
        sudo route add -net ${subnet} ${ORIGINAL_GATEWAY}
    done

    echo "路由配置完成。"
}

# 删除路由的函数
function delete_routes() {
    local tun_dest="${1:-$DEFAULT_TUN_DEST}"

    # 同样地，先找到我们之前为内网设置的网关
    BYPASS_GATEWAY=$(netstat -nr | grep '10.0.0.0/8' | awk '{print $2}' | head -n 1)

    echo "正在删除TUN设备的默认流量路由: ${tun_dest}..."
    sudo route delete -net 0.0.0.0/1 ${tun_dest}
    sudo route delete -net 128.0.0.0/1 ${tun_dest}

    if [ -n "${BYPASS_GATEWAY}" ]; then
        echo "正在删除内网IP段的绕行路由..."
        for subnet in "${BYPASS_SUBNETS[@]}"; do
            echo "  - 删除绕行: ${subnet}"
            sudo route delete -net ${subnet} ${BYPASS_GATEWAY}
        done
    else
        echo "警告: 未找到绕行网关，可能需要您手动删除内网路由。"
    fi

    echo "路由清理完成。"
}

function usage(){
    echo "用法:
    $0 add [tun_gateway]    # 设置默认路由到TUN，并为内网IP添加绕行
    $0 del [tun_gateway]    # 删除所有由本脚本添加的路由
    $0 help                 # 显示此帮助信息"
}

# --- 脚本主入口 ---
case $1 in
    add) add_routes $2;;
    # 将'delete'也作为'del'的别名
    del|delete) delete_routes $2;;
    *) usage ;;
esac