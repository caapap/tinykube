#!/usr/bin/env bash
# Usage: Install kubernetes

# base 
BASE_DIR="/iflytek/.kube"
KUBE_HOME=${KUBE_HOME:-/iflytek/kube}
kube_override=${kube_override:-false}
kube_systctl=${kube_systctl:-1}

# rpm 
RPM_DIR="/iflytek/repo" 

# helm
REPO_URL="https://registry.kxdigit.com"
MIRROR_IP=${MIRROR_IP:-null}

# docker 
DOCKER_LIB=${DOCKER_LIB:-${KUBE_HOME}/lib/docker} 
DOCKER_VERSION=${DOCKER_VERSION:-20.10.8}
DOCKER_LIVE_RESTORE=${DOCKER_LIVE_RESTORE:-false}
MIRROR_URL=${MIRROR_URL:-[\"https://registry.kxdigit.com\"]}
DOCKER_BRIDGE=${DOCKER_BRIDGE:-null}
PUBLIC_REPO=${REPO_URL}
RELEASE_REPO=${RELEASE_REPO:-$REPO_URL/blueking}

# k8s 
KUBELET_LIB=${KUBELET_LIB:-${KUBE_HOME}/lib/kubelet}
K8S_CTRL_IP=${K8S_CTRL_IP:-$LAN_IP}
K8S_VER=${K8S_VER:-1.22.12}
K8S_SVC_CIDR=${K8S_SVC_CIDR:-10.96.0.0/12}
K8S_POD_CIDR=${K8S_POD_CIDR:-10.244.0.0/16}
K8S_EXTRA_ARGS=${K8S_EXTRA_ARGS:-allowed-unsafe-sysctls: 'net.ipv4.tcp_tw_reuse'}
ETCD_LIB=${ETCD_LIB:-${KUBE_HOME}/lib/etcd}
KUBE_CP_WORKER=${KUBE_CP_WORKER:-0}
K8S_CNI=${K8S_CNI:-flannel}
join_cmd_b64=${join_cmd_b64:-null}
cluster_env=${cluster_env:-null}
master_join_cmd_b64=${master_join_cmd_b64:-null}

# safe mode 
set -euo pipefail

# reset PATH 
PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# Generic script framework variables
# 
#SELF_DIR=$(dirname "$(readlink -f "$0")")
#PROGRAM=$(basename "$0")
VERSION=1.0
EXITCODE=0
OP_TYPE=
LAN_IP=

# global variables 
PROJECTS=( kubenv op helm k8smaster k8snode )
PROJECT=
ON_CLOUD="bare-metal"

# error exit handler
err_trap_handler () {
    MYSELF="$0"
    LASTLINE="$1"
    LASTERR="$2"
    echo "${MYSELF}: line ${LASTLINE} with exit code ${LASTERR}" >&2
}
trap 'err_trap_handler ${LINENO} $?' ERR

usage () {
cat <<EOF
usage: 
kube.sh     [ -h --help -?      check help ]
            [ -i, --install     install module(${PROJECTS[*]}) ]
            [ -c, --clean       remove module(${PROJECTS[*]}) ]
            [ -r, --render      render or config module(${PROJECTS[*]}) ]
            [ -v, --version     [option] check script versin ]
EOF
}

usage_and_exit () {
    usage
    exit "$1"
}

log () {
    echo "[INFO]: $*"
}

warning () {
    echo "[WARN]: $*" 1>&2
    EXITCODE=$((EXITCODE + 1))
}

version () {
    echo "kube.sh version $VERSION"
}

highlight () {
    echo -e "\033[7m  $*  \033[0m"
}

error () {
    highlight "[ERROR]: $*" 1>&2
    usage_and_exit 1
}

ok_kube () {
    cat <<EOF

$(
    log "LAN_IP: $LAN_IP"
    highlight "Welcome to KUBE on $ON_CLOUD"
)
EOF
}

bye_kube () {
    cat <<EOF

$(
    highlight "Finish"
)
EOF
}

_retry () {
    local n=1
    local max=2
    local delay=1
    while true; do
        if "$@"; then
            break
        elif (( n < max )); then
            ((n++))
            log "Command failed. Attempt $n/$max:"
            sleep $delay;
        else
            error "The command $* has failed after $n attempts."
        fi
    done

}
 

# ***ops
install_op () {
    _install_common
    op_kubeadm
    op_kubectl
    op_minikube
    op_helm
    op_bkrepo "${REPO_URL}"
    log "Complete"
}

_install_common () {
    if ! rpm -q bash-completion &>/dev/null; then 
        yum -y install bash-completion || error "Install bash-completion Failed"
    fi
}

op_kubeadm () {
    if command -v kubeadm &>/dev/null; then
    sed -ri '/kube config begin for kubeadm/,/kube config end for kubeadm/d' "$KUBE_DIR/kube.env"
    cat >> "$KUBE_DIR/kube.env" << 'EOF'
# kube config begin for kubeadm
# kubeadm completation
source <(kubeadm completion bash)
# kube config end for kubeadm
EOF
    fi
}

op_kubectl () {
    if command -v kubectl &>/dev/null; then
    sed -ri '/kube config begin for kubectl/,/kube config end for kubectl/d' "$KUBE_DIR/kube.env"
    cat >> "$KUBE_DIR/kube.env" << 'EOF'
# kube config begin for kubectl
# kubectl completation
source <(kubectl completion bash)
# kube config end for kubectl
EOF
    fi
}

op_minikube () {
    if command -v minikube &>/dev/null; then
    sed -ri '/kube config begin for minikube/,/kube config end for minikube/d' "$KUBE_DIR/kube.env"
    cat >> "$KUBE_DIR/kube.env" << 'EOF'
# kube config begin for minikube
# minikube completation
source <(minikube completion bash)
# kube config end for minikube
EOF
    fi
}

op_helm () {
    if command -v helm &>/dev/null; then
    sed -ri '/kube config begin for helm/,/kube config end for helm/d' "$KUBE_DIR/kube.env"
    cat >> "$KUBE_DIR/kube.env" << 'EOF'
# kube config begin for helm
# Helm completation
source <(helm completion bash)
# Helm activate OCI support
export HELM_EXPERIMENTAL_OCI=1
# kube config end for helm
EOF
    fi
}

op_repo () {
    local REPO_URL="$1"
    if command -v helm &>/dev/null; then
        if [[ $REPO_URL == "null" ]]; then
            warning "REPO_URL is ${REPO_URL}, skipping"
            return 0
        fi
        highlight "Add repo: ${REPO_URL}"
        helm repo add k8s "${REPO_URL}"
        helm repo update
        log "k8srepo added"
    else
        warning "Add k8srepo: helm not found, skipping"
        return 0
    fi
}

clean_op () {
    helm repo remove k8s || warning "Remove k8srepo failed"
    clean_kubenv
}

install_kubenv () {
    local kube_override=true
    _add_sysctl
    _add_hosts
    cat -n "$KUBE_DIR/kube.env"
    _init_kubeadmconfig
    log "Complete" 
}

_init_kubeadmconfig () {
    local join_cmd
    local node_name
    local node_type
    
    # parameter checking 
    [[ -n ${KUBE_K8S_CTRL_IP}]] || error "Kubernetes control panel IP is not set"
    if [[ ${join_cmd_b64} != "null" ]]; then
        join_cmd=$(echo -n "${join_cmd_b64}" | base64 -d)
        echo -n "${join_cmd}" | grep -q "kubeadm join" || error "Invalid node join command"
        node_name="node-$(echo "$LAN_IP" | tr '.' '-')"
        node_type="JoinConfiguration"
    elif [[ ${master_join_cmd_b64} != "null" ]]; then
        join_cmd=$(echo -n "${master_join_cmd_b64}" | base64 -d)
        echo -n "${join_cmd}" | grep -q "kubeadm kubeadmjoin" || error "Invalid master node expanding command"
        node_name="master-$(echo "$LAN_IP" | tr '.' '-')"
        node_type="InitConfiguration"
    else
        node_name="master-$(echo "$LAN_IP" | tr '.' '-')"
        node_type="InitConfiguration"
    fi

    cat > "$KUBE_DIR/kubeadm-config" << EOF 
apiVersion: kubeadm.k8s.io/$(
    [[ $K8S_VER =~ ^1.(1[5-9]|2[0-5]) ]] && echo "v1beta2"; exit; }
)
apiServer:
  extraArgs:
    authorization-mode: Node,RBAC
  timeoutForControlPlane: 4m0s
certificatesDir: /etc/kubernetes/pki
clusterName: kubernetes
controlPlaneEndpoint: k8s-api.bcs.local:6443
controllerManager: {}:
dns:
  type: CoreDNS
etcd:
    local:
    dataDir: ${ETCD_LIB}
imageRepository: ${PUBLIC_REPO}/k8s.gcr.io
kind: ClusterConfiguration
kubernetesVersion: ${K8S_VER}
networking:
    dnsDomain: cluster.local
    podSubnet: ${K8S_POD_CIDR}
    serviceSubnet: ${K8S_SVC_CIDR}
scheduler: {}
---
apiVersion: kubeadm.k8s.io/$(
    [[ $K8S_VER =~ ^1.(1[5-9]|2[0-5]) ]] && echo "v1beta2"; exit; }
)
kind: ${node_type}
nodeRegistration:
  name: ${node_name}
  kubeletExtraArgs:
    root-dir: ${KUBELET_LIB}

$(
    if [[ -n ${K8S_EXTRA_ARGS}  ]]; then
        cat << EOFF
    ${K8S_EXTRA_ARGS}
EOFF
    fi
)
EOF
        highlight "$node_name: init bcsenv"
}

_on_baremetal () {
    log "NOT on cloud"
    [[ -n $LAN_IP ]] || LAN_IP=$(ip -4 o route get 10/8 | sed -n 's/.*src \([0-9.]\+\).*/\1/p')
    _init_kubenv
}

_init_kubenv () {
    highlight "Add envfile"
    # shellcheck disable=SC1091
    [[ ${cluster_env} == "null"]] || source <(echo "${cluster_env}" | base64 -d)
    [[ -n ${MIRROR_URL}  ]] || MIRROR_URL=${mirror_url}
    # local LAN_IP="$1"
    # local MIRROR_URL="$2"
    cat > "$KUBE_DIR/kube.env" << EOF
# kube config begin for $ON_CLOUD
ON_CLOUD="${ON_CLOUD}"
KUBE_DIR="${KUBE_DIR}"
KUBE_HOME="${KUBE_HOME}"
kube_sysctl="${kube_sysctl}"
MIRROR_IP="${MIRROR_IP}"
MIRROR_URL="${MIRROR_URL}"
REPO_URL="${REPO_URL}"
DOCKER_LIB="${DOCKER_LIB}"
DOCKER_VERSION="${DOCKER_VERSION}"
DOCKER_LIVE_RESTORE="${DOCKER_LIVE_RESTORE}"
DOCKER_BRIDGE="${DOCKER_BRIDGE}"
PUBLIC_REPO="${PUBLIC_REPO}"
RELEASE_REPO="${RELEASE_REPO}"
KUBELET_LIB="${KUBELET_LIB}"
K8S_VER="${K8S_VER}"
K8S_SVC_CIDR="${K8S_SVC_CIDR}"
K8S_POD_CIDR="${K8S_POD_CIDR}"
K8S_EXTRA_ARGS="${K8S_EXTRA_ARGS}"
ETCD_LIB="${ETCD_LIB}"
LAN_IP="${LAN_IP}"
K8S_CTRL_IP="${K8S_CTRL_IP:-$LAN_IP}"
# kube config end for $ON_CLOUD
EOF
    sed -ri "/kube config begin for $ON_CLOUD/,/kube config end for $ON_CLOUD/d" "$HOME/.bashrc"
    cat >> "$HOME/.bashrc" << EOF
# kube config begin for $ON_CLOUD
source "${KUBE_DIR}/kube.env"
# kube config end for $ON_CLOUD
EOF
# shellcheck disable=SC1091
    source "${KUBE_DIR}/kube.env"
}

_add_sysctl () { 
    # shellcheck diable=SC1091
    source /etc/os-release

    [[ ${kube_sysctl} == "1" ]] || return 0
    highlight "Add sysctl"
    TOTAL_MEM=$(free -b | awk 'NR==2{print $2}')
    TOTAL_MEM=${TOTAL_MEM:-$(( 16 * 1024 * 1024 *1024 ))}
    PAGE_SIZE=$(getconf PAGE_SIZE)
    PAGE_SIZE=${PAGE_SIZE:-4096}
    THREAD_SIZE=$(( PAGE_SIZE << 2 ))
    sed -ri.kube.bak '/kube config begin/,/kube config end/d' /etc/sysctl.conf
    cat >> "/etc/sysctl.conf" << EOF
# kube config begin
# 系统中每一个端口最大的监听队列的长度,这是个全局的参数,默认值128太小
net.core.somaxconn=32768
# 大量短连接时，开启TIME-WAIT端口复用
net.ipv4.tcp_tw_reuse=1
# TCP半连接队列长度。值太小的话容易造成高并发时客户端连接请求被拒绝
net.ipv4.tcp_max_syn_backlog=8096
# RPS是将内核网络rx方向报文处理的软中断分配到合适CPU核，以提升网络应用整体性能的技术。这个参数设置RPS flow table大小
fs.inotify.max_user_instances=8192
# inotify watch总数量限制。调大该参数避免"Too many open files"错误
fs.inotify.max_user_watches=524288
# 使用bpf需要开启
net.core.bpf_jit_enable=1
# 使用bpf需要开启
net.core.bpf_jit_harden=1
# 使用bpf需要开启
net.core.bpf_jit_kallsyms=1
# 用于调节rx软中断周期中内核可以从驱动队列获取的最大报文数，以每CPU为基础有效，计算公式(dev_weight * dev_weight_tx_bias)。主要用于调节网络栈和CPU在tx上的不对称
net.core.dev_weight_tx_bias=1
# socket receive buffer大小
net.core.rmem_max=16777216
# RPS是将内核网络rx方向报文处理的软中断分配到合适CPU核，以提升网络应用整体性能的技术。这个参数设置RPS flow table大小
net.core.rps_sock_flow_entries=8192
# socket send buffer大小
net.core.wmem_max=16777216
# 避免"neighbor table overflow"错误(发生过真实客户案例，触发场景为节点数量超过1024，并且某应用需要跟所有节点通信)
net.ipv4.neigh.default.gc_thresh1=2048
# 同上
net.ipv4.neigh.default.gc_thresh2=8192
# 同上
net.ipv4.neigh.default.gc_thresh3=16384
# orphan socket是应用以及close但TCP栈还没有释放的socket（不包含TIME_WAIT和CLOSE_WAIT）。 适当调大此参数避免负载高时报'Out of socket memory'错误。32768跟友商一致。
net.ipv4.tcp_max_orphans=32768
# 代理程序(如nginx)容易产生大量TIME_WAIT状态的socket。适当调大这个参数避免"TCP: time wait bucket table overflow"错误。
net.ipv4.tcp_max_tw_buckets=16384
# TCP socket receive buffer大小。 太小会造成TCP连接throughput降低
net.ipv4.tcp_rmem=4096 12582912 16777216
# TCP socket send buffer大小。 太小会造成TCP连接throughput降低
net.ipv4.tcp_wmem=4096 12582912 16777216
# 控制每个进程的内存地址空间中 virtual memory area的数量
vm.max_map_count=262144
# 为了支持k8s service, 必须开启
net.ipv4.ip_forward=1
# ubuntu系统上这个参数缺省为"/usr/share/apport/apport %p %s %c %P"。在容器中会造成无法生成core文件
kernel.core_pattern=core
# 内核在发生死锁或者死循环的时候可以触发panic,默认值是0.
kernel.softlockup_panic=0
# 使得iptable可以作用在网桥上
net.bridge.bridge-nf-call-ip6tables=1
net.bridge.bridge-nf-call-iptables=1
# 系统全局PID号数值的限制。
kernel.pid_max=$(( 4 * 1024 * 1024))
# 系统进程描述符总数量限制，根据内存大小动态计算得出，TOTAL_MEM为系统的内存总量，单位是字节，THREAD_SIZE默认为16，单位是kb。
kernel.threads-max=$((TOTAL_MEM / (8 * THREAD_SIZE) ))
# 整个系统fd（包括socket）的总数量限制。根据内存大小动态计算得出，TOTAL_MEM为系统的内存总量，单位是字节，调大该参数避免"Too many open files"错误。
fs.file-max=$(( TOTAL_MEM / 10240 ))
# kube config end
EOF
    sysctl --system
    # ulimit 
    cat > /etc/security/limit.d/99-kube.conf << EOF
# kube config begin
*   soft  nproc    1028546
*   hard  nproc    1028546
*   soft  nofile    204800
*   hard  nofile    204800
# kube config end
EOF
}

_add_hosts () { 
    [[ ${MIRROR_IP} != "null"]] || return 0
    highlight "Add hosts"
    sed -ri.kube.bak '/kube config begin for kube/,/kube config end for kube/d' /etc/hosts
    cat >> "/etc/hosts" << EOF
# kube config begin for kube 
$(
    if [[ -n ${MIRROR_IP} ]]; then
        echo "${MIRROR_IP} registry.kxdigit.com docker.kxdigit.com" 
    fi
)
# kube config end for kube
EOF
}

### docker runtime: Docker

install_docker () {
    
    if docker info &>/dev/null && [[ -d ${DOCKER_LIB}  ]];then
    warning "Already installed, skipping"
    return 0
    fi


}