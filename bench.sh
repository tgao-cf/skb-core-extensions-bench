#!/bin/bash
# Bench for the skb core extensions series.
#
# Two hosts on one link. The sender sends, the receiver receives. An XDP
# program on the receiver's ice NIC takes every IPv4 packet from the sender
# and either stores RX metadata with the series' kfuncs or does not ("store"
# 1 or 0). The rest of the host traffic passes unchanged.
#
# Tests:
#   veth-tcp    One TCP flow (netperf). XDP redirects it into a veth pair. The
#               receiver runs in a network namespace behind the pair. Store 1
#               reads the checksum status from the NIC and stores it.
#   cpumap-tcp  $FLOWS TCP flows (iperf3). XDP redirects them to one cpumap
#               CPU, and the host receives them. Store 1 stores the RX hash.
#
# Each round runs the client for $DUR seconds. After 5 seconds the receiver
# samples for $WIN seconds: MSR cycle counts (perf stat) and a profile (perf
# record) of the RX CPU and the cpumap CPU. The XDP packet count, NIC and SNMP
# counters are read just before and after, with a timestamp each. Rounds
# alternate the store variants. report.py reads the files.
#
# Usage, on the receiver. build runs as a normal user, run and test as root:
#   bench.sh build <series-patch-dir>
#       build the kernel in $KSRC, install it with sudo
#   bench.sh run <results-dir>
#       both tests: veth-checksum/ and cpumap-rx-hash/
#   bench.sh test <out-dir> <test> [rounds]
#       host settings, then one test. rounds 0: set up, then wait for Ctrl-C
# Environment: DUR (20), WIN (10), FLOWS (16)
set -euo pipefail
cd "$(dirname "$0")"

# Hosts, CPUs and tools. Set them here or in the environment.
RECV_IF=${RECV_IF:-eth0}		# NIC under test, XDP is attached here
RECV_VLAN_DEV=${RECV_VLAN_DEV:-}	# device that holds RECV_IP, if not RECV_IF. Its DHCP lease is renewed before each round
RECV_IP=${RECV_IP:-192.0.2.1}
SENDER=${SENDER:-sender}		# ssh name of the sender, in root's ssh config
SENDER_IF=${SENDER_IF:-eth0}		# recorded in state.txt
SENDER_IP=${SENDER_IP:-192.0.2.2}
RX_CPU=${RX_CPU:-98}			# IRQ of RX queue 0: XDP, and veth NAPI for veth-tcp
CPUMAP_CPU=${CPUMAP_CPU:-100}
APP_CPUS=${APP_CPUS:-102}		# netserver and the iperf3 server
KSRC=${KSRC:-/usr/src/linux}		# kernel tree, built by "bench.sh build"
CLANG=${CLANG:-clang-22}
BPFTOOL=${BPFTOOL:-$KSRC/tools/testing/selftests/bpf/tools/sbin/bpftool}

# The base commit plus the series and Lorenzo Bianconi's RX checksum patches
# 1-3, the Debian 13 kernel config (package linux-image-6.12.111+deb13-amd64)
# and the selftest config fragments. selftests/bpf gives the bpftool.
build() {
	local patches series=()
	local base=0fb18ce8a2e9de830433923cf65838933d615359
	local config=/boot/config-6.12.111+deb13-amd64
	[ -d "${1:-}" ] || { echo "series patch dir missing: ${1:-}" >&2; exit 1; }
	patches=$(realpath "$1")
	[ -f $config ] || { echo "missing $config" >&2; exit 1; }

	[ -e $KSRC/.git ] || { git init -q $KSRC; git -C $KSRC fetch -q --depth 1 \
		https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git $base; }
	local patch=$PWD/lorenzo-rx-checksum-v5-1-3.patch
	cd $KSRC
	git checkout -q --detach $base
	for f in "$patches"/00*.patch; do
		[[ $f = */0000-cover-letter.patch ]] || series+=("$f")
	done
	git -c user.name=bench -c user.email=bench@localhost am -q "${series[@]}" $patch
	echo "tree $(git rev-parse 'HEAD^{tree}')"

	cp $config .config
	# The bpf fragment goes last: where it and the net fragment differ, it sets =y.
	scripts/kconfig/merge_config.sh -m .config tools/testing/selftests/net/config \
		tools/testing/selftests/drivers/net/hw/config tools/testing/selftests/bpf/config
	# Put back what the net fragment turns off, drop Debian's signing keys.
	scripts/config -e DEBUG_INFO_BTF_MODULES -m VETH --set-str SYSTEM_TRUSTED_KEYS "" \
		--set-str SYSTEM_REVOCATION_KEYS "" --set-str LOCALVERSION -skbext-v1-rxcsum -d LOCALVERSION_AUTO
	make olddefconfig
	make -j"$(nproc)"
	sudo make INSTALL_MOD_STRIP=1 modules_install install
	make headers
	make -j"$(nproc)" -C tools/testing/selftests/bpf SKIP_DOCS=1 \
		CLANG=$CLANG LLC=llc-22 LLVM_STRIP=llvm-strip-22 LLVM_OBJCOPY=llvm-objcopy-22
	echo "installed $(make -s kernelrelease)"
}

# Host settings. Each changes only if it differs, because a ring change resets
# the NIC link.
sysconf() {
	for g in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor; do
		[ "$(cat $g)" = performance ] || echo performance > $g
	done
	local b=/sys/devices/system/cpu/cpufreq/boost
	[ ! -e $b ] || [ "$(cat $b)" = 1 ] || echo 1 > $b
	# irqbalance would move the IRQ of queue 0 away from RX_CPU
	! systemctl is-active -q irqbalance || systemctl stop irqbalance
	ring() { ethtool -g $RECV_IF | sed -n '/Current/,$p' | awk -v k="$1:" '$1 == k { print $2 }'; }
	[ "$(ring RX) $(ring TX)" = "2048 256" ] || ethtool -G $RECV_IF rx 2048 tx 256
	ethtool -c $RECV_IF | grep -q '^Adaptive RX: on' || ethtool -C $RECV_IF adaptive-rx on
	for f in rx-checksumming generic-receive-offload rx-vlan-offload receive-hashing; do
		ethtool -k $RECV_IF | grep -q "^$f: on" || { echo "$f is off on $RECV_IF" >&2; exit 1; }
	done
}

# Both tests. A test that fails does not stop the other.
run_all() {	# results-dir
	local b
	b=./$(basename "$0")
	$b test $1/veth-checksum veth-tcp 5 || echo "failed: veth-tcp" >&2
	FLOWS=16 $b test $1/cpumap-rx-hash cpumap-tcp 5 || echo "failed: cpumap-tcp" >&2
}

case ${1:-} in
build)	shift; build "$@"; exit ;;
run)	shift; run_all "$@"; exit ;;
test)	shift ;;
*)	sed -n '/^# Usage/,/^# Environment/p' "$0" >&2; exit 1 ;;
esac

OUT=$1
TEST=$2
ROUNDS=${3:-5}
DUR=${DUR:-20}
WIN=${WIN:-10}
FLOWS=${FLOWS:-16}
PIN=/sys/fs/bpf/skbext

# Keys of the cfg map, as in bench.bpf.c
CFG_SENDER=0
CFG_IFINDEX=1
CFG_CPU=2
CFG_STORE=3

DIR=$OUT/$TEST
[ $TEST != cpumap-tcp ] || DIR=$OUT/$TEST-$FLOWS
mkdir -p $DIR

RECV_MAC=$(cat /sys/class/net/$RECV_IF/address)
RECV_IRQ=$(awk -v n="ice-$RECV_IF-TxRx-0" '$NF == n { sub(":", "", $1); print $1 }' /proc/interrupts)
[ -n "$RECV_IRQ" ] || { echo "no IRQ ice-$RECV_IF-TxRx-0" >&2; exit 1; }

sender() {
	ssh -o BatchMode=yes $SENDER "$@"
}

# A 32-bit value as the 4 bytes bpftool expects, little endian
u32() {
	echo $(($1 & 255)) $(($1 >> 8 & 255)) $(($1 >> 16 & 255)) $(($1 >> 24 & 255))
}

set_cfg() {	# key, value as bytes
	$BPFTOOL map update pinned $PIN/maps/cfg key $(u32 $1) value $2
}

# Remove host names, addresses and home paths from what goes into the results
scrub() {
	sed -E -e "s/${RECV_IP//./\\.}/RECV_IP/g" -e "s/${SENDER_IP//./\\.}/SENDER_IP/g" \
		-e "s/$(hostname)/RECEIVER/g" -e "s/$SENDER_HOST/SENDER/g" \
		-e 's/([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}/MAC/g' -e 's#/home/[^/ ]+#~#g'
}

record_state() {
	echo "## receiver"
	uname -rv
	lscpu | grep -E "^Model name|^CPU\(s\)|^Thread|^NUMA node\(s\)"
	ethtool -i $RECV_IF | grep -E "^(driver|version|firmware-version):"
	lspci -s "$(ethtool -i $RECV_IF | awk '/bus-info/ { print $2 }')" | cut -d' ' -f2-
	echo "numa_node $(cat /sys/class/net/$RECV_IF/device/numa_node)" \
		"rx_cpu $RX_CPU cpumap_cpu $CPUMAP_CPU app_cpus $APP_CPUS"
	sed -E 's/(BOOT_IMAGE|root)=[^ ]* ?//g' /proc/cmdline
	echo "governor $(cat /sys/devices/system/cpu/cpu$RX_CPU/cpufreq/scaling_governor)" \
		"boost $(cat /sys/devices/system/cpu/cpufreq/boost)"
	echo "irqbalance $(systemctl is-active irqbalance || true)"
	ethtool -k $RECV_IF | grep -E "^(rx-checksumming|generic-receive-offload|rx-vlan-offload|receive-hashing):"
	ethtool -g $RECV_IF | sed -n '/Current/,$p' | grep -E "^(RX|TX):"
	ethtool -c $RECV_IF | grep -E "^(Adaptive|rx-usecs):"
	echo "## sender"
	sender "uname -rv; lscpu | grep '^Model name'; /usr/sbin/ethtool -i $SENDER_IF | grep -E '^(driver|firmware-version):'"
}

build_prog() {
	[ bench.bpf.o -nt bench.bpf.c ] && return
	$CLANG -O2 -g --target=bpf -I$KSRC/usr/include \
		-I$KSRC/tools/testing/selftests/bpf/tools/include \
		-c bench.bpf.c -o bench.bpf.o
}

load_prog() {
	rm -rf $PIN
	$BPFTOOL prog loadall bench.bpf.o $PIN type xdp xdpmeta_dev $RECV_IF pinmaps $PIN/maps
	set_cfg $CFG_SENDER "${SENDER_IP//./ }"	# network byte order
	set_cfg $CFG_CPU "$(u32 $CPUMAP_CPU)"
	set_cfg $CFG_STORE "$(u32 0)"
	# cpumap entry: queue size 2048, no program
	$BPFTOOL map update pinned $PIN/maps/cpu_map key $(u32 $CPUMAP_CPU) value $(u32 2048) 0 0 0 0
}

# The namespace holds the receiver address and veth1 holds the NIC's MAC, so the
# redirected frames need no rewrite. Replies go out through veth0 and the host,
# with the receiver address as source; accept_local and rp_filter 0 let the host
# forward them.
setup_veth() {
	ip netns add svc
	ip link add veth0 type veth peer name veth1 netns svc
	ip -n svc link set veth1 address $RECV_MAC
	sysctl -qw net.ipv6.conf.veth0.disable_ipv6=1
	ip netns exec svc sysctl -qw net.ipv6.conf.all.disable_ipv6=1

	ip addr add 10.0.2.1/24 dev veth0
	ip link set veth0 up
	ip -n svc link set lo up
	ip -n svc addr add 10.0.2.2/24 dev veth1
	ip -n svc addr add $RECV_IP/32 dev veth1
	ip -n svc link set veth1 up
	ip -n svc route replace default via 10.0.2.1 src $RECV_IP
	sysctl -qw net.ipv4.conf.veth0.accept_local=1 net.ipv4.conf.veth0.rp_filter=0 \
		net.ipv4.conf.veth0.forwarding=1

	# GRO turns on NAPI on veth1, which veth0 needs to take XDP frames
	ip netns exec svc ethtool -K veth1 gro on
	set_cfg $CFG_IFINDEX "$(u32 $(cat /sys/class/net/veth0/ifindex))"
	ip netns exec svc taskset -c $APP_CPUS netserver -L $RECV_IP > /dev/null
}

setup() {
	ethtool -X $RECV_IF equal 1	# every flow to RX queue 0
	echo $RX_CPU > /proc/irq/$RECV_IRQ/smp_affinity_list
	build_prog
	load_prog

	case $TEST in
	veth-tcp)
		setup_veth
		PROG=xdp_veth
		;;
	cpumap-tcp)
		PROG=xdp_cpumap
		;;
	esac

	$BPFTOOL net attach xdpdrv pinned $PIN/$PROG dev $RECV_IF overwrite
	# The NIC resets its rings on attach. Wait until the sender reaches the receiver again.
	for i in $(seq 30); do
		sender "ping -c 1 -W 1 $RECV_IP" > /dev/null && break
		sleep 1
	done
}

teardown() {
	set +e
	$BPFTOOL net detach xdpdrv dev $RECV_IF
	rm -rf $PIN
	ethtool -X $RECV_IF default
	ip netns pids svc 2> /dev/null | xargs -r kill
	ip netns del svc 2> /dev/null
}

run_client() {	# on the sender, for $DUR seconds
	case $TEST in
	veth-tcp)
		sender "netperf -H $RECV_IP -t TCP_STREAM -l $DUR -P 0"
		;;
	cpumap-tcp)
		sender "iperf3 -c $RECV_IP -P $FLOWS -t $DUR -J"
		;;
	esac
}

# Packets and store errors the XDP program counted, summed over CPUs
xdp_stats() {
	$BPFTOOL map dump pinned $PIN/maps/stats -j | python3 -c '
import json, sys

def value(v):	# a number, or little-endian bytes as hex strings
    return v if isinstance(v, int) else int.from_bytes(bytes(int(b, 16) for b in v), "little")

entries = json.load(sys.stdin)
print(" ".join(str(sum(value(c["value"]) for c in e["values"])) for e in entries))'
}

nic_stats() {
	ethtool -S $RECV_IF | grep -E " (rx_csum_bad\.nic|rx_dropped\.nic|rx_dropped):"
}

measure_round() {	# round, store
	local f=$DIR/store$2-r$1
	local in_ns=""
	[ $TEST != veth-tcp ] || in_ns="ip netns exec svc"

	set_cfg $CFG_STORE "$(u32 $2)"
	if [ -n "${RECV_VLAN_DEV:-}" ]; then	# a fresh DHCP lease, while the link is quiet
		networkctl renew $RECV_VLAN_DEV
		sleep 3
	fi
	if [ $TEST = cpumap-tcp ]; then
		taskset -c $APP_CPUS iperf3 -s -1 -B $RECV_IP > /dev/null &
		sleep 1
	fi

	run_client > $f.client 2>&1 &
	local client=$!
	sleep 5

	local t_before xdp_before nic_before
	t_before=$(date +%s%N)
	xdp_before=$(xdp_stats)
	nic_before=$(nic_stats)
	$in_ns nstat -n
	perf record -q -C $RX_CPU,$CPUMAP_CPU -F 4999 -o $f.perf.data -- sleep $WIN 2> /dev/null &
	local prof=$!
	perf stat -x, -A -C $RX_CPU,$CPUMAP_CPU -e msr/aperf/,msr/mperf/,msr/tsc/ -- sleep $WIN 2> $f.msr
	wait $prof || true
	local t_after=$(date +%s%N)
	{
		echo "time_before $t_before"
		echo "time_after $t_after"
		echo "stats_before $xdp_before"
		echo "stats_after $(xdp_stats)"
		echo "$nic_before" | sed 's/^/nic_before /'
		nic_stats | sed 's/^/nic_after /'
		$in_ns nstat -z | sed 's/^/nstat /'
	} > $f.counters
	wait $client || true

	{
		perf report -i $f.perf.data --stdio --no-children --sort cpu,sym --percent-limit 0.01
		perf report -i $f.perf.data --stdio --sort cpu | sed 's/^/cpu_total /'
	} 2> /dev/null | grep -v -e '^#' -e '^cpu_total #' | grep . > $f.perf.txt
	rm -f $f.perf.data

	for x in client counters perf.txt msr; do
		scrub < $f.$x > $f.$x.tmp
		mv $f.$x.tmp $f.$x
	done
	echo "$(basename $DIR) round $1 store $2: $(tail -c 200 $f.client | tr '\n' ' ' | cut -c1-100)"
}

sysconf
SENDER_HOST=$(sender hostname)
[ -f $OUT/state.txt ] || record_state 2>&1 | scrub > $OUT/state.txt
trap teardown EXIT
setup
if [ $ROUNDS = 0 ]; then
	echo "set up, Ctrl-C tears it down"
	sleep infinity
fi
for r in $(seq $ROUNDS); do
	for s in 0 1; do
		measure_round $r $s
	done
done
