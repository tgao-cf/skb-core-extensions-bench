// SPDX-License-Identifier: GPL-2.0
/* XDP programs for the skb core extensions bench. Each one passes every
 * packet that does not come from the sender, so the rest of the host traffic
 * is unchanged. The store kfuncs are weak and every call checks that the
 * kfunc exists.
 */
#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Same names as the kernel enums, so libbpf finds the kfunc prototypes compatible */
enum xdp_rss_hash_type { XDP_RSS_TYPE_NONE };
enum xdp_checksum { XDP_CHECKSUM_NONE = 1 };

extern int bpf_xdp_metadata_rx_hash(const struct xdp_md *ctx, __u32 *hash,
				    enum xdp_rss_hash_type *rss_type) __ksym;
extern int bpf_xdp_metadata_rx_vlan_tag(const struct xdp_md *ctx,
					__be16 *vlan_proto, __u16 *vlan_tci) __ksym;
/* From Lorenzo Bianconi's RX checksum kfunc series */
extern int bpf_xdp_metadata_rx_checksum(const struct xdp_md *ctx,
					enum xdp_checksum *ip_summed,
					__u32 *cksum, __u8 *cksum_level) __ksym __weak;
extern int bpf_xdp_skb_ext_store_rx_vlan(struct xdp_md *ctx, __be16 vlan_proto,
					 __u16 vlan_tci) __ksym __weak;
extern int bpf_xdp_skb_ext_store_rx_hash(struct xdp_md *ctx, __u32 hash,
					 enum xdp_rss_hash_type rss_type) __ksym __weak;
extern int bpf_xdp_skb_ext_store_rx_csum(struct xdp_md *ctx,
					 enum xdp_checksum ip_summed,
					 __u8 csum_level) __ksym __weak;

enum { CFG_SENDER, CFG_IFINDEX, CFG_CPU, CFG_STORE, CFG_NUM };
enum { ST_PKTS, ST_ERR, ST_NUM };

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, CFG_NUM);
	__type(key, __u32);
	__type(value, __u32);
} cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, ST_NUM);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_CPUMAP);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, struct bpf_cpumap_val);
} cpu_map SEC(".maps");

static __always_inline __u32 cfg_get(__u32 k)
{
	__u32 *v = bpf_map_lookup_elem(&cfg, &k);

	return v ? *v : 0;
}

static __always_inline void count(__u32 k)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &k);

	if (v)
		(*v)++;
}

static __always_inline bool from_sender(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *iph = data + sizeof(*eth);

	if ((void *)(iph + 1) > end || eth->h_proto != bpf_htons(ETH_P_IP))
		return false;
	return iph->saddr == cfg_get(CFG_SENDER);
}

/* CFG_STORE 1: read the checksum status from the NIC and store it */
SEC("xdp")
int xdp_veth(struct xdp_md *ctx)
{
	enum xdp_checksum ip_summed;
	__u32 cksum;
	__u8 level;

	if (!from_sender(ctx))
		return XDP_PASS;
	count(ST_PKTS);
	if (cfg_get(CFG_STORE) && bpf_ksym_exists(bpf_xdp_metadata_rx_checksum) &&
	    bpf_ksym_exists(bpf_xdp_skb_ext_store_rx_csum) &&
	    (bpf_xdp_metadata_rx_checksum(ctx, &ip_summed, &cksum, &level) ||
	     bpf_xdp_skb_ext_store_rx_csum(ctx, ip_summed, level)))
		count(ST_ERR);
	return bpf_redirect(cfg_get(CFG_IFINDEX), 0);
}

/* The NIC strips the VLAN tag of the test network into the RX descriptor.
 * Both variants store it, so the skb reaches the VLAN device that holds the
 * receiver address. CFG_STORE 1: also read the RX hash and store it.
 */
SEC("xdp")
int xdp_cpumap(struct xdp_md *ctx)
{
	enum xdp_rss_hash_type type;
	__be16 proto;
	__u16 tci;
	__u32 hash;

	if (!from_sender(ctx))
		return XDP_PASS;
	count(ST_PKTS);

	if (!bpf_ksym_exists(bpf_xdp_skb_ext_store_rx_vlan))
		return XDP_PASS;

	if (!bpf_xdp_metadata_rx_vlan_tag(ctx, &proto, &tci) &&
	    bpf_xdp_skb_ext_store_rx_vlan(ctx, proto, tci))
		count(ST_ERR);

	if (cfg_get(CFG_STORE) && bpf_ksym_exists(bpf_xdp_skb_ext_store_rx_hash) &&
	    (bpf_xdp_metadata_rx_hash(ctx, &hash, &type) ||
	     bpf_xdp_skb_ext_store_rx_hash(ctx, hash, type)))
		count(ST_ERR);

	return bpf_redirect_map(&cpu_map, cfg_get(CFG_CPU), 0);
}

char _license[] SEC("license") = "GPL";
