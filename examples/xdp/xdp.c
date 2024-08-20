//go:build ignore

#include "bpf_endian.h"
// #include "common.h"
//  #include <linux/bpf.h>
#include "uapi/linux/bpf.h"
// #include <linux/udp.h>
//  #include <linux/ip.h>
//  #include <linux/bpf.h>
typedef __u32 __wsum;

#include <bpf/bpf_helpers.h>
//  #include "../headers/bpf_helper_defs.h"
//   #include <unistd.h>
//   #include <netinet/in.h>
//   #include <ctype.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 16
#define DNS_PORT 53
#define LOCAL_DNS_IP 0x0100007F // 127.0.0.1 in hex
#define LOCAL_DNS_PORT 8000

/* Define an LRU hash map for storing packet count by source IPv4 address */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32); // source IPv4 address
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(value, __u32); // packet count
} xdp_stats_map SEC(".maps");

// struct bpf_map_def SEC("maps") pkt_count = {
// 	.type        = BPF_MAP_TYPE_ARRAY,
// 	.key_size    = sizeof(u32),
// 	.value_size  = sizeof(u64),
// 	.max_entries = 1,
// };

/*
Attempt to parse the IPv4 source address from the packet.
Returns 0 if there is no IPv4 header field; otherwise returns non-zero.
*/
// static __always_inline int parse_ip_src_addr(struct xdp_md *ctx, __u32 *ip_src_addr) {
// 	void *data_end = (void *)(long)ctx->data_end;
// 	void *data     = (void *)(long)ctx->data;

// 	// First, parse the ethernet header.
// 	struct ethhdr *eth = data;
// 	if ((void *)(eth + 1) > data_end) {
// 		return 1;
// 	}

// 	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
// 		// The protocol is not IPv4, so we can't parse an IPv4 source address.
// 		return 1;
// 	}

// 	// Then parse the IP header.
// 	struct iphdr *ip = (void *)(eth + 1);
// 	if ((void *)(ip + 1) > data_end) {
// 		return 1;
// 	}

// 	// Return the source IP address in network byte order.
// 	*ip_src_addr = (__u32)(ip->saddr);
// 	return 1;
// }

// SEC("xdp")
// int xdp_prog_func(struct xdp_md *ctx) {
// 	__u32 ip;
// 	if (!parse_ip_src_addr(ctx, &ip)) {
// 		// Not an IPv4 packet, so don't count it.
// 		goto done;
// 	}

// 	__u32 *pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &ip);
// 	if (!pkt_count) {
// 		// No entry in the map for this IP address yet, so set the initial value to 1.
// 		__u32 init_pkt_count = 1;
// 		bpf_map_update_elem(&xdp_stats_map, &ip, &init_pkt_count, BPF_ANY);
// 	} else {
// 		// Entry already exists for this IP address,
// 		// so increment it atomically using an LLVM built-in.
// 		__sync_fetch_and_add(pkt_count, 1);
// 	}

// done:
// 	// Try changing this to XDP_DROP and see what happens!
// 	return XDP_PASS;
// }

SEC("cgroup/recvmsg4")
int xdp_prog_func(struct bpf_sock_addr *ctx) {
	// void *data         = (void *)(long)ctx->data;
	// void *data_end     = (void *)(long)ctx->data_end;
	// struct ethhdr *eth = data;
	// struct iphdr *ip   = (data + sizeof(struct ethhdr));
	// struct udphdr *udp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

	// // return early if not enough data
	// // if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end) {
	// if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
	// 	// if (udp->dest == 13568 || udp->dest == 53) {
	// 	// 	// print dest
	// 	// 	bpf_printk("dst port: %d, got a dns request packet but returning early\n", udp->dest);
	// 	// }
	// 	// return XDP_PASS;
	// 	return 1;
	// }
	__u32 ip = bpf_htonl(ctx->user_ip4);

	bpf_printk("ip %pI4,   port: %d", &ip, bpf_htons(ctx->user_port));

	if (bpf_htons(ctx->user_port) != 53) {
		return 1;
	}
	bpf_printk("ip %pI4,   port: %d, got a dns request packet", &ip, bpf_htons(ctx->user_port));
	__u32 *key = &(ctx->user_ip4);

	__u32 *pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &key);
	if (!pkt_count) {
		// No entry in the map for this IP address yet, so set the initial value to 1.
		__u32 init_pkt_count = 1;
		bpf_map_update_elem(&xdp_stats_map, &key, &init_pkt_count, BPF_ANY);
	} else {
		// Entry already exists for this IP address,
		// so increment it atomically using an LLVM built-in.
		__sync_fetch_and_add(pkt_count, 1);
	}

	// pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &ip->saddr);
	// if (!pkt_count) {
	// 	// No entry in the map for this IP address yet, so set the initial value to 1.
	// 	__u32 init_pkt_count = 1;
	// 	bpf_map_update_elem(&xdp_stats_map, &ip->saddr, &init_pkt_count, BPF_ANY);
	// } else {
	// 	// Entry already exists for this IP address,
	// 	// so increment it atomically using an LLVM built-in.
	// 	__sync_fetch_and_add(pkt_count, 1);
	// }
	// bpf_printk("filled map\n");

	// if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end) {
	// 	// if (udp->dest == 13568 || udp->dest == 53) {
	// 	// 	// print dest
	// 	// 	bpf_printk("dst port: %d, got a dns request packet but returning early\n", udp->dest);
	// 	// }
	// 	return 1; // XDP_PASS;
	// }
	// // We only care about UDP packets
	// // if (iph->protocol != IPPROTO_UDP)
	// if (ip->protocol != 17)
	// 	return 1; // XDP_PASS;

	// bpf_printk("got a udp packet....\n");

	// UDP Header
	// struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
	// if ((void *)(udph + 1) > data_end) {
	// 	bpf_printk("data end, returning\n");
	// 	return XDP_PASS;
	// }
	// bpf_printk("got a udp packet\n");

	// We only care about DNS packets (port 53)
	// if (udp->dest != 13568) {
	// 	// print dest
	// 	return 1; // XDP_PASS;
	// }
	// bpf_printk("dst port: %d\n", udp->dest);
	// bpf_printk("got a dns request packet\n");

	// // if (udp->source == 13568 || udp->source == 53) {
	// // 	// print dest
	// // 	bpf_printk("src port: %d\n", udp->dest);
	// // 	bpf_printk("got a dns response packet\n");
	// // }

	// // DNS Packet: Skip UDP header
	// unsigned char *dns_payload = (unsigned char *)(udp + 1);
	// // if ((void *)(dns_payload + 12) > data_end) { // Basic DNS header length
	// // 	return XDP_PASS;
	// // }

	// // Parse the DNS query (we'll keep this simple for demo purposes)
	// unsigned char *dns_name = dns_payload + 12; // DNS query starts after header
	// char dns_name_str[256];
	// int i = 0;

	// while (dns_name < (unsigned char *)data_end && *dns_name != 0 && i < sizeof(dns_name_str) - 1) {
	// 	if (*dns_name < 32 || *dns_name >= 127) // Handle non-printable characters
	// 		break;
	// 	dns_name_str[i++] = *dns_name++;
	// }
	// dns_name_str[i] = '\0'; // Null-terminate the string
	// bpf_printk("dns_name_str %s\n", dns_name_str);

	// // Print DNS name (requires a helper like bpf_trace_printk)
	// // bpf_trace_printk("DNS Query: %s\n", dns_name_str);

	// // Redirect the packet by changing IP and port
	// // ip->daddr = bpf_htonl(LOCAL_DNS_IP); // Change destination IP to 127.0.0.1
	// udp->dest = bpf_htons(LOCAL_DNS_PORT); // Change destination port to 8080
	// // udp->dest = 8000; // Change destination port to 8080

	// Redirect the packet
	return 1; // XDP_PASS; // Use XDP_TX to transmit the modified packet out of the interface
}
