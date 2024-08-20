//go:build ignore

// #include "common.h"
#include "bpf_endian.h"
// #include "common.h"
//  #include <linux/bpf.h>
#include "uapi/linux/bpf.h"
typedef __u16 __sum16;
typedef __u16 u16;
#include <linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/in.h> // Add this line to include the necessary header file
#include <bcc/proto.h>

typedef __u8 u8;
typedef __u32 __wsum;
enum tc_action { TC_ACT_UNSPEC = -1, TC_ACT_OK = 0, TC_ACT_RECLASSIFY = 1, TC_ACT_SHOT = 2, TC_ACT_PIPE = 3, TC_ACT_STOLEN = 4, TC_ACT_QUEUED = 5, TC_ACT_REPEAT = 6, TC_ACT_REDIRECT = 7, TC_ACT_JUMP = 0x10000000 };

#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct dns_hdr_t {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} BPF_PACKET_HEADER;

struct dns_char_t {
	char c;
} BPF_PACKET_HEADER;

#define A_RECORD_TYPE 0x0001
#define DNS_CLASS_IN 0x0001
// RFC1034: the total number of octets that represent a domain name is limited to 255.
// We need to be aligned so the struct does not include padding bytes. We'll set the length to 256.
// Otherwise padding bytes will generate problems with the verifier, as it ?could contain arbitrary data from memory?
#define MAX_DNS_NAME_LENGTH 256

struct dns_hdr {
	uint16_t transaction_id;
	uint8_t rd : 1; // Recursion desired
	uint8_t tc : 1; // Truncated
	uint8_t aa : 1; // Authoritive answer
	uint8_t opcode : 4; // Opcode
	uint8_t qr : 1; // Query/response flag
	uint8_t rcode : 4; // Response code
	uint8_t cd : 1; // Checking disabled
	uint8_t ad : 1; // Authenticated data
	uint8_t z : 1; // Z reserved bit
	uint8_t ra : 1; // Recursion available
	uint16_t q_count; // Number of questions
	uint16_t ans_count; // Number of answer RRs
	uint16_t auth_count; // Number of authority RRs
	uint16_t add_count; // Number of resource RRs
};

// Used as value of our A record hashmap
struct dns_server {
	struct in_addr ip_addr;
	uint16_t port;
};

// Used as key in our hashmap
struct dns_query {
	uint16_t record_type;
	uint16_t class;
	char name[MAX_DNS_NAME_LENGTH];
};

struct bpf_map_def SEC("maps") query_redirection_config = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(struct dns_query),
	.value_size  = sizeof(struct dns_server),
	.max_entries = 65536,
};

static inline void update_ip_checksum(void *data, int len, uint16_t *checksum_location) {
	uint32_t accumulator = 0;
	int i;
#pragma unroll
	for (i = 0; i < len; i += 2) {
		uint16_t val;
		// If we are currently at the checksum_location, set to zero
		if (data + i == checksum_location) {
			val = 0;
		} else {
			// Else we load two bytes of data into val
			val = *(uint16_t *)(data + i);
		}
		accumulator += val;
	}

	// Add 16 bits overflow back to accumulator (if necessary)
	uint16_t overflow = accumulator >> 16;
	accumulator &= 0x00FFFF;
	accumulator += overflow;

	// If this resulted in an overflow again, do the same (if necessary)
	accumulator += (accumulator >> 16);
	accumulator &= 0x00FFFF;

	// Invert bits and set the checksum at checksum_location
	uint16_t chk = accumulator ^ 0xFFFF;

	bpf_printk("IP Checksum: %u", chk);

	*checksum_location = chk;
}

SEC("tc")
int egress_prog_func(struct __sk_buff *ctx) {
	// int ret = bpf_skb_pull_data(ctx, ctx->len);
	// if (ret < 0) {
	// 	bpf_printk("Error: unable to pull data");
	// 	return 1;
	// }
	void *data         = (void *)(long)ctx->data;
	void *data_end     = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *ip   = (data + sizeof(struct ethhdr));
	struct udphdr *udp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
		return TC_ACT_OK;
	}

	__u32 destip = bpf_htonl(ip->daddr);
	// return early if not enough data
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end) {
		return TC_ACT_OK;
	}
	if (udp->dest == bpf_htons(53)) {
		bpf_printk("remote %pI4,  port: %d, ctx len: %d", &destip, bpf_htons(udp->dest), ctx->len);
		// Boundary check for minimal DNS header
		if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(struct dns_hdr) > data_end) {
			return TC_ACT_OK;
		}
		struct dns_hdr_t *dns_hdr = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
		uint16_t flags            = bpf_ntohs(dns_hdr->flags);
		bpf_printk("dns flags : %x, AR count: %d, nscount: %d", bpf_ntohs(dns_hdr->flags), bpf_ntohs(dns_hdr->arcount), bpf_ntohs(dns_hdr->nscount));
		if ((flags & 0x8000) == 0) {
			// Check if header contains a standard query
			bpf_printk("udp len: %d, DNS query transaction id %u, ques count: %d", bpf_ntohs(udp->len), bpf_ntohs(dns_hdr->id), bpf_ntohs(dns_hdr->qdcount));

			if (bpf_ntohs(dns_hdr->qdcount) != 1) {
				return TC_ACT_OK;
			}
			void *cursor = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(struct dns_hdr);
			if (cursor + 1 > data_end) {
				return TC_ACT_OK;
			}

			// // We will only be parsing a single query for now
			struct dns_query q;
			__u8 query_length = 0;
			// print data_end
			bpf_printk("data_end: %p", data_end);

			struct dns_char_t *c;
			int namepos = 0;
			// Fill dns_query.name with zero bytes
			// Not doing so will make the verifier complain when dns_query is used as a key in bpf_map_lookup
			q.class       = 0;
			q.record_type = 0;
			memset(&q.name[0], 0, sizeof(q.name));

#pragma unroll
			for (int j = 0; j < 255; j++) {
				if (cursor + 1 > data_end) {
					bpf_printk("Error: boundary exceeded while parsing DNS query name");
					return TC_ACT_OK;
				}
				// bpf_printk("%d. Cursor(%p) contents in hex: %x", j + 1, cursor, *(char *)cursor);
				c = cursor;
				if (c->c == 0) {
					// bpf_printk("q name: %s", q.name);
					break;
					// return TC_ACT_OK;
				}
				if (namepos != 0) {
					if (c->c < '!' || c->c > '~') {
						q.name[namepos - 1] = '.';
					} else {
						bpf_printk("namepos: %d, c->c: %c", namepos, c->c);
						q.name[namepos - 1] = c->c;
					}
					query_length++;
				}
				namepos++;
				cursor++;
			}
			q.name[namepos] = '\0';
			bpf_printk("q name: %s", q.name);

			// lookup the query in the hashmap
			struct dns_server *dns_server = bpf_map_lookup_elem(&query_redirection_config, &q);
			if (dns_server) {
				bpf_printk("DNS query matched in hashmap. Redirecting to %pI4:%d", &dns_server->ip_addr, dns_server->port);
				// ip->daddr = bpf_htonl(dns_server->ip_addr.s_addr);
				ip->daddr = bpf_htonl(0x23e07e1b);
				udp->dest = bpf_htons(53);
				// Set UDP checksum to zero
				udp->check = 0;
				// Recalculate IP checksum
				update_ip_checksum(ip, sizeof(struct iphdr), &ip->check);
				if (cursor + 2 < data_end) {
					cursor++;
					q.record_type = bpf_ntohs(*(uint16_t *)(cursor));
					bpf_printk("class: %x", q.record_type);
				}
				return TC_ACT_OK;
			} else {
				bpf_printk("DNS query not matched in hashmap");
			}
		}
		return TC_ACT_OK;
	}

	return TC_ACT_OK;
}
