#include <swab.h>

#ifndef __section
#define __section(NAME) 	\
	__attribute__((section(NAME), used))
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define __bpf_ntohl(x)                 __builtin_bswap32(x)
# define __bpf_htonl(x)                 __builtin_bswap32(x)
# define __bpf_constant_ntohl(x)        ___constant_swab32(x)
# define __bpf_constant_htonl(x)        ___constant_swab32(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# define __bpf_ntohl(x)                 (x)
# define __bpf_htonl(x)                 (x)
# define __bpf_constant_ntohl(x)        (x)
# define __bpf_constant_htonl(x)        (x)
#else
# error "Check the compiler's endian detection."
#endif

//__builtin_constant_p 是编译器gcc内置函数，用于判断一个值是否为编译时常量，如果是常数，函数返回1 ，否则返回0。
#define bpf_htonl(x)                            \
        (__builtin_constant_p(x) ?              \
         __bpf_constant_htonl(x) : __bpf_htonl(x))
#define bpf_ntohl(x)                            \
        (__builtin_constant_p(x) ?              \
         __bpf_constant_ntohl(x) : __bpf_ntohl(x))

#ifndef FORCE_READ
#define FORCE_READ(X) (*(volatile typeof(X)*)&X)
#endif

#ifndef BPF_FUNC
#define BPF_FUNC(NAME, ...) 	\
	(*NAME)(__VA_ARGS__) = (void *) BPF_FUNC_##NAME
#endif

#ifndef printk
# define printk(fmt, ...)                                      \
    ({                                                         \
        char ____fmt[] = fmt;                                  \
        trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })
#endif


#define pod_productpage_ip_1 0x5400f40a
#define pod_productpage_ip_2 0x5500f40a
#define pod_productpage_ip_3 0x5600f40a

#define pod_details_ip_1 0x4900f40a
#define pod_details_ip_2 0x4a00f40a
#define pod_details_ip_3 0x4b00f40a

#define pod_reviews_v3_ip_1 0x5100f40a
#define pod_reviews_v3_ip_2 0x5200f40a
#define pod_reviews_v3_ip_3 0x5300f40a

#define pod_rating_ip_1 0x4c00f40a
#define pod_rating_ip_2 0x4f00f40a
#define pod_rating_ip_3 0x5000f40a

/* ebpf helper function
 * The generated function is used for parameter verification
 * by the eBPF verifier
 */
static int BPF_FUNC(msg_redirect_hash, struct sk_msg_md *md,
			void *map, void *key, uint64_t flag);
static int BPF_FUNC(sock_hash_update, struct bpf_sock_ops *skops,
			void *map, void *key, uint64_t flags);
static void BPF_FUNC(trace_printk, const char *fmt, int fmt_size, ...);

/*
 * Map definition
 */
struct bpf_map_def {
	uint32_t type;
	uint32_t key_size;
	uint32_t value_size;
	uint32_t max_entries;
	uint32_t map_flags;
};

struct sock_key {
	uint32_t sip4;
	uint32_t dip4;
	uint8_t  family;
	uint8_t  pad1;
	uint16_t pad2;
	// this padding required for 64bit alignment
	// else ebpf kernel verifier rejects
	// loading of the program
	uint32_t pad3;
	uint32_t sport;
	uint32_t dport;
} __attribute__((packed));


struct bpf_map_def __section("maps") sock_ops_map = {
	.type           = BPF_MAP_TYPE_SOCKHASH,
	.key_size       = sizeof(struct sock_key),
	.value_size     = sizeof(int),
	.max_entries    = 65535,
	.map_flags      = 0,
};

//struct bpf_map_def __section("maps") pod_ips_map ={
//    .type           = BPF_MAP_TYPE_ARRAY,
//    .key_size       = sizeof(int),
//    .value_size     = sizeof(int),
//    .max_entries    = 20,
//    .map_flags      = 0,
//};

/*
 *verify the pod ip exits
 */
static inline
int podip_verify(uint32_t local_ip)
{
    if (local_ip == pod_productpage_ip_1 ||
        local_ip == pod_productpage_ip_2 ||
        local_ip == pod_productpage_ip_3 ||
        local_ip == pod_details_ip_1 ||
        local_ip == pod_details_ip_2 ||
        local_ip == pod_details_ip_3 ||
        local_ip == pod_rating_ip_1 ||
        local_ip == pod_rating_ip_2 ||
        local_ip == pod_rating_ip_3 ||
        local_ip == pod_reviews_v3_ip_1 ||
        local_ip == pod_reviews_v3_ip_2 ||
        local_ip == pod_reviews_v3_ip_3
        ){
        return 1;
    }
    return 0;
}
