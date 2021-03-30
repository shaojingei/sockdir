#include <uapi/linux/bpf.h>
#include "bpf_sockops.h"


/*
 * extract the key identifying the socket source of the TCP event 
 */
static inline
void sk_extractv4_key(struct bpf_sock_ops *ops,
	struct sock_key *key)
{
	// keep ip and port in network byte order
	key->dip4 = ops->remote_ip4;
	key->sip4 = ops->local_ip4;
	key->family = 1;
	
	// local_port is in host byte order, and 
	// remote_port is in network byte order
	key->sport = (bpf_htonl(ops->local_port) >> 16);
	//#define FORCE_READ(X) (*(volatile typeof(X)*)&X)
	key->dport = FORCE_READ(ops->remote_port) >> 16;
}

static inline
void bpf_sock_ops_test(struct bpf_sock_ops *skops)
{
    struct sock_key = {};

    sk_extractv4_key(skops, &key);

    printk("<<< local_ip:port %d:%d ---> remote_ip:port %d:%d\n",
           bpf_ntohl(skops->local_ip4), skops->local_port);

    printk("<<< ---> remote_ip:port %d:%d\n", bpf_ntohl(skops->remote_ip4), bpf_ntohl(skops->remote_port));

}

__section("sockops")

int bpf_sockops_v4(struct bpf_sock_ops *skops)
{
	uint32_t family, op;

	family = skops->family;
	op = skops->op;

	switch (op) {
	    //在链接被动建立时
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		if (family == 2) { //AF_INET
                        bpf_sock_ops_test(skops);
		}
                break;
        default:
                break;
        }
	return 0;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
