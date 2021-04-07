#include <uapi/linux/bpf.h>
#include "bpf_sockops.h"

/*
 * extract the key identifying the socket source of the TCP event 
 */
static inline
void sk_extractv_in_key(struct bpf_sock_ops *ops,
	struct sock_key *key)
{
	// keep ip and port in network byte order
	key->dip4 = ops->remote_ip4;
	key->sip4 = ops->local_ip4;
	key->family = 1;
	
	// local_port is in host byte order, and 
	// remote_port is in network byte order
	key->sport = FORCE_READ(ops->local_port);
	//#define FORCE_READ(X) (*(volatile typeof(X)*)&X)
	key->dport = bpf_htonl(ops->remote_port);
}

/*
 * refactor the socket key of Outbound traffic
 */
static inline
void sk_extractv_out_key(struct bpf_sock_ops *ops,
                        struct sock_key *key)
{
    // keep ip and port in network byte order
    key->dip4 = 0x100007f;
    key->sip4 = ops->local_ip4;
    key->family = 1;

    // local_port is in host byte order, and
    // remote_port is in network byte order
    key->sport = FORCE_READ(ops->local_port);
    key->dport = 15001;
}

/*
 * extract the key of Inbound traffic
 */
static inline
void inboound_sock_ops_ipv4(struct bpf_sock_ops *skops)
{
	struct sock_key key = {};
	
	sk_extractv_in_key(skops, &key);

	// insert the source socket in the sock_ops_map
	int ret = sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);

	if (ret != 0) {
		printk("FAILED: sock_hash_update ret: %d\n", ret);
	} else{
        printk("SUCCESS! inbound sock_hash_update! local_port:%d--->remote_port:%d\n",
               key.sport, key.dport);
	}
}

/*
 * extract the key of Outbound traffic
 */
static inline
void outboound_sock_ops_ipv4(struct bpf_sock_ops *skops)
{
    struct sock_key key = {};

    sk_extractv_out_key(skops, &key);

    // insert the source socket in the sock_ops_map
    int ret = sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);

    if (ret != 0) {
        printk("FAILED: sock_hash_update ret: %d\n", ret);
    } else{
        printk("SUCCESS! outbound sock_hash_update! local_port:%d--->remote_port:%d\n",
               key.sport, key.dport);
    }
}

__section("sockops")

int bpf_sockops_v4(struct bpf_sock_ops *skops)
{
	uint32_t family, op;

	family = skops->family;
	op = skops->op;

	switch (op) {
	    //listen the statement of socket, SYK&&ACK
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		if (family == 2) { //AF_INET
		    //Inbound traffic
            if (skops->local_ip4 == 0x100007f && skops->remote_ip4 == 0x100007f){
                if (skops->local_port == 9080 || bpf_ntohl(skops->remote_port) == 9080){
                    inboound_sock_ops_ipv4(skops);
                }
            }
            //Outbound traffic, two cases: svc_pod send endpoint && envoy_listen endpoint
            //iptables,send endpoint
            if (podip_verify(skops->local_ip4) && bpf_ntohl(skops->remote_port) == 9080){
                outboound_sock_ops_ipv4(skops);
            }
            //normal,envoy_listen endpoint
            if (skops->local_ip4 == 0x100007f && skops->local_port == 15001){
                inboound_sock_ops_ipv4(skops);
            }
            //pod to pod in same host
            if (skops->local == 15006){
                inboound_sock_ops_ipv4(skops);
            }
		}
                break;
        default:
                break;
        }
	return 0;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
