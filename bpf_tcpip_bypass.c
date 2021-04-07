#include <uapi/linux/bpf.h>

#include "bpf_sockops.h"



/* extract the key that identifies the destination socket in the sock_ops_map */
static inline
void sk_msg_extract4_key(struct sk_msg_md *msg,
	struct sock_key *key)
{
	key->sip4 = msg->remote_ip4;
	key->dip4 = msg->local_ip4;
	key->family = 1;

	key->dport = FORCE_READ(msg->local_port);
	key->sport = bpf_ntohl(msg->remote_port);
}

/*
 * refactor the socket key of Outbound traffic
 */
static inline
void sk_msg_extract4_out_key(struct bpf_sock_ops *ops,
                         struct sock_key *key)
{
    // keep ip and port in network byte order
    key->sip4 = 0x100007f;
    key->dip4 = ops->local_ip4;
    key->family = 1;

    // local_port is in host byte order, and
    // remote_port is in network byte order
    key->dport = FORCE_READ(ops->local_port);
    //#define FORCE_READ(X) (*(volatile typeof(X)*)&X)
    key->sport = 15001;
}

__section("sk_msg")
int bpf_tcpip_bypass(struct sk_msg_md *msg)
{
    struct  sock_key key = {};

    //refactor the key of Inbound traffic
    if (skops->local_ip4 == 0x100007f && skops->remote_ip4 ==0x100007f){
        if (skops->local_port == 9080 || bpf_ntohl(skops->remote_port) == 9080){
            sk_msg_extract4_key(msg, &key);
        }
    }

    //refactor the key of Outbound traffic
    if (podip_verify(msg->local_ip4)){
        sk_msg_extract4_out_key(msg, &key);
    }

    msg_redirect_hash(msg, &sock_ops_map, &key, BPF_F_INGRESS);
    printk("socket has redirected local_port:%d--->remote_port:\n",
           key.dport, key.sport);

    return SK_PASS;
}

char ____license[] __section("license") = "GPL";
