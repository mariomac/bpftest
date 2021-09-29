#define KBUILD_MODNAME "netdump"

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

struct ip_event
{
    uint32_t saddr;
    uint32_t daddr;
    uint8_t protocol;
    uint16_t sport;
    uint16_t dport;
} __attribute__((packed));

BPF_PERF_OUTPUT(ip_events);

int inspect_network(struct xdp_md *ctx)
{
    bpf_trace_printk("packet received\n");
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)eth + sizeof(*eth) <= data_end)
    {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)ip + sizeof(*ip) <= data_end)
        {
            struct ip_event ipe;
            ipe.saddr = htonl(ip->saddr);
            ipe.daddr = htonl(ip->daddr);
            ipe.protocol = ip->protocol;

            switch (ip->protocol)
            {
            case IPPROTO_TCP:
            {
                struct tcphdr *tcp = (void *)ip + sizeof(*ip);
                if ((void *)tcp + sizeof(*tcp) <= data_end)
                {
                    ipe.sport = htons(tcp->source);
                    ipe.dport = htons(tcp->dest);
                }
            }
            break;
            case IPPROTO_UDP:
            {
                struct udphdr *udp = (void *)ip + sizeof(*ip);
                if ((void *)udp + sizeof(*udp) <= data_end)
                {
                    ipe.sport = htons(udp->source);
                    ipe.dport = htons(udp->dest);
                }
            }
            break;
            default:
                break;
            }

            ip_events.perf_submit(ctx, &ipe, sizeof(ipe));
        }
    }
    return XDP_PASS;
}
