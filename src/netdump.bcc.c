#define KBUILD_MODNAME "netdump"

#include "../elf/include/bpf_map.h"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#define SEC(NAME) __attribute__((section(NAME), used))

#define PERF_MAX_STACK_DEPTH 127

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define bpf_perf_event_output perf_event_output

struct ip_event
{
    __u32 saddr;
    __u32 daddr;
    __u8 protocol;
    __u16 length;
    __u16 sport;
    __u16 dport;
} __attribute__((packed));

struct bpf_map_def SEC("maps/ip_events") ip_events = {
    .type = BPF_MAP_TYPE_QUEUE,
    .key_size = 0,
    .value_size = sizeof(struct ip_event),
    .max_entries = 1024,
};

SEC("xdp/inspect_network")
int inspect_network(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)eth + sizeof(*eth) <= data_end)
    {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)ip + sizeof(*ip) <= data_end)
        {
            struct ip_event ipe;
            ipe.saddr = ip->saddr;
            ipe.daddr = ip->daddr;
            ipe.protocol = ip->protocol;

            switch (ip->protocol)
            {
            case IPPROTO_TCP:
            {
                struct tcphdr *tcp = (void *)ip + sizeof(*ip);
                if ((void *)tcp + sizeof(*tcp) <= data_end)
                {
                    ipe.sport = tcp->source;
                    ipe.dport = tcp->dest;
                }
            }
            break;
            case IPPROTO_UDP:
            {
                struct udphdr *udp = (void *)ip + sizeof(*ip);
                if ((void *)udp + sizeof(*udp) <= data_end)
                {
                    ipe.sport = udp->source;
                    ipe.dport = udp->dest;
                }
            }
            break;
            default:
                break;
            }

            bpf_perf_event_output(ctx, &ip_events, 0, &ipe, sizeof(struct ip_event));
        }
    }
    return XDP_PASS;
}
