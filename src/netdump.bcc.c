#define KBUILD_MODNAME "netdump"

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct ip_event
{
    uint32_t saddr;
    uint32_t daddr;
    uint8_t protocol;
    uint16_t length;
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
            ipe.length = ip->tot_len;

            ip_events.perf_submit(ctx, &ipe, sizeof(ipe));

            /*
            if (ip->protocol == IPPROTO_UDP)
            {

                struct udphdr *udp = (void *)ip + sizeof(*ip);
                if ((void *)udp + sizeof(*udp) <= data_end)
                {
                    struct udphdr *udp = (void *)ip + sizeof(*ip);
                    if ((void *)udp + sizeof(*udp) <= data_end)
                    {
                        u64 value = htons(udp->dest);
                        counter.increment(value);
                    }
                }
            }
            */
        }
    }
    return XDP_PASS;
}
