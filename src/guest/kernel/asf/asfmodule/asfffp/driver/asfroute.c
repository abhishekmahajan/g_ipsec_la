/**************************************************************************
 * Copyright 2010-2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfroute.c
 *
 * Description: Some route/arp helper functions taken from Linux
 *
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 */
/*
 * History
 * 25 Feb 2014 - Subha: Initial Implemenatation: All routines based on Linux
 * routing routines
 *
 */
/******************************************************************************/
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/if_vlan.h>
#include <linux/if_bridge.h>
#include <linux/if_arp.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#include <asm/io.h>
#include <asm/irq.h>
#include <asm/uaccess.h>
#include <linux/module.h>
#include <linux/dma-mapping.h>
#include <linux/crc32.h>
#include <linux/mii.h>
#include <linux/phy.h>
#include <linux/phy_fixed.h>
#include <net/xfrm.h>
#include <linux/sysctl.h>
#include "asf.h"
#include "asfcmn.h"
#include "asfroute.h"

struct fib_nh_exception *asf_find_exception(struct fib_nh *nh, __be32 daddr)
{
	struct fnhe_hash_bucket *hash;
	struct fib_nh_exception *fnhe;
	u32 hval;

	asf_debug("asf_find_exception: nh = 0x%p\n", nh); 

	if (nh == NULL)
	{
		asf_debug("nh = NULL, return NULL\n");
		return NULL;
	}

	hash = nh->nh_exceptions;

	if (!hash)
		return NULL;

	hval = asf_fnhe_hashfun(daddr);

	for (fnhe = rcu_dereference(hash[hval].chain); fnhe;
	     fnhe = rcu_dereference(fnhe->fnhe_next)) {
		if (fnhe->fnhe_daddr == daddr)
			return fnhe;
	}
	return NULL;
}
EXPORT_SYMBOL(asf_find_exception);

static struct dst_entry *asf_ipv4_blackhole_dst_check(struct dst_entry *dst, u32 cookie)
{
	return NULL;
}

static unsigned int asf_ipv4_blackhole_mtu(const struct dst_entry *dst)
{
	unsigned int mtu = dst_metric_raw(dst, RTAX_MTU);

	return mtu ? : dst->dev->mtu;
}

static void asf_ipv4_rt_blackhole_update_pmtu(struct dst_entry *dst, struct sock *sk,
					  struct sk_buff *skb, u32 mtu)
{
}

static void asf_ipv4_rt_blackhole_redirect(struct dst_entry *dst, struct sock *sk,
				       struct sk_buff *skb)
{
}

static u32 *asf_ipv4_rt_blackhole_cow_metrics(struct dst_entry *dst,
					  ULONG old)
{
	return NULL;
}

static unsigned int asf_ipv4_default_advmss(const struct dst_entry *dst)
{
	return 0;
}

static struct neighbour *asf_neigh_lookup(const struct dst_entry *dst, 
	struct sk_buff *skb, 
	const void *daddr)
{
	struct net_device *dev = dst->dev;
	const __be32 *pkey = daddr;
	const struct rtable *rt;
	struct neighbour *n;

	rt = (const struct rtable *) dst;
	if (rt->rt_gateway)
		pkey = (const __be32 *) &rt->rt_gateway;
	else if (skb)
		pkey = &ip_hdr(skb)->daddr;

	n = __ipv4_neigh_lookup(dev, *(__force u32 *)pkey);
	if (n)
		return n;
	return neigh_create(&arp_tbl, pkey, dev);
}


struct dst_ops asf_ipv4_dst_blackhole_ops = {
	.family			=	AF_INET,
	.protocol		=	cpu_to_be16(ETH_P_IP),
	.check			=	asf_ipv4_blackhole_dst_check,
	.mtu			=	asf_ipv4_blackhole_mtu,
	.default_advmss		=	asf_ipv4_default_advmss,
	.update_pmtu		=	asf_ipv4_rt_blackhole_update_pmtu,
	.redirect		=	asf_ipv4_rt_blackhole_redirect,
	.cow_metrics		=	asf_ipv4_rt_blackhole_cow_metrics,
	.neigh_lookup		=	asf_neigh_lookup,
};
EXPORT_SYMBOL(asf_ipv4_dst_blackhole_ops);

struct rtable *asf_rt_dst_alloc(struct net_device *dev,
				   bool nopolicy, bool noxfrm, bool will_cache)
{
	printk("In asf_rt_dst_alloc\n");
	return dst_alloc(&asf_ipv4_dst_blackhole_ops, dev, 1, DST_OBSOLETE_FORCE_CHK,
			 (will_cache ? 0 : (DST_HOST | DST_NOCACHE)) |
			 (nopolicy ? DST_NOPOLICY : 0) |
			 (noxfrm ? DST_NOXFRM : 0));
}
EXPORT_SYMBOL(asf_rt_dst_alloc);

void fnhe_flush_routes(struct fib_nh_exception *fnhe)
{
	struct rtable *rt;

	rt = rcu_dereference(fnhe->fnhe_rth_input);
	if (rt) {
		RCU_INIT_POINTER(fnhe->fnhe_rth_input, NULL);
		asf_rt_free(rt);
	}
	rt = rcu_dereference(fnhe->fnhe_rth_output);
	if (rt) {
		RCU_INIT_POINTER(fnhe->fnhe_rth_output, NULL);
		asf_rt_free(rt);
	}
}
EXPORT_SYMBOL(fnhe_flush_routes);
void fill_route_from_fnhe(struct rtable *rt, struct fib_nh_exception *fnhe)
{
	rt->rt_pmtu = fnhe->fnhe_pmtu;
	rt->dst.expires = fnhe->fnhe_expires;

	if (fnhe->fnhe_gw) {
		rt->rt_flags |= RTCF_REDIRECTED;
		rt->rt_gateway = fnhe->fnhe_gw;
		rt->rt_uses_gateway = 1;
	}
}
EXPORT_SYMBOL(fill_route_from_fnhe);

#ifdef CONFIG_IP_ROUTE_CLASSID
void set_class_tag(struct rtable *rt, u32 tag)
{
	if (!(rt->dst.tclassid & 0xFFFF))
		rt->dst.tclassid |= tag & 0xFFFF;
	if (!(rt->dst.tclassid & 0xFFFF0000))
		rt->dst.tclassid |= tag & 0xFFFF0000;
}
EXPORT_SYMBOL(set_class_tag);
#endif
