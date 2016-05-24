/**************************************************************************
 * Copyright 2010-2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfroute.h
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
#ifndef _ASF_ROUTE_H
#define _ASF_ROUTE_H

#include <net/arp.h>
#include <net/ip_fib.h>
#include <net/route.h>
#include <linux/inetdevice.h>

struct rtable *asf_rt_dst_alloc(struct net_device *dev,
				   bool nopolicy, bool noxfrm, bool will_cache);
void fnhe_flush_routes(struct fib_nh_exception *fnhe);
void fill_route_from_fnhe(struct rtable *rt, struct fib_nh_exception *fnhe);
#ifdef CONFIG_IP_ROUTE_CLASSID
void set_class_tag(struct rtable *rt, u32 tag);
#endif

struct fib_nh_exception *asf_find_exception(struct fib_nh *nh, __be32 daddr);
struct _ipv4
{
    struct flowi4 fl;
    struct fib_result res;
    struct rtable *rth;
    struct neighbour *n;
};


static inline int asf_arp_resolve(
	struct _ipv4 *ipv4, ASFBuffer_t *abuf, ASF_IPv4Addr_t ulDestIp)
{
	struct neighbour *neigh;
	int res;
	ASF_IPv4Addr_t	nexthop; /* Destination IP Address */

	nexthop = (ipv4->rth->rt_gateway) ? ipv4->rth->rt_gateway : ulDestIp;

	asf_debug("asf_arp_resolve: ipv4->rth_rt_gateway=0x%x\n", nexthop);
	rcu_read_lock_bh();
	ipv4->n = __ipv4_neigh_lookup(ipv4->rth->dst.dev, nexthop);
	if (unlikely(!(ipv4->n)))
	{
		asf_debug("ipv4->n = 0x%p  Calling neigh_create\n", (ipv4->n));
		neigh = __neigh_create(&arp_tbl, &nexthop,  ipv4->rth->dst.dev, false);
		asf_debug("neigh_create returned 0x%p\n", neigh);
		if (!IS_ERR(neigh))
		{
			dst_hold(&(ipv4->rth->dst));
			skb_dst_set(abuf->nativeBuffer, &ipv4->rth->dst);
			res = dst_neigh_output(&ipv4->rth->dst, neigh, abuf->nativeBuffer);
			asf_debug("dst_neigh_output returned %d\n", res);
			if (res == 0)
			{
				asf_debug("Stack will handle the transmit\n");
				rcu_read_unlock_bh();
				return 2;
			}
		}
		asf_debug("IS_ERR neigh true\n");
		rcu_read_unlock_bh();
		return -1;
	}

	rcu_read_unlock_bh();
	return 0;
}


/* Loosely based on Linux IP ip_fib.h */

#ifndef CONFIG_IP_MULTIPLE_TABLES
static inline int asf_fib_lookup(
    ASFNetDevEntry_t *anDev, 
    struct _ipv4 *ipv4, 
    struct sk_buff *skb, 
    ASF_int8_t tos)
{
	struct fib_table *table;
	struct net *net;
	struct flowi4 *f1 = &(ipv4->fl4);
	struct fib_result *res = &(ipv4->res);

	if (likely(anDev->ulDevType == ASF_IFACE_TYPE_ETHER))
	{
		net = dev_net(anDev->ndev);

		/* first time fib_lookup is done for this flow, so fl parameters have to be filled */  
		if unlikely(!(fl->flowi4_iif))
		{
			fl->flowi4_iif = anDev->ndev->ifindex;
			fl->flowi4_mark = skb->mark;
			fl->flowi4_tos = tos;
		}

/* Not needed I think - Currently; Need to revisit 
		table = fib_get_table(net, RT_TABLE_LOCAL);
		if (!fib_table_lookup(table, flp, &ipv4->res, 0))
			return 0;
*/

		table = fib_get_table(net, RT_TABLE_MAIN);
		if (!fib_table_lookup(table, flp, res, 0))
		{
			return 0;
		}

		return -ENETUNREACH;
	}
}

#else /* CONFIG_IP_MULTIPLE_TABLES */
/* Need to have this definition */
struct fib4_rule {
	struct fib_rule common;
	u8 	dst_len;
	u8	src_len;
	u8 	tos;
	__be32	src;
	__be32	srcmask;
	__be32  dst;
	__be32	dstmask;
#ifdef CONFIG_IP_ROUTE_CLASSID
	u32	tclassid;
#endif
};

static inline int __asf_fib_lookup(struct net *net, struct flowi4 *flp, struct fib_result *res)
{
	struct fib_lookup_arg arg = {
		.result = res,
		.flags = 0,
	};
	int err;

	err = fib_rules_lookup(net->ipv4.rules_ops, flowi4_to_flowi(flp), 0, &arg);
#ifdef CONFIG_IP_ROUTE_CLASSID
	if (arg.rule)
		res->tclassid = ((struct fib4_rule *)arg.rule)->tclassid;
	else
		res->tclassid = 0;
#endif
	return err;
}
static inline int asf_fib_lookup(ASFNetDevEntry_t *anDev, 
    struct _ipv4 *ipv4, struct sk_buff *skb, ASF_uint8_t tos)
{
	//struct fib_table *table;
	struct net *net;
	struct flowi4 *fl = &(ipv4->fl);
	struct fib_result *res = &(ipv4->res);

	asf_debug("In asf_fib_lookup\n");

	if (likely(anDev->ulDevType == ASF_IFACE_TYPE_ETHER))
	{
		net = dev_net(anDev->ndev);

		/* first time fib_lookup is done for this flow, so fl parameters have to be filled */  
		if (unlikely(!(fl->flowi4_iif)))
		{
			fl->flowi4_iif = anDev->ndev->ifindex;
			fl->flowi4_mark = skb->mark;
			fl->flowi4_tos = tos;
		}

		if (!net->ipv4.fib_has_custom_rules) {
			res->tclassid = 0;
			if (net->ipv4.fib_local &&
		    !fib_table_lookup(net->ipv4.fib_local, fl, res,
				      0))
				return 0;
		if (net->ipv4.fib_main &&
		    !fib_table_lookup(net->ipv4.fib_main, fl, res,
				      0))
			return 0;
		if (net->ipv4.fib_default &&
		    !fib_table_lookup(net->ipv4.fib_default, fl, res,
				      0))
			return 0;
		return -ENETUNREACH;
		}
		return(__asf_fib_lookup(net, fl, &ipv4->res));
	}
	return -ENETUNREACH;
}
#endif /* CONFIG_IP_MULTIPLE_TABLES */
static inline u32 asf_fnhe_hashfun(__be32 daddr)
{
	u32 hval;

	hval = (__force u32) daddr;
	hval ^= (hval >> 11) ^ (hval >> 22);

	return hval & (FNHE_HASH_SIZE - 1);
}


static inline bool rt_is_expired(const struct rtable *rth)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 19, 0)
	return rth->rt_genid != rt_genid(dev_net(rth->dst.dev));
#else
	return rth->rt_genid != rt_genid_ipv4(dev_net(rth->dst.dev));
#endif
}

static inline bool asf_rt_cache_valid(const struct rtable *rt)
{
	return	rt &&
		rt->dst.obsolete == DST_OBSOLETE_FORCE_CHK &&
		!rt_is_expired(rt);
}

static inline void asf_rt_free(struct rtable *rt)
{
	call_rcu(&rt->dst.rcu_head, dst_rcu_free);
}



static inline int asf_route_resolve(ASFNetDevEntry_t *inputDev, 
   struct _ipv4 *ipv4, ASFBuffer_t *abuf, 
   ASF_IPv4Addr_t ulDestIp,
   ASF_uint8_t tos)
{
	int ret;
	struct fib_result *res = &(ipv4->res);
	struct fib_nh_exception *fnhe;
	unsigned int itag;
	bool do_cache, cached;

	cached = false;
	fnhe = NULL;

	rcu_read_lock();

	if (!(ret =asf_fib_lookup(inputDev, ipv4, abuf->nativeBuffer, tos)))
	{
		asf_debug("asf_fib_lookup completed res->fi = 0x%p\n", res->fi);
		if (res->fi)
		{
			//struct fib_nh *nh;
#ifdef  CONFIG_IP_ROUTE_MULTIPATH
			/*
			if (res->fi->fib_nhs > 1)
				fib_select_multipath(&(flow->ipv4.res));
			*/
#endif
			asf_debug("asf_route_resolve: 1\n");
			fib_combine_itag(&itag, &(ipv4->res));
			do_cache = ipv4->res.fi && !itag;

			asf_debug("asf_route_resolve: 2\n");
			if (do_cache)
			{
				asf_debug("asf_route_resolve: 3 0x%p \n", &FIB_RES_NH(ipv4->res));
				fnhe = asf_find_exception(&FIB_RES_NH(ipv4->res),ulDestIp);
				if (fnhe != NULL)
					ipv4->rth = rcu_dereference(fnhe->fnhe_rth_input);
				else
					ipv4->rth = rcu_dereference(FIB_RES_NH(ipv4->res).nh_rth_input);

				if ((ipv4->rth) && ((asf_rt_cache_valid(ipv4->rth))))
					dst_hold(&(ipv4->rth->dst));
				else
				{
					ipv4->rth = NULL;
					fnhe = NULL;
				}

			}

			asf_debug("asf_route_resolve: 4\n");

			if (!(ipv4->rth))
			{
				asf_debug("flow->ipv4.rth invalid: Need to allocate for route\n");

				asf_debug("asf_route_resolve: 5\n");

				ipv4->rth = asf_rt_dst_alloc(FIB_RES_DEV(ipv4->res),  
					IN_DEV_CONF_GET(__in_dev_get_rcu(inputDev->ndev), NOPOLICY),
					IN_DEV_CONF_GET(__in_dev_get_rcu(FIB_RES_DEV(ipv4->res)), NOXFRM), do_cache);

				if (!ipv4->rth)
				{
					asf_debug("Error in allocating rt_dst\n");
					rcu_read_unlock();
					return -1;
				}
				asf_debug("asf_route_resolve: 6\n");


#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 19, 0)
				ipv4->rth->rt_genid = rt_genid(dev_net(ipv4->rth->dst.dev));
#else
				ipv4->rth->rt_genid = rt_genid_ipv4(dev_net(ipv4->rth->dst.dev));
#endif
				ipv4->rth->rt_flags = 0 ;
				ipv4->rth->rt_type = res->type;
				ipv4->rth->rt_is_input = 1;
				ipv4->rth->rt_iif 	= 0;
				ipv4->rth->rt_pmtu	= 0;
				ipv4->rth->rt_gateway	= 0;
				ipv4->rth->rt_uses_gateway = 0;
				INIT_LIST_HEAD(&ipv4->rth->rt_uncached);

				/* Find next hop */
				asf_debug("asf_route_resolve: 7\n");
				{
					struct fib_nh *nh = &FIB_RES_NH(ipv4->res);

					if (nh->nh_gw && nh->nh_scope == RT_SCOPE_LINK)
					{
						ipv4->rth->rt_gateway = nh->nh_gw;
						ipv4->rth->rt_uses_gateway = 1;
					}
					dst_init_metrics(&ipv4->rth->dst, res->fi->fib_metrics, true);
#ifdef CONFIG_IP_ROUTE_CLASSID
					ipv4->rth->dst.tclassid = nh->nh_tclassid;
#endif
					if (!ipv4->rth->rt_gateway)
						ipv4->rth->rt_gateway = ulDestIp;

				}
#ifdef CONFIG_IP_ROUTE_CLASSID
#ifdef CONFIG_IP_MULTIPLE_TABLES
				set_class_tag(ipv4->rth, res->tclassid);
#endif
				set_class_tag(ipv4->rth, itag);
#endif
			}
		
			rcu_read_unlock();
			return 0;
		}
		asf_debug("fi invalid\n");
	}
	asf_debug("asf_fib_lookup returned error\n");
	rcu_read_unlock();
	return -1;
}

#endif
