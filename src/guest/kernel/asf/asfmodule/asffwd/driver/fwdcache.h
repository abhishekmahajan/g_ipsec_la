/**************************************************************************
 * Copyright 2010-2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asffwd.h
 *
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 * History:
 */
#ifndef _FWD_CACHE_H
#define _FWD_CACHE_H
#define ASF_FWD_MAX_FLOWS	(128*1024)
#define ASF_FWD_MAX_HASH_BKT	(ASF_FWD_MAX_FLOWS/16)


typedef struct ASFFwdGlobalStats_s {
	ASF_uint32_t    ulInPkts;	/* Total number of packets received */
	ASF_uint32_t    ulInPktCacheHits;	/* Total number of packets found a matching flow */
	ASF_uint32_t    ulOutPkts;	/* Total number of packets transmitted */
	ASF_uint32_t    ulOutBytes;	/* Total number of bytes transmitted */

	ASF_uint32_t    ulFlowAllocs;
	ASF_uint32_t    ulFlowFrees;
	ASF_uint32_t    ulFlowAllocFailures;
	ASF_uint32_t    ulFlowFreeFailures; /* Invalid flow delete requests */

} ASFFwdGlobalStats_t;


typedef struct ASFFwd6GlobalStats_s {
	ASF_uint32_t    ulInPkts;	/* Total number of packets received */
	ASF_uint32_t    ulInPktCacheHits;	/* Total number of packets found a matching flow */
	ASF_uint32_t    ulOutPkts;	/* Total number of packets transmitted */
	ASF_uint32_t    ulOutBytes;	/* Total number of bytes transmitted */

	ASF_uint32_t    ulFlowAllocs;
	ASF_uint32_t    ulFlowFrees;
	ASF_uint32_t    ulFlowAllocFailures;
	ASF_uint32_t    ulFlowFreeFailures; /* Invalid flow delete requests */

} ASFFwd6GlobalStats_t;

static inline int asf_fwd_arp_resolve(fwd_flow4_t *flow, 
	ASFBuffer_t *abuf)
{
	int ret;
	if ((ret = asf_arp_resolve(&flow->l2, abuf, flow->ulDestIp)) == 0)
	{
		/* For now assume it is just the ethernet header len; need to revisit for VLAN */
		flow->l2blob_len = ETH_HLEN;
	}
	return ret;
}

static inline int asf_fwd_route_resolve(
    ASFNetDevEntry_t *inputDev, fwd_flow4_t *flow, ASFBuffer_t *abuf, ASF_uint8_t tos)
{
    int ret;
    if ((ret = asf_route_resolve(inputDev, &flow->l2, abuf, flow->ulDestIp, tos)) == 0)
    {
        if (flow->l2.rth->rt_pmtu)
	    flow->pmtu = flow->l2.rth->rt_pmtu;
	else
	    flow->pmtu = flow->l2.rth->dst.dev->mtu;

	flow->odev = flow->l2.rth->dst.dev;

   	return 0;
    }
    return ret;
}

#ifdef ASF_IPV6_FP_SUPPORT
static inline int asf_fwd_route6_resolve(ASFNetDevEntry_t *inputDev, fwd_flow6_t *flow, ASFBuffer_t *abuf)
{
	int ret;
	if ((ret = _asf_route6_resolve(inputDev, &flow->l2, abuf)) == 0)
	{
		flow->odev = flow->l2.dst->dev;
	}
	return ret;
}

static inline int asf_fwd_arp6_resolve(fwd_flow6_t *flow, ASFBuffer_t *abuf)
{
	int ret;
	if ((ret = _asf_arp6_resolve(&flow->l2, abuf, &flow->ipv6DestIp)) == 0)
	{
		flow->l2blob_len = ETH_HLEN;
	}
	return ret;
}
#endif
#endif
