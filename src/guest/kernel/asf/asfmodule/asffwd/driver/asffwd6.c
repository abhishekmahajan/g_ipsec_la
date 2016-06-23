/**************************************************************************
 * Copyright 2014-2015, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asffwd6.c
 *
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 * History:
 */

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
#ifdef CONFIG_DPA
#include <dpa/dpaa_eth.h>
#include <dpa/dpaa_eth_common.h>
#include <linux/fsl_bman.h>
#include <linux/fsl_qman.h>
#else
#if 0 /* Subha */
#include <gianfar.h>
#else
#include <e1000.h>
#include <linux/inetdevice.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/addrconf.h>
#endif
#endif
#ifdef ASF_TERM_FP_SUPPORT
#include <linux/if_pmal.h>
#endif
#include "../../asfffp/driver/asf.h"
#include "../../asfffp/driver/asfcmn.h"
#include "../../asfffp/driver/gplcode.h"
#include "../../asfffp/driver/asfmpool.h"
#include "../../asfffp/driver/asftmr.h"
#include "../../asfffp/driver/asfroute.h"
#include "../../asfffp/driver/asfroute6.h"
#include "../../asfffp/driver/asfparry.h"
#include "../../asfffp/driver/asfpvt.h"
#include "fwdpvt.h"
#include "fwdcache.h"
#define ASF_FWD_INAC_TIMER_INTERVAL 1    /* inter bucket gap */
#define ASF_FWD_INAC_TIMER_BUCKT 512
#define ASF_FWD_NUM_RQ_ENTRIES  (256)
#define ASF_FWD_INAC_TMOUT	2
#define ASF_FWD6_INAC_TIME_INTERVAL 1    /* inter bucket gap */
#define ASF_FWD6_INAC_TIMER_BUCKT 2048    /* Max inactity timer value  */
#define ASF_FWD6_NUM_RQ_ENTRIES  (256)
#define ASFFWD_RESPONSE_FAILURE -1
#define ASFFWD_RESPONSE_SUCCESS 0

 
typedef uint32_t asf_max_val_t;
int asf_fwd6_max_vsgs;
int asf_fwd6_enable = 1;

asf_max_val_t fwd_max_flow6s = ASF_FWD_MAX_FLOWS;
int asf_fwd6_inac_divisor = 1;
int fwd6_hash_buckets = ASF_FFP_MAX_HASH_BKT;
fwd6_bucket_t *fwd_flow6_cache;
ULONG asf_fwd6_hash_init_value;
static unsigned int  fwd_flow6_pool_id = -1;
static unsigned int  fwd6_inac_tmr_pool_id = -1;
int fwd6_max_flows = ASF_FWD_MAX_FLOWS;
ASFFwd6GlobalStats_t *fwd6_gstats;
ASFFwdVsg6Stats_t *fwd6_vsg_stats;


ptrIArry_tbl_t fwd6_ptrArray;
fwd6_cache_t *fwd6_cache;

static int fwd_create_flow6(ASF_uint32_t ulVsgId,
    ASF_IPv6Addr_t	*ipv6SrcIp, /* Source IPV6 Address */
    ASF_IPv6Addr_t	*ipv6DestIp, /* Destination IPV6 Address */
    ASF_uint32_t flowlabel,
    ASF_uint32_t hashVal,
    fwd_flow6_t **flow_ptr);

static inline fwd_flow6_t *fwd_flow6_alloc(void)
{
    char bHeap;
    fwd_flow6_t	*flow;
    ASFFFPGlobalStats_t	*gstats = asfPerCpuPtr(fwd6_gstats,
    					smp_processor_id());
    
    flow = (fwd_flow6_t *)asfGetNode(fwd_flow6_pool_id, &bHeap);
    if (flow) {
    	/*memset(flow, 0, sizeof(*flow)); */
    	gstats->ulFlowAllocs++;
    	flow->bHeap = bHeap;
    } else
    	gstats->ulFlowAllocFailures++;

    return flow;
}

static inline void fwd_flow6_free(fwd_flow6_t *flow)
{
    ASFFFPGlobalStats_t     *gstats = asfPerCpuPtr(fwd6_gstats,
    				smp_processor_id());
    asfReleaseNode(fwd_flow6_pool_id, flow, flow->bHeap);
    gstats->ulFlowFrees++;
}

#ifdef ASF_FWD_GLOBAL_CACHE
static void fwd_flow6_free_rcu(struct rcu_head *rcu)
{
   fwd_flow6_t *flow = (fwd_flow_t *)rcu;
   fwd_flow6_free(flow);
}
#endif

static __u32 ipv6_rule_salt __read_mostly;
static inline ULONG _fwd6_compute_hash(
				ASF_uint32_t ulVsgId,
				ASF_IPv6Addr_t *ip6SrcIp,
				ASF_IPv6Addr_t *ip6DestIp,
				ASF_uint32_t  flowlabel,
				ULONG initval)
{
	 
	ULONG ulSrcIp = 0;
	ULONG ulDestIp = 0;

	ulSrcIp += ip6SrcIp->s6_addr32[0];
	ulSrcIp += ip6SrcIp->s6_addr32[1];
	ulSrcIp += ip6SrcIp->s6_addr32[2];
	ulSrcIp += ip6SrcIp->s6_addr32[3];
	ulDestIp += ip6DestIp->s6_addr32[0];
	ulDestIp += ip6DestIp->s6_addr32[1];
	ulDestIp += ip6DestIp->s6_addr32[2];
	ulDestIp += ip6DestIp->s6_addr32[3];
	ulSrcIp += ipv6_rule_salt;

	asf_debug("1: ulSrcIp = 0x%x, ulDestIp =0x%x\n", (unsigned int)ulSrcIp, (unsigned int)ulDestIp);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	ulDestIp += JHASH_GOLDEN_RATIO;
#else
	ulDestIp += JHASH_INITVAL;
#endif
	asf_debug("2: ulSrcIp = 0x%x, ulDestIp =0x%x\n", (unsigned int)ulSrcIp, (unsigned int)ulDestIp);
	flowlabel += initval;
	ASF_BJ3_MIX(ulSrcIp, ulDestIp, flowlabel);
	asf_debug("4: ulSrcIp = 0x%x, ulDestIp = 0x%x, flowlabel = 0x%x\n", (unsigned int)ulSrcIp, (unsigned int)ulDestIp, (unsigned int)flowlabel);
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	ulSrcIp += ulVsgId;
	asf_debug("5: ulSrcIp = 0x%x, ulDestIp = 0x%x, flowlabel = 0x%x\n", (unsigned int)ulSrcIp, (unsigned int)ulDestIp, (unsigned int)flowlabel);
	ASF_BJ3_MIX(ulSrcIp, ulDestIp, flowlabel);
	asf_debug("6: ulSrcIp = 0x%x, ulDestIp = 0x%x, flowlabel = 0x%x\n", (unsigned int)ulSrcIp, (unsigned int)ulDestIp, (unsigned int)flowlabel);
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
	asf_debug("ipv6_rule_salt = 0x%x, flowlabel = 0x%x, Hashvalue = 0x%x\n", ipv6_rule_salt, (unsigned int)flowlabel, (unsigned int)(ipv6_rule_salt + flowlabel));
	return ipv6_rule_salt + flowlabel;
}


#define FWD_HINDEX(h)	ASF_HINDEX(h,fwd6_hash_buckets)

static inline fwd6_bucket_t *_fwd6_bucket_by_hash(unsigned int ulHashVal)
{
	return &fwd_flow6_cache[FWD_HINDEX(ulHashVal)];
}

static void _fwd_flow6_insert(fwd_flow6_t *flow, 
	fwd_flow6_t *bkt)
{
	fwd_flow6_t *head, *temp;
	head = (fwd_flow6_t *) bkt;
#ifdef ASF_FWD_GLOBAL_CACHE
	spin_lock_bh(&bkt->lock);
#endif
	temp = flow->pNext = head->pNext;
	flow->pPrev = head;
#ifdef ASF_FWD_GLOBAL_CACHE
	rcu_assign_pointer(head->pNext, flow);
#else
	head->pNext =  flow;
#endif
	temp->pPrev = flow;
#ifdef ASF_FWD_GLOBAL_CACHE
	spin_unlock_bh(&bkt->lock);
#endif

}

static void _fwd_flow6_delete(fwd_flow6_t *flow)
{
#ifdef ASF_FWD_GLOBAL_CACHE
    ASF_uint32_t hashVal;
    fwd_bucket6_t *bkt;

    hashVal = _fwd_cmpute_hash(flow->ulVsgId,
        flow->ulSrcIp,
        flow->ulDestIp,
        flow->flowlabel,initval);
    bkt = _fwd6_bucket_by_hash(hashVal);
    spin_lock_bh(&bkt->lock);
#endif

    flow->pNext->pPrev = flow->pPrev;
    flow->pPrev->pNext = flow->pNext;

#ifdef ASF_FWD_GLOBAL_CACHE
    spin_unlock_bh(&bkt->lock);
#endif
   fwd_flow6_free(flow);
}

static void _fwd_flow6_insert_in_cache(fwd_flow6_t *flow)
{
    fwd6_cache_t *per_cpu_fwd_cache = asfPerCpuPtr(fwd6_cache, smp_processor_id());
    if (per_cpu_fwd_cache != NULL)
    {
	    flow->pCacheNext = per_cpu_fwd_cache->pHead; 
	    flow->pCachePrev = NULL;
	    if (per_cpu_fwd_cache->pHead)
	        per_cpu_fwd_cache->pHead->pCachePrev = flow;

	    per_cpu_fwd_cache->pHead = flow;

	    if (per_cpu_fwd_cache->pTail == NULL)
            per_cpu_fwd_cache->pTail = per_cpu_fwd_cache->pHead;
	}
    
}

static void _fwd_flow6_move_in_cache(fwd_flow6_t *flow)
{
    fwd6_cache_t *per_cpu_fwd_cache = asfPerCpuPtr(fwd6_cache, smp_processor_id());
    if (per_cpu_fwd_cache != NULL)
    {
	if (flow == per_cpu_fwd_cache->pHead)
	{
	    /* already in head;
 	       do nothing 
	    */
            return;
	}
	if (flow->pCachePrev)
	{
            flow->pCachePrev->pCacheNext = flow->pCacheNext;
	}
	if (flow->pCacheNext)
	{
	    flow->pCacheNext->pCachePrev = flow->pCachePrev;
	}
	if (flow == per_cpu_fwd_cache->pTail)
	{
	    per_cpu_fwd_cache->pTail = flow->pCachePrev;
	}

	/* Insert at head */
	flow->pCacheNext = per_cpu_fwd_cache->pHead;
	flow->pCachePrev = NULL;

	per_cpu_fwd_cache->pHead->pCachePrev = flow;
	per_cpu_fwd_cache->pHead = flow;
   }
}


static inline void _fwd_flow6_delete_lru()
{
    fwd6_cache_t *per_cpu_fwd_cache = asfPerCpuPtr(fwd6_cache, smp_processor_id());
    fwd_flow6_t *flow;

    if (likely(per_cpu_fwd_cache))
    {
        if ((per_cpu_fwd_cache->count+1) < fwd6_max_flows)
            return;

        /* remove from tail */
        flow = per_cpu_fwd_cache->pTail;

        per_cpu_fwd_cache->pTail = flow->pCachePrev;
        per_cpu_fwd_cache->pTail->pCacheNext = NULL;
    
	asfTimerStop(ASF_FWD6_INAC_TMR_ID, 0, flow->pInacTmr);
	ptrIArray_delete(&fwd6_ptrArray,flow->id.ulArg1,NULL);
        _fwd_flow6_delete(flow);
    }
}

static void _fwd_flow6_del_in_cache(fwd_flow6_t *flow)
{
    fwd_cache_t *per_cpu_fwd_cache = asfPerCpuPtr(fwd6_cache, smp_processor_id());
    if (per_cpu_fwd_cache != NULL)
    {
        if (flow->pCachePrev)
        {
            flow->pCachePrev->pCacheNext = flow->pCacheNext;
        }
        if (flow->pCacheNext)
        {
            flow->pCacheNext->pCachePrev = flow->pCachePrev;
        }
        if (flow == per_cpu_fwd_cache->pTail)
	{
	    per_cpu_fwd_cache->pTail = flow->pCachePrev;
	}
    }
}

ASF_boolean_t _is_route6_cacheable(
    ASFNetDevEntry_t *aDev,
    struct ipv6hdr *hdr)
{
	
    return ASF_TRUE;
}


fwd_flow6_t *asf_fwd_flow6_lookup(
	ASF_uint32_t ulVSGId,
	ASF_IPv6Addr_t *sip,
	ASF_IPv6Addr_t *dip,
	ASF_uint32_t flowlabel,
	ASF_uint32_t *hashVal)
{
	fwd_flow6_t *pHead, *flow; 

#ifdef ASF_FWD_GLOBAL_CACHE
	rcu_read_lock();
#endif
	
	*hashVal = _fwd6_compute_hash(ulVSGId, sip, dip,flowlabel, asf_fwd6_hash_init_value);

	pHead = (fwd_flow6_t *)_fwd6_bucket_by_hash(*hashVal);
	
	for (flow = pHead->pNext; flow != pHead; flow = flow->pNext) {
			if (!(_ipv6_addr_cmp((struct in6_addr *)&(flow->ipv6SrcIp), (struct in6_addr *)sip))
			&& !(_ipv6_addr_cmp((struct in6_addr *)&(flow->ipv6DestIp), (struct in6_addr *)dip))
			&& (flow->flowlabel == flowlabel)
			&& (flow->ulVsgId == ulVSGId)
			) {
				return flow;
			}
	}
#ifdef ASF_FWD_GLOBAL_CACHE
	rcu_read_unlock();
#endif
	return NULL;

}
	

ASF_uint32_t ASFFWD6_Process(
    ASF_uint32_t ulVsgId,
    ASF_uint32_t ulCommonInterfaceId,
    ASFBuffer_t  Buffer,
    genericFreeFn_t pFreeFn,
    ASF_void_t *freeArg)
{
	struct ipv6hdr		*ip6h;
	ULONG		ulHashVal;
	struct sk_buff		*skb;
	ASFNetDevEntry_t	*anDev;
	unsigned char		nexthdr;
	ASFFwdVsg6Stats_t *vstats;
	ASFFwd6GlobalStats_t *gstats;
        unsigned int exthdrsize = 0;
	asf_vsg_info_t *vsgInfo;
	unsigned int pkt_len = 0;
	unsigned int hashVal;
	fwd_flow6_t *flow;
	int ret;
	bool bFirstLookup = 0;
    	struct net_device       *netdev;
	ASFFwdFlowStats_t       *flow_stats;

	gstats = asfPerCpuPtr(fwd6_gstats, smp_processor_id());
	printk("ASFFWD6_Process entered\n");


	skb = (struct sk_buff *) Buffer.nativeBuffer;
	anDev = ASFCiiToNetDev(ulCommonInterfaceId);
	
	if (unlikely(!anDev)) {
		asf_debug("CII %u doesn't appear to be valid\n",
			ulCommonInterfaceId);
		pFreeFn(skb);
		return;
	}
	
	asf_debug("Subha: ProcessAndSendIPv6: 2\n");

	
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	vstats = asfPerCpuPtr(fwd6_vsg_stats, smp_processor_id()) + ulVsgId;
	vstats->ulInPkts++;
#endif
	ip6h = ipv6_hdr(skb);

	
#ifdef ASF_DEBUG_FRAME
	asf_print(" Pkt (%x) skb->len = %d, ip6h->payload_len = %d",
		pIpsecOpaque, skb->len, ip6h->payload_len);
	hexdump(skb->data - 14, skb->len + 14);
#endif
	
	if (unlikely(ip6h->version != 6)) {
		asf_debug("Bad iph-version =%d", ip6h->version);
		pFreeFn(skb);
		return ASF_DONE;
	}
	asf_debug("Subha: ProcessAndSendIPv6: 3\n");

	rcu_read_lock();
	
	if (ipv6_addr_is_multicast(&ip6h->daddr) || 
		ipv6_addr_is_multicast(&ip6h->saddr))
        {
	    printk("Returned to stack: 4\n");
   	    return ASF_RTS;
        }    

	/* IP packet need to be set in SKB */
	skb_set_transport_header(skb, sizeof(struct ipv6hdr));
	
	pkt_len = ntohs(ip6h->payload_len);
	
	/* Traverse IPv6 extension headers */
	
	nexthdr = ip6h->nexthdr;
/*
	if (pkt_len || ip6h->nexthdr != NEXTHDR_HOP) {
	    	printk("Returned to stack: 5\n");
   	    	return ASF_RTS;
		
	}
*/

	if (unlikely(nexthdr == NEXTHDR_HOP)) {

		/* Only hop-by-hop extension header with only Jumboigram optiohn sippoted */
		/* rest will given to  Linux */

		/* jumbograms + extra options  */
		if (skb_transport_header(skb)[1] != 0)
		{
	    		printk("Returned to stack: 6\n");
   	    		return ASF_RTS;
		}

		/* Is jumbograms ? */
		if (skb_transport_header(skb)[2] != IPV6_TLV_JUMBO)
		{
	    		printk("Returned to stack: 7\n");
   	    		return ASF_RTS;
		}

		/* jumbograms lenght should be 4 */
		if (skb_transport_header(skb)[3] != 4)
		{
	    		printk("Returned to stack: 8\n");
   	    		return ASF_RTS;
		}
		
		pkt_len = ntohs(*(unsigned int *)(&skb_transport_header(skb)[4]));

		if (pkt_len > skb->len - sizeof(struct ipv6hdr))
		{
			pFreeFn(skb);
   	    		return ASF_DONE;
		}

		/* Process hop by hop IP options, esp for JUMBOGRAM option */

		nexthdr = skb_transport_header(skb)[0];
		exthdrsize += (skb_transport_header(skb)[1] + 1) << 3;

		skb_set_transport_header(skb, sizeof(struct ipv6hdr) + exthdrsize);

	}

	
	asf_debug("Subha: nexthdr = 0x%x ProcessAndSendIPv6: 4 Pktlen = 0x%x\n", nexthdr, pkt_len);
	rcu_read_unlock();

	ASF_uint32_t flowlabel;

        flowlabel = (* (__be32 *) ip6h) & IPV6_FLOWINFO_MASK;

	flow = asf_fwd_flow6_lookup(ulVsgId,
        	&ip6h->saddr, &ip6h->daddr,
        	flowlabel, &hashVal);

        if (flow)
    	{

		printk("Flow found\n");
        	_fwd_flow6_move_in_cache(flow);
		vsgInfo = asf_ffp_get_vsg_info_node(ulVsgId);
        	if (vsgInfo)
        	{
            		if (vsgInfo->configIdentity.l2blobConfig.ulL2blobMagicNumber != 
                		flow->configIdentity.l2blobConfig.ulL2blobMagicNumber)
            		{
		        	if (flow->l2.dst)
				{
					dst_release(flow->l2.dst);
					flow->l2.dst = NULL;
				}
				if (flow->l2.n)
				{
					neigh_release(flow->l2.n);
					flow->l2.n = NULL;
				}
				flow->l2blob_len = 0;
				flow->odev = NULL;
            		}
        	}
		if ((flow->l2.n) &&  ((flow->l2.n->flags & NUD_FAILED) || (flow->l2.n->flags & NUD_STALE)))
		{
			/* BBB */
			neigh_release(flow->l2.n);
			flow->l2.n = NULL;
			flow->l2blob_len = 0;
		}
	}
        else
        {
		printk("Flow not found\n");
	    /* Check if the flow can be offloaded */
		if (_is_route6_cacheable(anDev, ip6h) == ASF_TRUE)
            	{
            		if (fwd_create_flow6(ulVsgId, &ip6h->saddr, &ip6h->daddr, flowlabel, hashVal, &flow)
				 == ASFFWD_RESPONSE_SUCCESS)
            		{
				printk("Flow Created\n");
	            		_fwd_flow6_delete_lru();
				printk("Delete LRU done\n");
	            		_fwd_flow6_insert(flow, (fwd_flow6_t*)_fwd6_bucket_by_hash(hashVal)); 
				printk("Insert in Flow cache done\n");
                		_fwd_flow6_insert_in_cache(flow);
            		}
			else
			{
			     /* Send it up to Stack */
   	    			return ASF_RTS;
			}
        	}
    	}
	if (flow)
	{
		printk("Flow Created\n");
        	flow_stats = &flow->stats;
		if (flow->l2blob_len == 0) {
			/* do route lookup */
			if (unlikely(!flow->l2.dst))
			{
				if (unlikely((ret = asf_fwd_route6_resolve(anDev, flow, &Buffer)) != 0))
				{
					asf_debug("Unable to resolve route: ret = %d Send Packet up to stack\n",ret);
   	    				return ASF_RTS;
				}
				asf_debug("asf_fwd_route6_resolve returned %d\n", ret);
				if (ret == 0)
				{
					vsgInfo = asf_ffp_get_vsg_info_node(ulVsgId);
					if (flow->configIdentity.l2blobConfig.ulL2blobMagicNumber != 
						vsgInfo->configIdentity.l2blobConfig.ulL2blobMagicNumber)
					{
						flow->configIdentity.l2blobConfig.ulL2blobMagicNumber = 
							vsgInfo->configIdentity.l2blobConfig.ulL2blobMagicNumber;
					}
					else
					{
						bFirstLookup = 1;
					}
				}
			}
			/* do arp lookup */
			if ((ret = asf_fwd_arp6_resolve(flow, &Buffer)) == 0)
			{
				asf_debug("asf_fwd_arp6_resolve returned %d\n", ret);
	
			}
			else if (ret == 2)
			{
				asf_debug("dst_neigh_output absorbed the packet\n");
   	    			return ASF_DONE;
			}
			else
			{
				if (!bFirstLookup)
				{
					asf_debug("Could not resolve ARP after L2blob Magic Number change: Dropping packet\n");
					pFreeFn(skb);
   	    				return ASF_DONE;
				}
				else
				{
					asf_debug("arp6_resolve returned %d returning to stack\n", ret);
   	    				return ASF_RTS;
				}
			}
		}
		if (unlikely(skb_shinfo(skb)->frag_list)) {
			/* Handle frag list */
			struct sk_buff *pSkb;
	
			/* This is tricky */
			asfIpv6MakeFragment(skb, &pSkb);
	
			skb = pSkb;
		}

		do {
			struct sk_buff *pTempSkb;
			unsigned int tunnel_hdr_len = 0;

			pTempSkb = skb->next;
			asf_debug("Next skb = 0x%x\r\n", pTempSkb);
			skb->next = NULL;

			ip6h = ipv6_hdr(skb);

			skb->pkt_type = PACKET_FASTROUTE;

			/* make following unconditional*/
			/*
			if (flow->bVLAN)
				skb->vlan_tci = flow->tx_vlan_id;
			else
				skb->vlan_tci = 0;
			*/

			ip6h->hop_limit--;

			skb->data -= flow->l2blob_len;


			skb->dev = flow->odev;

			asf_debug("Subha: ProcessAndSendIPv6: 15\n");

			asf_debug("Calling asfCopyWords\n");
			asfCopyWords((unsigned int *)skb->data, (unsigned int *)flow->l2.n->ha, 6 );
			asfCopyWords((unsigned int *)(skb->data + 6), (unsigned int *)flow->l2.n->dev->perm_addr,  6);
		

			skb->len += flow->l2blob_len;

			asf_debug("skb->network_header = 0x%x, skb->transport_header = 0x%x\r\n",
				  skb_network_header(skb), skb_transport_header(skb));
			asf_debug("Transmitting  buffer = 0x%x dev->index = %d\r\n",
				  skb, skb->dev->ifindex);

struct netdev_queue *txq;

			txq = netdev_get_tx_queue(skb->dev, skb->queue_mapping);
			netdev = skb->dev;
			if (asfDevHardXmit(skb->dev, skb) != 0) {
				asf_warn("Error in transmit: Should not happen\r\n");
				ASFSkbFree(skb);
			} else
				netdev->trans_start = txq->trans_start = jiffies;
		
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			gstats->ulOutPkts++;
			vstats->ulOutPkts++;
			flow_stats->ulOutPkts++;
#endif

			skb = pTempSkb;
		}while (skb);
   	    	return ASF_DONE;
	}
	else
	{
		printk("Returing to stack\n");
   	    	return ASF_RTS;
	}
}


static int fwd_create_flow6(ASF_uint32_t ulVsgId,
    ASF_IPv6Addr_t	*ipv6SrcIp, 
    ASF_IPv6Addr_t	*ipv6DestIp, 
    ASF_uint32_t flowlabel,
    ASF_uint32_t hashVal,
    fwd_flow6_t **flow_ptr)
{
    fwd_flow6_t *flow;
    struct flowi4 *fl;
    int index;
    fwd6_cache_t *per_cpu_fwd_cache = asfPerCpuPtr(fwd6_cache, smp_processor_id()) + ulVsgId; 
     *flow_ptr = NULL;

    if (asf_fwd6_enable)
    {
	    if (ulVsgId < asf_fwd6_max_vsgs)
	    {
	        if (per_cpu_fwd_cache != NULL)
 	        {
    	        flow = fwd_flow6_alloc();
                if (flow)
                {
			    ipv6_addr_copy((struct in6_addr *)&(flow->ipv6SrcIp),
					(struct in6_addr *)(ipv6SrcIp));
		            ipv6_addr_copy((struct in6_addr *)&(flow->ipv6DestIp),
					(struct in6_addr *)(ipv6DestIp));
          
	                flow->ulVsgId = ulVsgId;
	             	flow->flowlabel = flowlabel;

/*
	                fl = &flow->l2.fl;

	                fl->flowi4_oif = 0;
	                fl->flowi4_scope = RT_SCOPE_UNIVERSE;
	                fl->daddr = flow->ipv6SrcIp;
	                fl->saddr = flow->ipv6DestIp;
*/


	                index = ptrIArray_add(&fwd6_ptrArray, flow);
	                if (index > fwd6_ptrArray.nr_entries)
	                {
	                    asf_debug("Flow creation failed\n");
                        fwd_flow6_free(flow);
	                    return ASFFWD_RESPONSE_FAILURE;
	                }
		            flow->id.ulArg1 = index;
	                flow->id.ulArg2 = fwd6_ptrArray.pBase[index].ulMagicNum;

					flow->pInacTmr = asfTimerStart(ASF_FWD6_INAC_TMR_ID, 0,
							     flow->ulInacTime/asf_fwd6_inac_divisor,
							     flow->ulVsgId,
							     flow->id.ulArg1,
							     flow->id.ulArg2, hashVal, 0);
					
				    if (!flow->pInacTmr)
				    {
					    ptrIArray_delete(&fwd6_ptrArray,flow->id.ulArg1,NULL);
					    fwd_flow6_free(flow);
					    flow = NULL;
				    }
		            *flow_ptr = flow;
		            return ASFFWD_RESPONSE_SUCCESS;
    		    }
            }
            else
            {
                asf_err("fwd_create_flow6: Unable to locate per CPU Cache\n");
                return ASFFWD_RESPONSE_FAILURE;
            }
	    }
        else
        {
    	    asf_debug("VSG %d > MAX %d\n", ulVsgId, asf_fwd6_max_vsgs);
	    return ASFFWD_RESPONSE_FAILURE;
        }
     }
     return ASFFWD_RESPONSE_FAILURE;
} 


static inline fwd_flow6_t *fwd_flow6_by_id_ex(
	unsigned int ulIndex, 
	unsigned int ulMagicNum)
{
	return (fwd_flow6_t *) 
		((fwd6_ptrArray.pBase[ulIndex].ulMagicNum == ulMagicNum) ? 
		fwd6_ptrArray.pBase[ulIndex].pData : NULL);
}

unsigned int asfFwd6InacTmrCb(unsigned int ulVSGId,
				    unsigned int ulIndex, 
				    unsigned int ulMagicNum, 
				    unsigned int ulHashVal, 
				    bool bIPv6)
{
	fwd_flow6_t *flow;
	
	asf_debug_l2("vsg %u idx %u magic %u hash %u\n", ulVSGId, ulIndex, ulMagicNum, ulHashVal);

	flow = fwd_flow6_by_id_ex(ulIndex, ulMagicNum);
	if (flow)
	{
		_fwd_flow6_del_in_cache(flow);
	}
	else
	{
	    asf_debug("Inac Tmr: flow not found {%u, %u}\n", ulIndex, ulMagicNum);
	}
	return 0;
}


static int asf_fwd_init_flow6_table()
{
    unsigned int max_num;
    int i;
    ptrIArry_nd_t   *node;

    max_num = fwd_max_flow6s/20;
    get_random_bytes(&asf_fwd6_hash_init_value, sizeof(asf_fwd6_hash_init_value));

    if (asfCreatePool("FwdFlow", max_num,
		max_num, (max_num/2),
		sizeof(fwd_flow6_t),
		&fwd_flow6_pool_id) != 0)
    {
		asf_err("Failed to initialize forward flow pool\n");
		return -ENOMEM;
    }

	
    fwd_flow6_cache = kzalloc((sizeof(fwd6_bucket_t ) *fwd6_hash_buckets),
	GFP_KERNEL);

    if (fwd_flow6_cache == NULL)
    {
	asf_err("Unable to allocate memory for flow table\n");
	return -ENOMEM;
    }

    for (i=0; i < fwd6_hash_buckets; i++)
    {
#ifdef ASF_FWD_GLOBAL_CACHE
	spin_lock_init(&fwd_flow6_cache[i].lock);
#endif
        fwd_flow6_cache[i].pNext = (fwd_flow6_t *)&fwd_flow6_cache[i];
    	fwd_flow6_cache[i].pPrev = fwd_flow6_cache[i].pNext;
    }

    node = kzalloc((sizeof(ptrIArry_nd_t)*fwd_max_flow6s), GFP_KERNEL);

    if (NULL == node) {
	return -ENOMEM;
    }
    ptrIArray_setup(&fwd6_ptrArray, node, fwd_max_flow6s, 1);


	if (asfCreatePool("FwdInac6Timers", max_num,
			  max_num, (max_num/2),
			  sizeof(asfTmr_t),
			  &fwd6_inac_tmr_pool_id)) {
		asf_err("Error in creating pool for Inac Timers\n");
		return -ENOMEM;
	}

	asf_debug("Timer : InacTimer_PoolId = %d\r\n",
		 fwd6_inac_tmr_pool_id);

	asf_print("Instantiating blob timer wheels\n");

	if (asfTimerWheelInit(ASF_FWD6_INAC_TMR_ID, 0,
			      ASF_FWD6_INAC_TIMER_BUCKT, ASF_TMR_TYPE_SEC_TMR,
			      ASF_FWD6_INAC_TIME_INTERVAL, ASF_FWD6_NUM_RQ_ENTRIES) == 1) {
		asf_err("Error in initializing L2blob Timer wheel\n");
		return -ENOMEM;
	}

	asf_print("Instantiating inac timer wheels\n");
	if (asfTimerAppRegister(ASF_FWD6_INAC_TMR_ID, 0,
				(asfTmrCbFn) asfFwd6InacTmrCb,
				fwd6_inac_tmr_pool_id)) {
		asf_debug("Error in registering Cb Fn/Pool Id\n");
		return -ENOMEM;
	}
    return 0;
}

    
void asf_fwd_cleanup_all_flow6s(void)
{
	int i;
	fwd6_bucket_t    *bkt;
	fwd_flow6_t      *head, *flow, *temp;

	for (i = 0; i < fwd6_hash_buckets; i++) {
		bkt = &fwd_flow6_cache[i];
		head = (fwd_flow6_t *)  bkt;
		flow = head->pNext;

		/* Now the list is detached from the bucket */
		while (flow != head) {
			temp = flow;
			flow = flow->pNext;
			if (temp->pInacTmr) {
				asfTimerStop(ASF_FFP_INAC_REFRESH_TMR_ID, 0, temp->pInacTmr);
			}
		}
	}
}

static void asf_fwd_destroy_all_flow6s(void)
{
	int i;
	fwd_flow6_t	*head, *flow, *temp;

	for (i = 0; i < fwd6_hash_buckets; i++) {
		head = (fwd_flow6_t *) &fwd_flow6_cache[i];
		flow = head->pNext;
		while (flow != head) {
			temp = flow;
			flow = flow->pNext;
		
		       	if (temp->l2.dst)
			{
				dst_release(temp->l2.dst);
				temp->l2.dst = NULL;
			}
			if (temp->l2.n)
			{
				neigh_release(temp->l2.n);
				temp->l2.n = NULL;
			}
			temp->l2blob_len = 0;
			temp->odev = NULL;

			fwd_flow6_free(temp);
		}
	}
}
static void asf_fwd_destroy_flow6_table()
{
	/*asf_fwd_cleanup_all_flows(); */
	asf_fwd_destroy_all_flow6s();

	asf_debug("DestroyPool FlowPool\n");
	if (asfDestroyPool(fwd_flow6_pool_id) != 0)
		asf_debug("failed to destroy flow mpool\n");

	/* free the table bucket array */
	kfree(fwd_flow6_cache);

	ptrIArray_cleanup(&fwd6_ptrArray);
}

static void asf_fwd_destroy_cache6()
{ 
    kfree(fwd6_cache);
}


int asf_fwd6_init_cache(void)
{
    fwd6_cache_t *per_cpu_fwd_cache;
    int cpu;
    int vsg;

    fwd6_cache = asfAllocPerCpu(sizeof(fwd6_cache_t)*asf_fwd6_max_vsgs);
    if (fwd6_cache == NULL)
    {
	asf_err("Error in allocating forward cache\n");
	return ASFFWD_RESPONSE_FAILURE;
    }

    for (cpu=0; cpu< 2; cpu++)
    {
	for (vsg = 0; vsg < asf_fwd6_max_vsgs; vsg++)
	{
            per_cpu_fwd_cache = asfPerCpuPtr(fwd6_cache, cpu) + vsg;
	   
	   per_cpu_fwd_cache->count = 0;
	   per_cpu_fwd_cache->pHead = NULL;
           per_cpu_fwd_cache->pTail = NULL;
        }
    }
    return 0;
}
		

int asf_fwd6_init(void)
{
	int err;

	/*Checks are intoduced to prevent the asf initialization
	with negative parameter*/
	asf_fwd6_max_vsgs =  1 /* asf_cap.ulNumVSGs */;
	if (fwd_max_flow6s < 0) {
		asf_err("invalid number of flows (%d).ASF is not initialized.\n",
			fwd_max_flow6s);
		return -1;
	}
	if (fwd6_hash_buckets < 0) {
		asf_err("invalid bucket size(%d).ASF is not initialized.\n",
			fwd6_hash_buckets);
		return -1;
	}

	
	asf_debug("Allocating perCpu memory for global stats\n");
	fwd6_gstats = asfAllocPerCpu(sizeof(ASFFwdGlobalStats_t));
	if (!fwd6_gstats) {
		asf_err("Failed to allocate per-cpu memory for global statistics\n");
		return -ENOMEM;
	}

	asf_debug("Allocating perCpu memory for VSG stats\n");
	fwd6_vsg_stats = asfAllocPerCpu(sizeof(ASFFwdVsgStats_t)*asf_fwd6_max_vsgs);
	if (!fwd6_vsg_stats) {
		asf_err("Failed to allocate per-cpu memory for VSG statistics\n");
		return -ENOMEM;
	}

	asf_print("Fwd6: Initializing Flow Table\n");
	err = asf_fwd_init_flow6_table();
	if (err) {
		return err;
	}

	err = asf_fwd6_init_cache();
	if (err) {
		asf_fwd_destroy_flow6_table();
		return err;
	}
	ASFFFPRegisterFwd6Functions((ASFFwdFn_f)ASFFWD6_Process);


	return err;
}

int asf_fwd6_deinit(void)
{
//	asf_fwd_destroy_cache6();
	asf_fwd_destroy_all_flow6s();
	return 0;
}
