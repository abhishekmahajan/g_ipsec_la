/**************************************************************************
 * Copyright 2014-2015, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asffwd.c
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

 
typedef ASF_uint32_t asf_max_val_t;

int asf_fwd_max_vsgs;
int asf_fwd_enable = 1;
int asf_fwd_inac_divisor = 1;

asf_max_val_t fwd_max_flows = ASF_FWD_MAX_FLOWS;
asf_max_val_t fwd_max_flows_per_vsg = ASF_FWD_MAX_FLOWS;
fwd4_bucket_t *fwd_flow_cache;
unsigned long asf_fwd_hash_init_value;
static unsigned int  fwd_flow4_pool_id = -1;
static unsigned int  fwd4_inac_tmr_pool_id = -1;
int fwp_max_flows = ASF_FWD_MAX_FLOWS;
int fwd_hash_buckets = ASF_FFP_MAX_HASH_BKT;

#define ASFFWD_RESPONSE_FAILURE -1
#define ASFFWD_RESPONSE_SUCCESS 0

ptrIArry_tbl_t fwd4_ptrArray;

ASFFwdGlobalStats_t *fwd_gstats;
ASFFwdVsgStats_t *fwd_vsg_stats;

fwd_cache_t *fwd_cache;
static __u32 rule_salt __read_mostly;

extern struct dst_ops asf_ipv4_dst_blackhole_ops;
int fwd_register_proc(void);
int asf_unregister_proc(void);
#ifdef ASF_IPV6_FP_SUPPORT
extern int asf_fwd6_init(void);
extern int asf_fwd6_deinit(void);
#endif
static inline fwd_flow4_t *fwd_flow4_alloc(void)
{
    char bHeap;
    fwd_flow4_t	*flow;
    ASFFwdGlobalStats_t	*gstats = (ASFFwdGlobalStats_t *)
		asfPerCpuPtr(fwd_gstats, smp_processor_id());
    
    flow = (fwd_flow4_t *)asfGetNode(fwd_flow4_pool_id, &bHeap);
    if (flow) {
    	/*memset(flow, 0, sizeof(*flow)); */
    	gstats->ulFlowAllocs++;
    	flow->bHeap = bHeap;
    } else
    	gstats->ulFlowAllocFailures++;

    return flow;
}

static inline void fwd_flow4_free(fwd_flow4_t *flow)
{
    ASFFwdGlobalStats_t     *gstats = (ASFFwdGlobalStats_t *)
	asfPerCpuPtr(fwd_gstats, smp_processor_id());
    asfReleaseNode(fwd_flow4_pool_id, flow, flow->bHeap);
    gstats->ulFlowFrees++;
}

#ifdef ASF_FWD_GLOBAL_CACHE
static void fwd_flow_free_rcu(struct rcu_head *rcu)
{
   fwd_flow4_t *flow = (fwd_flow4_t *)rcu;
   fwd_flow_free(flow);
}
#endif

static inline unsigned long _fwd_cmpute_hash(
				ASF_uint32_t ulVsgId,
				ASF_uint32_t ulSrcIp,
				ASF_uint32_t ulDestIp,
				ASF_uint8_t  tos,
				unsigned long initval)
{
        ASF_uint32_t ultos = (ASF_uint32_t )tos; 
	ulSrcIp += rule_salt;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	ulDestIp += JHASH_GOLDEN_RATIO;
#else
	ulDestIp += JHASH_INITVAL;
#endif
	ultos += initval;

	ASF_BJ3_MIX(ulSrcIp, ulDestIp, ultos);

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	ulSrcIp += ulVsgId;
	ASF_BJ3_MIX(ulSrcIp, ulDestIp, ultos);
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
	return rule_salt + ultos;
}

#define FWD_HINDEX(h)	ASF_HINDEX(h,fwd_hash_buckets)

static inline fwd4_bucket_t *_fwd_bucket_by_hash(unsigned int ulHashVal)
{
	printk("FWD_HINDEX(h) = %x\n", FWD_HINDEX(ulHashVal));
	return &fwd_flow_cache[FWD_HINDEX(ulHashVal)];
}

static void _fwd_flow_insert(fwd_flow4_t *flow, 
	fwd_flow4_t *bkt)
{
	fwd_flow4_t *head, *temp;
	head = (fwd_flow4_t *) bkt;
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

static void _fwd_flow_delete(fwd_flow4_t *flow)
{
#ifdef ASF_FWD_GLOBAL_CACHE
    ASF_uint32_t hashVal;
    fwd4_bucket_t *bkt;

    _fwd_cmpute_hash(flow->ulVsgId,
        flow->ulSrcIp,
        flow->ulDestIp,
        flow->ucTos,initval);
    bkt = _fwd_bucket_by_hash(ulHashVal);
    spin_lock_bh(&bkt->lock);
#endif

    flow->pNext->pPrev = flow->pPrev;
    flow->pPrev->pNext = flow->pNext;

#ifdef ASF_FWD_GLOBAL_CACHE
    spin_unlock_bh(&bkt->lock);
#endif
   fwd_flow4_free(flow);
}

static int fwd_create_flow4(ASF_uint32_t ulVsgId,
    ASF_IPv4Addr_t	ulSrcIp, 
    ASF_IPv4Addr_t	ulDestIp, 
    ASF_uint8_t ucTos,
    ASF_uint32_t hashVal,
    fwd_flow4_t **flow_ptr)
{
    fwd_flow4_t *flow;
    struct flowi4 *fl;
    int index;
    fwd_cache_t *per_cpu_fwd_cache = asfPerCpuPtr(fwd_cache, smp_processor_id()) + ulVsgId; 

    if (asf_fwd_enable)
    {
	    if (ulVsgId < asf_fwd_max_vsgs)
	    {
	        if (per_cpu_fwd_cache != NULL)
 	        {
    	        flow = fwd_flow4_alloc();
                if (flow)
                {
	                flow->ulVsgId = ulVsgId;
	                flow->ulSrcIp = ulSrcIp;
	                flow->ulDestIp = ulDestIp;
	                flow->ucTos = ucTos;

	                fl = &flow->l2.fl;
	                fl->flowi4_oif = 0;
	                fl->flowi4_scope = RT_SCOPE_UNIVERSE;
	                fl->daddr = ulDestIp;
	                fl->saddr = ulSrcIp;

	                index = ptrIArray_add(&fwd4_ptrArray, flow);
	                if (index > fwd4_ptrArray.nr_entries)
	                {
	                    asf_debug("Flow creation failed\n");
                            fwd_flow4_free(flow);
	                    return ASFFWD_RESPONSE_FAILURE;
	                }
		    	flow->id.ulArg1 = index;
	                flow->id.ulArg2 = fwd4_ptrArray.pBase[index].ulMagicNum;
				
			flow->pInacTmr = asfTimerStart(ASF_FWD4_INAC_TMR_ID, 0,
				     flow->ulInacTime/asf_fwd_inac_divisor,
				     flow->ulVsgId,
				     flow->id.ulArg1,
				     flow->id.ulArg2, hashVal, 0);
				    if (!flow->pInacTmr)
				    {
					    ptrIArray_delete(&fwd4_ptrArray,flow->id.ulArg1,NULL);
					    fwd_flow4_free(flow);
					    flow = NULL;
				    }
			    }
				
		        *flow_ptr = flow;
			printk("flow_ptr allocated\n");
		        return ASFFWD_RESPONSE_SUCCESS;
    	    }
         }
         else
         {
            asf_err("fwd_create_flow4: Unable to locate per CPU Cache\n");
            return ASFFWD_RESPONSE_FAILURE;
         }
	}
    else
    {
    	printk("VSG %d > MAX %d\n", ulVsgId, asf_fwd_max_vsgs);
	    return ASFFWD_RESPONSE_FAILURE;
    }
     return ASFFWD_RESPONSE_FAILURE;
} 
static void _fwd_flow_insert_in_cache(fwd_flow4_t *flow)
{
    fwd_cache_t *per_cpu_fwd_cache = 
	(fwd_cache_t *)asfPerCpuPtr(fwd_cache, smp_processor_id());
    if (per_cpu_fwd_cache != NULL)
    {
	flow->pCacheNext = per_cpu_fwd_cache->pHead; 
	flow->pCachePrev = NULL;
	if (per_cpu_fwd_cache->pHead)
	{
	   printk("insert_in_cache: previous flow found\n");
	    per_cpu_fwd_cache->pHead->pCachePrev = flow;
	}

	per_cpu_fwd_cache->pHead = flow;

	if (per_cpu_fwd_cache->pTail == NULL)
	{
            per_cpu_fwd_cache->pTail = per_cpu_fwd_cache->pHead;
	}
    }
}

static void _fwd_flow_move_in_cache(fwd_flow4_t *flow)
{
    fwd_cache_t *per_cpu_fwd_cache = asfPerCpuPtr(fwd_cache, smp_processor_id());
    if (per_cpu_fwd_cache != NULL)
    {
	if (flow == per_cpu_fwd_cache->pHead)
	{
	    /* already in head;
 	       do nothing 
	    */
	    printk("Single flow: doing nothing\n");
            return;
	}
	printk("More than one flow, moving\n");
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


static inline void _fwd_flow_delete_lru(void)
{
#ifdef ASF_IPV6_FP_SUPPORT
    fwd6_cache_t *per_cpu_fwd_cache = 
	(fwd_cache_t *)asfPerCpuPtr(fwd_cache, smp_processor_id());
#endif
    fwd_cache_t *per_cpu_fwd_cache =  
	(fwd_cache_t *)asfPerCpuPtr(fwd_cache, smp_processor_id());
    fwd_flow4_t *flow;

    if (likely(per_cpu_fwd_cache))
    {
        if ((per_cpu_fwd_cache->count+1) < fwd_max_flows_per_vsg)
	{
            printk("_fwd_flow_delete_lru: returning\n");
            return;
	}

        /* remove from tail */
        flow = per_cpu_fwd_cache->pTail;

        per_cpu_fwd_cache->pTail = flow->pCachePrev;
        per_cpu_fwd_cache->pTail->pCacheNext = NULL;

	asfTimerStop(ASF_FWD4_INAC_TMR_ID, 0, flow->pInacTmr);
	ptrIArray_delete(&fwd4_ptrArray,flow->id.ulArg1,NULL);
        _fwd_flow_delete(flow);
    }
}

static void _fwd_flow_del_in_cache(fwd_flow4_t *flow)
{
    fwd_cache_t *per_cpu_fwd_cache = asfPerCpuPtr(fwd_cache, smp_processor_id());
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

ASF_boolean_t _is_route_cacheable(
    ASFNetDevEntry_t *aDev,
    struct iphdr *iph)
{
    struct in_device *in_dev = __in_dev_get_rcu(aDev->ndev);

    if (ipv4_is_multicast(iph->daddr)) 
       return ASF_FALSE;

    if (!aDev)
        return ASF_FALSE;

    if (ipv4_is_multicast(iph->saddr) || ipv4_is_lbcast(iph->saddr))
        return ASF_FALSE;

    if (ipv4_is_lbcast(iph->daddr) || (
	iph->saddr == 0 && iph->daddr == 0))
        return ASF_FALSE;

    if (ipv4_is_zeronet(iph->saddr))
        return ASF_FALSE;

    if (ipv4_is_zeronet(iph->daddr))
        return ASF_FALSE;

    if (ipv4_is_loopback(iph->daddr)) {
	if (!IN_DEV_NET_ROUTE_LOCALNET(in_dev, dev_net(aDev->ndev)))
	return ASF_FALSE;
    }
    else if (ipv4_is_loopback(iph->saddr)) {
	if (!IN_DEV_NET_ROUTE_LOCALNET(in_dev, dev_net(aDev->ndev)))
	return ASF_FALSE;
    }
    if (inet_addr_type(dev_net(aDev->ndev), iph->daddr) == RTN_LOCAL)
       return ASF_FALSE;

    printk("Routable: Returning TRUE\n");
    return ASF_TRUE;
}
    

fwd_flow4_t *asf_fwd_flow_lookup(
	ASF_uint32_t ulVSGId,
	ASF_uint32_t saddr,
	ASF_uint32_t daddr,
	ASF_uint8_t tos,
	ASF_uint32_t *hashVal)
{
	fwd_flow4_t *pHead, *flow; 

#ifdef ASF_FWD_GLOBAL_CACHE
	rcu_read_lock();
#endif
	
	*hashVal = _fwd_cmpute_hash(ulVSGId,saddr,daddr,tos,asf_fwd_hash_init_value);

	pHead = (fwd_flow4_t *)_fwd_bucket_by_hash(*hashVal);

	for (flow = pHead->pNext; flow != pHead; flow = flow->pNext) {
		if ((flow->ulSrcIp == saddr)
		&& (flow->ulDestIp == daddr)
		&& (flow->ucTos == tos)
		&& (flow->ulVsgId == ulVSGId)
		) {
#ifdef ASF_FWD_GLOBAL_CACHE
			rcu_read_unlock();
#endif
			return flow;
		}

	}
#ifdef ASF_FWD_GLOBAL_CACHE
	rcu_read_unlock();
#endif
	return NULL;
	
	

}
	
	
ASF_void_t ASFFWD_Process(
    ASF_uint32_t ulVsgId,
    ASF_uint32_t ulCommonInterfaceId,
    ASFBuffer_t  Buffer,
    genericFreeFn_t pFreeFn,
    ASF_void_t *freeArg)
{
    struct sk_buff *skb;
    ASFNetDevEntry_t *aDev;
    ASFFwdVsgStats_t *vstats;
    ASFFwdGlobalStats_t *gstats;
    struct iphdr *iph;
    fwd_flow4_t *flow;
    asf_vsg_info_t *vsgInfo;
    ASFFwdFlowStats_t *flow_stats;
    int hashVal;
    int ret = 0;
    struct netdev_queue *txq;
    struct net_device       *netdev;
    ASF_uint32_t seq;
    ASF_int32_t hh_len;
    ASF_int32_t hh_alen;
    struct hh_cache *hh;
	int ii;

    gstats = asfPerCpuPtr(fwd_gstats, smp_processor_id());

    skb = (struct sk_buff *)Buffer.nativeBuffer;

    aDev = ASFCiiToNetDev(ulCommonInterfaceId);
 
    if (unlikely(!(aDev)))
    {
        asf_debug("CII %u is not valid\n", ulCommonInterfaceId);
        pFreeFn(skb);
        return;
    } 

    printk("Process 0\n");

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
    vstats = asfPerCpuPtr(fwd_vsg_stats, smp_processor_id()) + ulVsgId;
    vstats->ulInPkts++; 
#endif

    iph = ip_hdr(skb);

#ifdef ASF_DEBUG_FRAME
    asf_print(" Pkt skb->len = %d, iph->tot_len = %d",
		 skb->len, ntohs(iph->tot_len));
    hexdump(skb->data - 14, skb->len + 14);
#endif
    printk("Proces 1\n");

    if (unlikely(iph->ttl < 1))
    {
        ASF_netif_receive_skb(skb);
        return;
    } 

    printk("Proces 2\n");
    flow = asf_fwd_flow_lookup(ulVsgId,
        iph->saddr, iph->daddr,
        iph->tos, &hashVal);

    if (flow)
    {
    	printk("Proces 3 : flow found\n");

        _fwd_flow_move_in_cache(flow);
    	printk("Proces 4 : flow found\n");
        vsgInfo = asf_ffp_get_vsg_info_node(ulVsgId);
        if (vsgInfo)
        {
            if (vsgInfo->configIdentity.l2blobConfig.ulL2blobMagicNumber != 
                flow->configIdentity.l2blobConfig.ulL2blobMagicNumber)
            {
    		  printk("Proces 5 : flow found : L2blob change\n");
		  printk("VSG Magic Number = %d, flow Magic Number =%d\n",
			vsgInfo->configIdentity.l2blobConfig.ulL2blobMagicNumber,
			flow->configIdentity.l2blobConfig.ulL2blobMagicNumber);
	          if (flow->l2.n)
		  {
		            neigh_release(flow->l2.n);
		            flow->l2.n = NULL;
		            asf_debug("Setting flow->l2.n = NULL\n");
                 }
                if (flow->l2.rth)
                {
                    dst_release(&flow->l2.rth->dst);
                    flow->l2.rth = NULL;
                    asf_debug("Setting flow->l2.rth = NULL\n");
                }
                if (flow->l2.res.fi)
 	            {
                    fib_info_put(flow->l2.res.fi);
                    flow->l2.res.fi = NULL;
                    asf_debug("Setting flow->l2.res.fi = NULL\n");
                }
                flow->odev = NULL;
		
                memset(&flow->l2.res, 0, sizeof(struct fib_result));
                flow->l2.fl.flowi4_iif = 0;
            }
        }
	if ((flow->l2.n) &&  ((flow->l2.n->flags & NUD_FAILED) || 
		    (flow->l2.n->flags & NUD_STALE)))
        {
	        /* BBB */
	        neigh_release(flow->l2.n);
	        flow->l2.n = NULL;
	    }
    }
    else
    {
    	  printk("Proces 6 : flow not found\n");
	    /* Check if the flow can be offloaded */
	if (_is_route_cacheable(aDev, iph) == ASF_TRUE)
        {
    	  printk("Proces 7 : creating cache entry\n");
           
            if (fwd_create_flow4(ulVsgId, iph->saddr, iph->daddr,
                iph->tos, hashVal, &flow) == ASFFWD_RESPONSE_SUCCESS)
            {
                printk("Process 8: create flow succeeded\n");
	        _fwd_flow_delete_lru();
	        _fwd_flow_insert(flow, (fwd_flow4_t *)_fwd_bucket_by_hash(hashVal)); 
		printk("Inserted flow in cache\n");
		
               _fwd_flow_insert_in_cache(flow);
		printk("Inserted in cache\n");
            } 
            else
	    {
                printk("Process 9: create flow failed\n");
	        /* Send it up to Stack */
		 ASF_netif_receive_skb(skb);
		 return;
	    }
        }
    }
  
    if (flow)
    {
        printk("Process 10: flow found or created\n");
        flow_stats = &flow->stats;
        flow_stats->ulInPkts++;
        if (unlikely(!(flow->l2.rth)))
        {
            printk("Process 11: Resolving Route\n");
	    if ((asf_ipv4_dst_blackhole_ops.kmem_cachep) == NULL)
		printk("kmem_cachep = NULL\n");
	    else
                printk("kmem_cachep = 0x%p\n", asf_ipv4_dst_blackhole_ops.kmem_cachep);
            ret = asf_fwd_route_resolve(aDev, flow, &Buffer, iph->tos);
	    if (ret == 0)
	    {
                vsgInfo = asf_ffp_get_vsg_info_node(ulVsgId);
		if (vsgInfo != NULL)
		{
                    flow->configIdentity.l2blobConfig.ulL2blobMagicNumber = 
                        vsgInfo->configIdentity.l2blobConfig.ulL2blobMagicNumber;
		}
		
            }	
	    printk("Process 12: Resolving route\n");
	    asf_debug("asf_fib_lookup returned %d ret\n", ret);
        }
	printk("Process 11-a ret = %d\n", ret);
        if (!ret)
        {
            printk("Process 12: Proceeding to send l2blob_len%d\n", flow->l2blob_len);
            printk("Process 12: Proceeding to send \n");
            if (((skb->len + ((flow->l2blob_len > 0) ?
		    flow->l2blob_len : LL_RESERVED_SPACE(flow->l2.rth->dst.dev))) >
		    (flow->pmtu + ETH_HLEN)) ||
		    (skb_shinfo(skb)->frag_list)) 
	    {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
                struct sk_buff *pSkb, *pTempSkb;
		printk("Going into fragmentation: skb->len  = %d, flow->l2blob_len = %d, LL_RESERVED=%d, skb_shinfo(skb)->frag_list=%p, flow->pmtu = %d, ETH_HLEN=%d\n", skb->len, flow->l2blob_len, LL_RESERVED_SPACE(flow->l2.rth->dst.dev), skb_shinfo(skb)->frag_list, flow->pmtu, ETH_HLEN);

                if (unlikely(!(iph->frag_off & IP_DF)))
                {
	            /* Need to call fragmentation routine */
	            asf_debug("attempting to fragment and xmit\n");

		    if (!asfIpv4Fragment(skb, flow->pmtu,
		        /*32*/ ((flow->l2blob_len > 0) ?
	                flow->l2blob_len : 
	                LL_RESERVED_SPACE(flow->l2.rth->dst.dev)),
		        0 /* FALSE */, flow->odev,
		        &pSkb)) 
                    {
		        int ulFrags = 0;
		        /* asf_display_frags(pSkb, "Before Xmit");*/
		        //asf_display_skb_list(pSkb, "Before Xmit");
		        for (; pSkb != NULL; pSkb = pTempSkb) 
                        {
		            ulFrags++;
		            pTempSkb = pSkb->next;
		            asf_debug("Next skb = 0x%x\r\n", pTempSkb);
		            pSkb->next = NULL;
                            iph = ip_hdr(pSkb);

			    pSkb->pkt_type = PACKET_FASTROUTE;
			               
			    ip_decrease_ttl(iph);

			    pSkb->data -= flow->l2blob_len;
			    pSkb->len += flow->l2blob_len;

			   if (pSkb->data < pSkb->head) 
			   {
			        asf_debug("SKB's head > data ptr .. UNDER PANIC!!!\n");
			        ASFSkbFree(pSkb);
			        continue;
			   }

			   pSkb->dev = flow->odev;

     			   if (unlikely(!(flow->l2.n)))
       			   {
       			       ret = asf_fwd_arp_resolve(flow, &Buffer);
            		   }		
			   asf_debug("asf_fwd_arp_resolve returned %d ret\n", ret);
			   if (ret == 2)
			   {
			       asf_debug("ARP module will take care of sending packet\n");
			       continue;
			   }
			   else if (ret < 0)
			   {
			       /* Should not happen  */
			       asf_debug("arp_resolve returned %d\n", ret);
			       ASFSkbFree(pSkb);
			       continue;
			   }

                           asfCopyWords((unsigned int *)pSkb->data, (unsigned int *)flow->l2.n->ha, 6 );
			   asfCopyWords((unsigned int *)(pSkb->data + 6), (unsigned int *)flow->l2.n->dev->dev_addr,  6);

			   asf_debug("skb->network_header = 0x%x, skb->transport_header = 0x%x\r\n",
			       skb_network_header(pSkb), skb_transport_header(pSkb));
			   asf_debug("Transmitting  buffer = 0x%x dev->index = %d\r\n",
			       pSkb, pSkb->dev->ifindex);

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			   gstats->ulOutBytes += pSkb->len;
			   flow_stats->ulOutBytes += pSkb->len;
			   vstats->ulOutBytes += pSkb->len;
#endif
			   txq = netdev_get_tx_queue(pSkb->dev, skb->queue_mapping);

			   printk("20: Sending it out\n");
			   if (asfDevHardXmit(pSkb->dev, pSkb) != 0) {
			       asf_debug("Error in transmit: Should not happen\r\n");
			       ASFSkbFree(pSkb);
			    } 
                            else
			        pSkb->dev->trans_start = txq->trans_start = jiffies;
			
		        }
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		        gstats->ulOutPkts += ulFrags;
		        vstats->ulOutPkts += ulFrags;
		        flow_stats->ulOutPkts += ulFrags;
#endif
		    }
		    else
		    {
		        printk("asfcore.c:%d - asfIpv4Fragment returned NULL!!\n", __LINE__);
		    }
	        }
                else
                {
                    /* Send it to Stack DF bit set*/
                    printk("DF bit set: Sending it up to Stack\n");
		    ASF_netif_receive_skb(skb);
                }
		return;
                printk("Fragments done: returning\n");
            }
            printk("decreasing TTL\n"); 
           
            asf_debug_l2("decreasing TTL\n"); 
            ip_decrease_ttl(iph);

            asf_debug_l2("attempting to xmit non fragment packet\n");
            skb->dev = flow->odev;
            if (!(flow->l2.n))
            {
                printk("Resolving Arp\n");
                /* Proceed to arp lookup */
	        ret = asf_fwd_arp_resolve(flow, &Buffer);
	        asf_debug("asf_fwd_arp_resolve returned %d ret\n", ret);
                if (ret == 2)
	        {
	            asf_debug("ARP module will take care of sending packet\n");
	            return;
	        }
	        else 
                {
                    if (ret < 0)
	            {
	                /* Should not happen  */
                        asf_debug("arp_resolve returned %d\n", ret);
		        ASFSkbFree(skb);
		        return;
	            }
	            /* Ret == 0 ; fallthrough */
	        }
	      }
	      /* Update the MAC address information */
	      skb->len += flow->l2blob_len;
	      skb->data -= flow->l2blob_len;

	      asfCopyWords((unsigned int *)skb->data, (unsigned int *)flow->l2.n->ha,  6);
	      asfCopyWords((unsigned int *)(skb->data+6), (unsigned int *)flow->l2.n->dev->dev_addr, 6);

	     if(unlikely(skb->data < skb->head))
		printk("Error: Not enough room to write header: Writing into other space \n");

	      skb->pkt_type = PACKET_FASTROUTE;
	    
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
              gstats->ulOutBytes += skb->len;
              flow_stats->ulOutBytes += skb->len;
              vstats->ulOutBytes += skb->len;
#endif
              netdev = skb->dev;
	      txq = netdev_get_tx_queue(skb->dev, skb->queue_mapping);
	      printk("Sending packet\n");
	      if (asfDevHardXmit(skb->dev, skb)) {
	        XGSTATS_INC(DevXmitErr);
	        asf_debug("Error in transmit: may happen as we don't check for gfar free desc\n");
		printk("Error in transmit\n");
	        ASFSkbFree(skb);
	      } else
	          netdev->trans_start = txq->trans_start = jiffies;
#endif
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	      gstats->ulOutPkts++;
	      vstats->ulOutPkts++;
	      flow_stats->ulOutPkts++;
#endif
	      printk("Returning after sending\n");
        }
	else
	{
	  printk("ret_100: returning to stack\n");
          ASF_netif_receive_skb(skb);
	  return;
        }
    }
}


static inline fwd_flow4_t *fwd_flow4_by_id_ex(
	unsigned int ulIndex, 
	unsigned int ulMagicNum)
{
	return (fwd_flow4_t *) 
		((fwd4_ptrArray.pBase[ulIndex].ulMagicNum == ulMagicNum) ? 
		fwd4_ptrArray.pBase[ulIndex].pData : NULL);
}

unsigned int asfFwd4InacTmrCb(unsigned int ulVSGId,
				    unsigned int ulIndex, 
				    unsigned int ulMagicNum, 
				    unsigned int ulHashVal, 
				    bool bIPv6)
{
	fwd_flow4_t *flow;
	
	asf_debug_l2("vsg %u idx %u magic %u hash %u\n", ulVSGId, ulIndex, ulMagicNum, ulHashVal);

	flow = fwd_flow4_by_id_ex(ulIndex, ulMagicNum);
	if (flow)
	{
		_fwd_flow_del_in_cache(flow);
	}
	else
	{
	    asf_debug("Inac Tmr: flow not found {%u, %u}\n", ulIndex, ulMagicNum);
	}
	return 0;
}



#define ASF_FWD4_INAC_TIME_INTERVAL 1    /* inter bucket gap */
#define ASF_FWD4_INAC_TIMER_BUCKT 2048    /* Max inactity timer value  */
#define ASF_FWD4_NUM_RQ_ENTRIES  (256)

static int asf_fwd_init_flow4_table(void)
{
    unsigned int max_num;
    int i;
    ptrIArry_nd_t   *node;

    max_num = fwd_max_flows/20;
    get_random_bytes(&asf_fwd_hash_init_value, sizeof(asf_fwd_hash_init_value));

    printk("1\n");
    if (asfCreatePool("FwdFlow", max_num,
		max_num, (max_num/2),
		sizeof(fwd_flow4_t),
		&fwd_flow4_pool_id) != 0)
    {
		asf_err("Failed to initialize forward flow pool\n");
		return -ENOMEM;
    }

    fwd_flow_cache = kzalloc((sizeof(fwd4_bucket_t ) *fwd_hash_buckets),
	    GFP_KERNEL);

    if (fwd_flow_cache == NULL)
    {
	asf_err("Unable to allocate memory for flow table\n");
	return -ENOMEM;
    }
    printk("2\n");

    for (i=0; i < fwd_hash_buckets; i++)
    {
#ifdef ASF_FWD_GLOBAL_CACHE
	spin_lock_init(&fwd_flow_cache[i].lock);
#endif
        fwd_flow_cache[i].pNext = (fwd_flow4_t *)(&fwd_flow_cache[i]);
    	fwd_flow_cache[i].pPrev = fwd_flow_cache[i].pNext;
    }

    printk("3\n");

    node = kzalloc((sizeof(ptrIArry_nd_t)*fwd_max_flows), GFP_KERNEL);

    if (NULL == node) {
	return -ENOMEM;
    }
    printk("4\n");
    ptrIArray_setup(&fwd4_ptrArray, node, fwd_max_flows, 1);


	if (asfCreatePool("FwdInacTimers", max_num,
			  max_num, (max_num/2),
			  sizeof(asfTmr_t),
			  &fwd4_inac_tmr_pool_id)) {
		asf_err("Error in creating pool for Inac Timers\n");
		return -ENOMEM;
	}

    printk("4\n");
	asf_debug("Timer : InacTimer_PoolId = %d\r\n",
		 fwd4_inac_tmr_pool_id);

	asf_print("Instantiating blob timer wheels\n");

	if (asfTimerWheelInit(ASF_FWD4_INAC_TMR_ID, 0,
			      ASF_FWD4_INAC_TIMER_BUCKT, ASF_TMR_TYPE_SEC_TMR,
			      ASF_FWD4_INAC_TIME_INTERVAL, ASF_FWD4_NUM_RQ_ENTRIES) == 1) {
		asf_err("Error in initializing L2blob Timer wheel\n");
		return -ENOMEM;
	}

    printk("5\n");
	asf_print("Instantiating inac timer wheels\n");
	if (asfTimerAppRegister(ASF_FWD4_INAC_TMR_ID, 0,
				(asfTmrCbFn) asfFwd4InacTmrCb,
				fwd4_inac_tmr_pool_id)) {
		asf_debug("Error in registering Cb Fn/Pool Id\n");
		return -ENOMEM;
	}
    fwd_register_proc();
    printk("6\n");
    return 0;
}

    
void asf_fwd_cleanup_all_flow4s(void)
{
	int i;
	fwd4_bucket_t    *bkt;
	fwd_flow4_t      *head, *flow, *temp;

	for (i = 0; i < fwd_hash_buckets; i++) {
		bkt = &fwd_flow_cache[i];
		head = (fwd_flow4_t *)  bkt;
		flow = head->pNext;

		/* Now the list is detached from the bucket */
		while (flow != head) {
			temp = flow;
			flow = flow->pNext;
			if (temp->pInacTmr) {
				asfTimerStop(ASF_FWD4_INAC_TMR_ID, 0, temp->pInacTmr);
			}
		}
	}
}

static void asf_fwd_destroy_all_flow4s(void)
{
	int i;
	fwd_flow4_t	*head, *flow, *temp;

	for (i = 0; i < fwd_hash_buckets; i++) {
		head = (fwd_flow4_t *) &fwd_flow_cache[i];
		flow = head->pNext;
		while (flow != head) {
			temp = flow;
			flow = flow->pNext;
		
			if (temp->l2.res.fi)
				fib_info_put(temp->l2.res.fi);

			if (temp->l2.rth)
				dst_release(&(temp->l2.rth->dst));

			if (temp->l2.n)
				neigh_release(temp->l2.n);

			ptrIArray_delete(&fwd4_ptrArray, temp->id.ulArg1, NULL);
			
			fwd_flow4_free(temp);
		}
	}
}

static void asf_fwd_destroy_flow4_table(void)
{
	/*asf_fwd_cleanup_all_flows(); */
	asfTimerWheelDeInit(ASF_FWD4_INAC_TMR_ID, 0);

	asf_fwd_destroy_all_flow4s();

	asf_debug("DestroyPool FlowPool\n");
	if (asfDestroyPool(fwd_flow4_pool_id) != 0)
		asf_debug("failed to destroy flow mpool\n");

	if (asfDestroyPool(fwd4_inac_tmr_pool_id) != 0)
		asf_debug("failed to destroy flow mpool\n");

	/* free the table bucket array */
	kfree(fwd_flow_cache);

	ptrIArray_cleanup(&fwd4_ptrArray);
}

static void asf_fwd_destroy_cache4(void)
{ 
    kfree(fwd_cache);
}


int asf_fwd_init_cache(void)
{
    fwd_cache_t *per_cpu_fwd_cache;
    int cpu;
    int vsg;

    fwd_cache = asfAllocPerCpu(sizeof(fwd_cache_t)*asf_fwd_max_vsgs);
    if (fwd_cache == NULL)
    {
	asf_err("Error in allocating forward cache\n");
	return ASFFWD_RESPONSE_FAILURE;
    }

    printk("1 NR_CPUS =%d\n", NR_CPUS);
    for (cpu=0; cpu< 2; cpu++)
    {
        printk("cpu=%d\n", cpu);
	for (vsg = 0; vsg < asf_fwd_max_vsgs; vsg++)
	{
        printk("vsg=%d\n", vsg);
            per_cpu_fwd_cache = asfPerCpuPtr(fwd_cache, cpu) + vsg;

            if (per_cpu_fwd_cache == NULL)
            {
               printk("per_cpu_fwd_cache = NULL\n");
	       continue;
            }
	   
	   per_cpu_fwd_cache->count = 0;
	   per_cpu_fwd_cache->pHead = NULL;
           per_cpu_fwd_cache->pTail = NULL;
        }
    }
    printk("7\n");
    return 0;
}
		

int asf_fwd_init(void)
{
	int err;
	ASFCap_t	asf_cap;

        printk(" 1 fwd_init: kmem_cachep = 0x%p\n", asf_ipv4_dst_blackhole_ops.kmem_cachep);

	/*Checks are intoduced to prevent the asf initialization
	with negative parameter*/

	//ASFGetCapabilities(&asf_cap);
	asf_fwd_max_vsgs =  2 /* asf_cap.ulNumVSGs */;
	if (fwd_max_flows< 0) {
		asf_err("invalid number of flows (%d).ASF is not initialized.\n",
			fwd_max_flows);
		return -1;
	}
	fwd_max_flows_per_vsg = fwd_max_flows/asf_fwd_max_vsgs;

	if (fwd_hash_buckets < 0) {
		asf_err("invalid bucket size(%d).ASF is not initialized.\n",
			fwd_hash_buckets);
		return -1;
	}

        printk(" 2 fwd_init: kmem_cachep = 0x%p\n", asf_ipv4_dst_blackhole_ops.kmem_cachep);
	
	printk("Allocating perCpu\n");

	asf_debug("Allocating perCpu memory for global stats\n");
	fwd_gstats = asfAllocPerCpu(sizeof(ASFFwdGlobalStats_t));
	if (!fwd_gstats) {
		asf_err("Failed to allocate per-cpu memory for global statistics\n");
		return -ENOMEM;
	}

        printk(" 3 fwd_init: kmem_cachep = 0x%p\n", asf_ipv4_dst_blackhole_ops.kmem_cachep);

	asf_debug("Allocating perCpu memory for VSG stats\n");
	fwd_vsg_stats = asfAllocPerCpu(sizeof(ASFFwdVsgStats_t)*asf_fwd_max_vsgs);
	if (!fwd_vsg_stats) {
		asf_err("Failed to allocate per-cpu memory for VSG statistics\n");
		return -ENOMEM;
	}

        printk(" 4 fwd_init: kmem_cachep = 0x%p\n", asf_ipv4_dst_blackhole_ops.kmem_cachep);
	asf_print("Initializing Flow Table\n");
	printk("Initializing Flow Table\n");
	err = asf_fwd_init_flow4_table();
	if (err) {
		return err;
	}
	printk("Initializing cache\n");

        printk(" 5 fwd_init: kmem_cachep = 0x%p\n", asf_ipv4_dst_blackhole_ops.kmem_cachep);
	err = asf_fwd_init_cache();
	if (err) {
		asf_fwd_destroy_flow4_table();
		return err;
	}
                printk(" 6 fwd_init: kmem_cachep = 0x%p\n", asf_ipv4_dst_blackhole_ops.kmem_cachep);

	ASFFFPRegisterFwdFunctions((ASFFwdFn_f)ASFFWD_Process);
        printk(" fwd_init: kmem_cachep = 0x%p\n", asf_ipv4_dst_blackhole_ops.kmem_cachep);

        printk("8\n");
	return err;
}

int asf_fwd_deinit(void)
{
	asf_unregister_proc();
	asf_debug("Free PerCpu memory of Vsg Stats\n");
	asfFreePerCpu(fwd_vsg_stats);

	asf_debug("Free PerCpu memory of Global Stats\n");
	asfFreePerCpu(fwd_gstats);

	printk("1\n");
//	asf_fwd_destroy_cache4();
	printk("2\n");
	asf_fwd_destroy_flow4_table();
	printk("3\n");
}


MODULE_AUTHOR("Freescale Semiconductor, Inc");
MODULE_DESCRIPTION("Application Specfic FastPath Forward");
MODULE_LICENSE("Dual BSD/GPL");

static int __init ASFFwd_Init(void)
{
	//Commented for running with single core
	//asf_fwd_init();
#ifdef ASF_IPV6_FP_SUPPORT
	asf_fwd6_init();
#endif
	return 0;
}


static void __exit ASFFwd_Exit(void)
{
	//Commented for running with single core
	//asf_fwd_deinit();
#ifdef ASF_IPV6_FP_SUPPORT
	asf_fwd6_deinit();
#endif
}

module_init(ASFFwd_Init);
module_exit(ASFFwd_Exit);
