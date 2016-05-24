/**************************************************************************
 * Copyright 2010-2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	fwdpvt.h
 *
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 * History:
 */
#ifndef _FWD_PVT_H
#define _FWD_PVT_H


#ifdef ASF_IPV6_FP_SUPPORT
typedef struct ASFFwdFlow6Stats_s {
	/* Number of Received Packets */
	ASF_uint32_t    ulInPkts;

	/* Number of Received  Bytes */
	ASF_uint32_t    ulInBytes;

	/* Number of Packets Sent out */
	ASF_uint32_t    ulOutPkts;

	/* Number of bytes Sent out. */
	ASF_uint32_t    ulOutBytes;
} ASFFwdFlow6Stats_t;
	
typedef struct ASFFwdVsg6Stats_s {
	ASF_uint32_t	ulInPkts;
	ASF_uint32_t	ulInPktFlowMatches; /* Total number of packets found a matching flow */
	ASF_uint32_t	ulOutPkts;
	ASF_uint32_t	ulOutBytes;
} ASFFwdVsg6Stats_t;
#endif

typedef struct ASFFwdFlowStats_s {
	/* Number of Received Packets */
	ASF_uint32_t    ulInPkts;

	/* Number of Received  Bytes */
	ASF_uint32_t    ulInBytes;

	/* Number of Packets Sent out */
	ASF_uint32_t    ulOutPkts;

	/* Number of bytes Sent out. */
	ASF_uint32_t    ulOutBytes;
} ASFFwdFlowStats_t;
	
typedef struct ASFFwdVsgStats_s {
	ASF_uint32_t	ulInPkts;
	ASF_uint32_t	ulInPktFlowMatches; /* Total number of packets found a matching flow */
	ASF_uint32_t	ulOutPkts;
	ASF_uint32_t	ulOutBytes;
} ASFFwdVsgStats_t;

typedef struct fwd_flow_id_s
{
	ASF_uint32_t ulArg1;
	ASF_uint32_t ulArg2;
}fwd_flow_id_t;
	

typedef struct fwd_flow4_s{
#ifdef ASF_FWD_GLOBAL_CACHE
	struct rcu_head rcu;
#endif
	/* For the 3 tuple based hash list */
	struct fwd_flow4_s		*pPrev;
	struct fwd_flow4_s		*pNext;

	/* For the activity based linear linked list */
	struct fwd_flow4_s 		*pCachePrev;
	struct fwd_flow4_s		*pCacheNext;
	
	ASF_uint32_t	ulVsgId;
	ASF_IPv4Addr_t	ulSrcIp; /* Source IP Address */
	ASF_IPv4Addr_t	ulDestIp; /* Destination IP Address */
	ASF_uint8_t ucTos; /* Type of Service */
        ASF_uint32_t    l2blob_len;

	ASF_void_t	*as_flow_info;
	unsigned short	  bDeleted:1; /* tcp time stamp option to be checked or not ? */
	unsigned short	bHeap:1;
	
	ASFFFPConfigIdentity_t	configIdentity;
	struct net_device		*odev;
	ASF_uint32_t ulInacTime;
	asfTmr_t *pInacTmr;
	fwd_flow_id_t id;
	struct _ipv4 l2;
	ASF_uint32_t pmtu;
	ASFFwdFlowStats_t		stats;
}fwd_flow4_t;

#ifdef ASF_IPV6_FP_SUPPORT
typedef struct fwd_flow6_s{
#ifdef ASF_FWD_GLOBAL_CACHE
	struct rcu_head rcu;
#endif
	struct fwd_flow6_s       *pPrev;
	struct fwd_flow6_s       *pNext;

	/* For the activity based linear linked list */
	struct fwd_flow6_s 		*pCachePrev;
	struct fwd_flow6_s		*pCacheNext;

	ASF_uint32_t	ulVsgId;
	ASF_IPv6Addr_t	ipv6SrcIp; /* Source IPV6 Address */
	ASF_IPv6Addr_t	ipv6DestIp; /* Destination IPV6 Address */
	ASF_uint32_t flowlabel; /* Type of Service */
        ASF_uint32_t    l2blob_len;
	ASF_void_t	*as_flow_info;
	
	unsigned short	  bDeleted:1; /* tcp time stamp option to be checked or not ? */
	unsigned short	bHeap:1;

	ASFFFPConfigIdentity_t  configIdentity;
	struct net_device       *odev;
	ASF_uint32_t ulInacTime;
	asfTmr_t *pInacTmr;
	fwd_flow_id_t id;
	struct _ipv6 l2;
	ASF_uint32_t pmtu;
	ASFFwdFlowStats_t       stats;
}fwd_flow6_t;
#endif

typedef struct fwd4_bucket_s {
    fwd_flow4_t *pPrev;
    fwd_flow4_t *pNext;
#ifdef ASF_FWD_GLOBAL_CACHE
    spinlock_t lock;
#endif
}fwd4_bucket_t;

#ifdef ASF_IPV6_FP_SUPPORT
typedef struct fwd6_bucket_s {
    fwd_flow6_t *pPrev;
    fwd_flow6_t *pNext;

#ifdef ASF_FWD_GLOBAL_CACHE
   spinlock_t lock;
#endif	

}fwd6_bucket_t;
#endif



typedef struct fwd_cache_list_s{
	int	count;
	fwd_flow4_t *pHead;
	fwd_flow4_t *pTail;
}fwd_cache_t;

#ifdef ASF_IPV6_FP_SUPPORT
typedef struct fwd_cache6_list_s{
	int	count;
	fwd_flow6_t *pHead;
	fwd_flow6_t *pTail;
}fwd6_cache_t;
#endif

#endif

