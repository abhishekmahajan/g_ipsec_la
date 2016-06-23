/**************************************************************************
 * Copyright 2010-2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfpvt.h
 *
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 */
/* History
 *  Version	Date		Author		Change Description
 * 22 Jul 2011 - Sachin Saxena - Changes to introduce ASF tool kit support.
 *
*/
/******************************************************************************/

#ifndef __ASF_PVT_H
#define __ASF_PVT_H

#include <net/arp.h>
#include <net/ip_fib.h>
#include <net/route.h>
#include <linux/inetdevice.h>
#include <net/ip6_fib.h>

#include "asfdeps.h"
#include "asfipsec.h"


#ifdef ASF_FFP_XTRA_STATS
typedef struct ASFFFPXtraFlowStats_s {

} ASFFFPXtraFlowStats_t;

typedef struct ASFFFPXtraGlobalStats_s {
	ULONG   ulBridgePkts;
	ULONG   ulInvalidBridgeDev;
	ULONG   ulVlanPkts;
	ULONG   ulInvalidVlanDev;
	ULONG   ulPPPoEPkts;
	ULONG   ulPPPoEUnkPkts;
	ULONG   ulInvalidPPPoEDev;

	ULONG   ulNonIpPkts;
	ULONG   ulNonTcpUdpPkts;
	ULONG   ulVsgSzoneUnk;
	ULONG   ulInvalidCsum;

	ULONG   ulIpOptPkts;

	ULONG   ulLocalCsumVerify;
	ULONG   ulLocalBadCsum;
	ULONG   ulUdpBlankCsum;

	ULONG   ulIpOptProcFail;

	ULONG   ulIpFragPkts;
	ULONG   ulbDropPkts;

	ULONG   ulCondition1;
	ULONG   ulCondition2;

	ULONG   ulUdpPkts;
	ULONG   ulTcpPkts;
	ULONG   ulTcpHdrLenErr;
	ULONG   ulTcpTimeStampErr;
	ULONG   ulTcpOutOfSequenceErr;
	ULONG   ulTcpProcessErr;

	ULONG   ulNatPkts;
	ULONG   ulBlankL2blobInd;
	ULONG   ulFragAndXmit;
	ULONG   ulNormalXmit;
	ULONG   ulL2hdrAdjust;
	ULONG   ulDevXmitErr;
	ULONG   ulFlowEndInd;
	ULONG   ulPktCtxInacRefreshInd;
	ULONG   ulPktCtxL2blobInd;
	ULONG   ulNetIfQStopped;

	ULONG   ulCreateFlowsCmd;
	ULONG   ulCreateFlowsCmdVsgErr;
	ULONG   ulCreateFlowsCmdErrDown;
	ULONG   ulCreateFlowsCmdErrDown1;
	ULONG   ulCreateFlowsCmdErrDown2;
	ULONG   ulCreateFlowsCmdFailures;
	ULONG   ulDeleteFlowsCmd;
	ULONG   ulDeleteFlowsCmdFailures;
	ULONG   ulModifyFlowsCmd;
	ULONG   ulModifyFlowsCmdFailures;

	ULONG   ulBlobTmrCalls;
	ULONG   ulTmrCtxL2blobInd;
	ULONG   ulBlobTmrCtxBadFlow;

	ULONG   ulInacTmrCalls;
	ULONG   ulTmrCtxInacInd;
	ULONG   ulInacTmrCtxBadFlow1;
	ULONG   ulInacTmrCtxBadFlow2;

	ULONG   ulInacTmrCtxAutoFlowDel;

	ULONG   ulPktCmdTxInPkts;
	ULONG   ulPktCmdTxBlobRefresh;
	ULONG   ulPktCmdTxAutoFlowCreate;
	ULONG   ulPktCmdTxAutoFlowBlobRefresh;
	ULONG   ulPktCmdTxLogicalDevErr;
	ULONG   ulPktCmdTxNonIpErr;

	ULONG   ulPktCmdTxDummyPkt;
	ULONG   ulPktCmdTxValidPkt;
	ULONG   ulPktCmdTxFlowFound;
	ULONG   ulPktCmdTxBlobInitialUpdates;
	ULONG   ulPktCmdTxBlobTmrErr;
	ULONG   ulPktCmdTxInacTmrErr;
	ULONG   ulPktCmdTxVlanTag;
	ULONG   ulPktCmdTxSkbFrees;
	ULONG   ulPktCmdTxInvalidFlowErr;

	ULONG   ulPktCtxAutoFlowDel;
	ULONG   ulAutoFlowBlobRefreshSentUp;
	ULONG   ulAutoFlowCreateSentUp;

	ULONG   ulPktCmdTxHdrSizeErr;
	ULONG   ulPktCmdBlobSkbFrees;
	ULONG   ulPktCmdTxAutoDelFlows;
	ULONG   ulPktCmdTxAutoFlowCreateErr;


} ASFFFPXtraGlobalStats_t;

#define ACCESS_XGSTATS()	ASFFFPXtraGlobalStats_t	*xgstats = asfPerCpuPtr(asf_xgstats, smp_processor_id())
#define XGSTATS_INC(f)	(xgstats->ul##f++)
#define XGSTATS_DEC(f)	(xgstats->ul##f--)

#else
#define ACCESS_XGSTATS()
#define XGSTATS_INC(f)
#define XGSTATS_DEC(f)
#endif

typedef struct ASFFFPFlowId_s {

	unsigned int ulArg1;	/* Flow Index */
	unsigned int ulArg2;	/* Flow Magic Number */

} ASFFFPFlowId_t;


extern char *asf_version;

extern int ffp_max_flows;
extern int ffp_hash_buckets;
extern int asf_tcp_fin_timeout;

extern int asf_unregister_proc(void);
extern int asf_register_proc(void);

#ifdef ASF_IPSEC_FP_SUPPORT
extern ASFFFPIPSecInv4_f pFFPIPSecIn;
extern ASFFFPIPSecOutv4_f pFFPIPSecOut;
extern ASFFFPIPSecInVerifyV4_f pFFPIpsecInVerify;
extern ASFFFPIPSecProcessPkt_f pFFPIpsecProcess;
#endif
/* Need to hold (ETH_HDR+VLAN_HDR+PPPOE_HDR+PPP_HDR)
 *	14+4+6+2 = 26 (rounded to 28 to make it multiple of 4)
 */


typedef struct ffp_flow_s {
	/* Must be first entries in this structure to enable circular list */
	struct rcu_head	 rcu;
	struct ffp_flow_s       *pPrev;
	struct ffp_flow_s       *pNext;

	ASF_uint32_t	ulVsgId;
	ASF_uint32_t	ulZoneId;
	union {
		ASF_IPv4Addr_t	ulSrcIp; /* Source IP Address */
#ifdef ASF_IPV6_FP_SUPPORT
		ASF_IPv6Addr_t	ipv6SrcIp; /* Source IPV6 Address */
#endif
	};
	union {
		ASF_IPv4Addr_t	ulDestIp; /* Destination IP Address */
#ifdef ASF_IPV6_FP_SUPPORT
		ASF_IPv6Addr_t	ipv6DestIp; /* Destination IPV6 Address */
#endif
	};
	ASF_uint32_t	ulPorts; /* Source Port and Destination Port */
	ASF_uint8_t	ucProtocol; /* IP Protocol */
	ASF_void_t	*as_flow_info;

	/* Source IP Address */
	union {
		ASF_IPv4Addr_t    ulSrcNATIp;
#ifdef ASF_IPV6_FP_SUPPORT
		ASF_IPv6Addr_t    ipv6SrcNATIp;
#endif
	};

	/* Destination IP Address */
	union {
		ASF_IPv4Addr_t    ulDestNATIp;
#ifdef ASF_IPV6_FP_SUPPORT
		ASF_IPv6Addr_t    ipv6DestNATIp;
#endif
	};

	ASF_uint32_t	    ulNATPorts; /* Source NAT Port and Destination NAT Port */

	unsigned short	  bDrop:1, bNat:1, bVLAN:1, bPPPoE:1, bIPsecIn:1, bIPsecOut:1, bIP6IP4In:1, bIP6IP4Out:1,  bIP4IP6In:1, bIP4IP6Out:1;
	unsigned short	  bTcpOutOfSeqCheck:1; /* TCP state processing to be on or not */
	unsigned short	  bTcpTimeStampCheck:1; /* tcp time stamp option to be checked or not ? */
	unsigned short	  bDeleted:1; /* tcp time stamp option to be checked or not ? */
	unsigned short	bHeap:1;
	unsigned short	  pmtu;

	ASFFFPConfigIdentity_t  configIdentity;
	ASFFFPIpsecInfo_t       ipsecInfo;
	struct net_device       *odev;
#if 0 /* ROUTE_CACHE_IN_FLOW Subha: Changes: 02/11 */
	unsigned char	   l2blob[ASF_MAX_L2BLOB_LEN];
#else
	/* will be removed later : Subha: 02/11 */
	unsigned char	   l2blob[ASF_MAX_L2BLOB_LEN];
	unsigned short	  l2blob_len;
	union
	{
		struct _ipv4 ipv4;
#ifdef ASF_IPV6_FP_SUPPORT
		struct _ipv6 ipv6;
#endif
	};
#endif
	unsigned short	  tx_vlan_id; /*valid if bVLAN is 1*/
	ASFFFPFlowStats_t       stats;
#ifdef ASF_FFP_XTRA_STATS
	ASFFFPXtraFlowStats_t   xstats;
#endif
	ULONG	   ulInacTime; /* time in jiffies */
	ULONG	   ulLastPktInAt; /* jiffies at which last packet was seen */
	ULONG	   ulLastL2ValidationTime;

	unsigned int	    ulTcpTimeStamp;	/* current time stamp value */
	ASFFFPTcpState_t	tcpState;
	asfTmr_t		*pL2blobTmr;
	asfTmr_t		*pInacRefreshTmr;
	ASFFFPFlowId_t	  id;
	ASFFFPFlowId_t	  other_id;
#ifdef ASF_INGRESS_MARKER
	ASFMKInfo_t	mkinfo;
#endif
#ifdef ASF_EGRESS_QOS
	unsigned int tc_filter_res;
#endif
	/*bool bStatic;  -> 1 for Static and 0 for dynamic  */
} ffp_flow_t;


/* this structure is mapped to ffp_flow_t structure to maintain circular list.
 * So first two entries pPrev and pNext must be at the beginning of both structures.
 */
typedef struct ffp_bucket_s {
	/* Must be first two entries in this structure to enable circular list */
	struct rcu_head	 rcu;
	ffp_flow_t	      *pPrev;
	ffp_flow_t	      *pNext;

	spinlock_t	      lock;

} ffp_bucket_t;



typedef struct asf_vsg_info_s {
	struct rcu_head rcu;
	ASF_uint32_t    ulReasmTimeout;
	ASF_uint32_t    ulReasmMaxFrags;
	ASF_uint32_t    ulReasmMinFragSize;
	ASF_boolean_t   bDropOutOfSeq;
	ASF_uint32_t	ulTcpSeqNumRange;
	ASF_uint32_t	ulTcpRstSeqNumRange;
	ASFFFPConfigIdentity_t configIdentity;
	ASF_Modes_t		curMode;
	ASF_boolean_t 	bIPsec; /*IPsec function */
} asf_vsg_info_t;

extern asf_vsg_info_t *asf_ffp_get_vsg_info_node(ASF_uint32_t ulVSGId);

extern const struct	file_operations asf_interface_fops;
extern spinlock_t	asf_app_lock;

#ifdef ASF_DEBUG
#define SEARCH_MAX_PER_BUCKET	(1024)
#endif

static inline int asf_ffp_arp_resolve(ffp_flow_t *flow, 
	ASFBuffer_t *abuf)
{
	int ret;
	if ((ret = asf_arp_resolve(&flow->ipv4, abuf, flow->ulDestIp)) == 0)
	{
		/* For now assume it is just the ethernet header len; need to revisit for VLAN */
		flow->l2blob_len = ETH_HLEN;
	}
	return ret;
}
static inline int asf_ffp_route_resolve(ASFNetDevEntry_t *inputDev, ffp_flow_t *flow, ASFBuffer_t *abuf, ASF_uint8_t tos)
{
    int ret;
    if ((ret = asf_route_resolve(inputDev, &flow->ipv4, abuf, flow->ulDestIp, tos)) == 0)
    {
        if (flow->ipv4.rth->rt_pmtu)
	    flow->pmtu = flow->ipv4.rth->rt_pmtu;
	else
	    flow->pmtu = flow->ipv4.rth->dst.dev->mtu;

	flow->odev = flow->ipv4.rth->dst.dev;

   	return 0;
    }
    return ret;
}
#endif
