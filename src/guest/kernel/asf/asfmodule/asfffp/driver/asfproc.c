/**************************************************************************
 * Copyright 2010-2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfproc.c
 *
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 */
/* History
 *  Version	Date		Author		Change Description
 *
*/
/******************************************************************************/

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
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#include <asm/io.h>
#include <asm/irq.h>
#include <asm/uaccess.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#ifdef ASF_TERM_FP_SUPPORT
#include <linux/if_pmal.h>
#endif

#include <linux/version.h>
#include <linux/proc_fs.h>
#include "gplcode.h"
#include "asf.h"
#include "asfcmn.h"
#include "asfmpool.h"
#include "asftmr.h"
#include "asfroute.h"
#ifdef ASF_IPV6_FP_SUPPORT
#include "asfroute6.h"
#endif
#include "asfpvt.h"
#ifdef ASF_IPV6_FP_SUPPORT
#include "asfipv6pvt.h"
#endif
#include "asftcp.h"

/*
 * Implement following proc
 *	/proc/asf/flows
 *	/proc/asf/stats
 */

static int ffp_debug_show_index;
static int ffp_debug_show_count = 50;

extern void asf_ffp_cleanup_all_flows(void);

int fwd_debug_show_index;
int fwd_debug_show_count = 50;
EXPORT_SYMBOL(fwd_debug_show_index);
EXPORT_SYMBOL(fwd_debug_show_count);



extern ffp_bucket_t *ffp_flow_table;
extern ASFFFPGlobalStats_t *asf_gstats;
#ifdef ASF_FFP_XTRA_STATS
extern ASFFFPXtraGlobalStats_t *asf_xgstats;
#endif
extern ASFFFPVsgStats_t *asf_vsg_stats; /* per cpu vsg stats */
extern int asf_max_vsgs;
extern int asf_enable;
extern int asf_l2blob_refresh_npkts;
extern int asf_l2blob_refresh_interval;


#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
static int asf_exec_cmd_clear_stats(struct seq_file *m, void *v)
#else
static int asf_exec_cmd_clear_stats(char *page, char **start,
					 off_t off, int count,
					 int *eof, void *data)
#endif
{
	int vsg, cpu, i;
	ffp_flow_t *head, *flow;

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
	seq_printf(m, "Clearing Global%s Stats\n",
#else
	printk("Clearing Global%s Stats\n",
#endif
#ifdef ASF_FFP_XTRA_STATS
	       " and XtraGlobal"
#else
	       ""
#endif
	    );

	for_each_online_cpu(cpu)
	{
		ASFFFPGlobalStats_t *gstats;
#ifdef ASF_FFP_XTRA_STATS
		ASFFFPXtraGlobalStats_t *xgstats;
#endif
		gstats = asfPerCpuPtr(asf_gstats, cpu);
		memset(gstats, 0, sizeof(*gstats));

#ifdef ASF_FFP_XTRA_STATS
		xgstats = asfPerCpuPtr(asf_xgstats, cpu);
		memset(xgstats, 0, sizeof(*xgstats));
#endif
	}

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
	seq_printf(m, "Clearing VSG Stats\n");
#else
	printk("Clearing VSG Stats\n");
#endif
	for (vsg = 0 ; vsg < asf_max_vsgs ; vsg++) {
		for_each_online_cpu(cpu)
		{
			ASFFFPVsgStats_t *vstats;
			vstats = asfPerCpuPtr(asf_vsg_stats, cpu)+vsg;
			memset(vstats, 0, sizeof(*vstats));
		}
	}

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
	seq_printf(m, "Clearing Flow Stats\n");
#else
	printk(KERN_INFO "Clearing Flow Stats\n");
#endif
	for (i = 0; i < ffp_hash_buckets; i++) {
		head = (ffp_flow_t *)  &ffp_flow_table[i];
		for (flow = head->pNext; flow != head; flow = flow->pNext) {
			if (flow == flow->pNext)
				break;
			flow->stats.ulInPkts = 0;
			flow->stats.ulInBytes = 0;
			flow->stats.ulOutPkts = 0;
			flow->stats.ulOutBytes = 0;
		}
	}
	return 0;
}


#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
static int asf_exec_cmd_clear_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, asf_exec_cmd_clear_stats, NULL);
}
#endif


static struct ctl_table asf_proc_table[] = {
	{
		.procname       = "ffp_max_flows",
		.data	   = &ffp_max_flows,
		.maxlen	 = sizeof(int),
		.mode	   = 0444,
		.proc_handler   = proc_dointvec,
	} ,
	{
		.procname       = "ffp_max_vsgs",
		.data	   = &asf_max_vsgs,
		.maxlen	 = sizeof(int),
		.mode	   = 0444,
		.proc_handler   = proc_dointvec,
	} ,
	{
		.procname       = "ffp_hash_buckets",
		.data	   = &ffp_hash_buckets,
		.maxlen	 = sizeof(int),
		.mode	   = 0444,
		.proc_handler   = proc_dointvec,
	} ,
	{
		.procname       = "l2blob_refresh_npkts",
		.data	   = &asf_l2blob_refresh_npkts,
		.maxlen	 = sizeof(int),
		.mode	   = 0644,
		.proc_handler   = proc_dointvec,
	} ,
	{
		.procname       = "l2blob_refresh_interval",
		.data	   = &asf_l2blob_refresh_interval,
		.maxlen	 = sizeof(int),
		.mode	   = 0644,
		.proc_handler   = proc_dointvec,
	} ,
	{
		.procname       = "ffp_debug_show_index",
		.data	   = &ffp_debug_show_index,
		.maxlen	 = sizeof(int),
		.mode	   = 0644,
		.proc_handler   = proc_dointvec,
	} ,
	{
		.procname       = "ffp_debug_show_count",
		.data	   = &ffp_debug_show_count,
		.maxlen	 = sizeof(int),
		.mode	   = 0644,
		.proc_handler   = proc_dointvec,
	} ,
	{
		.procname       = "fwd_debug_show_index",
		.data	   = &fwd_debug_show_index,
		.maxlen	 = sizeof(int),
		.mode	   = 0644,
		.proc_handler   = proc_dointvec,
	} ,
	{
		.procname       = "fwd_debug_show_count",
		.data	   = &fwd_debug_show_count,
		.maxlen	 = sizeof(int),
		.mode	   = 0644,
		.proc_handler   = proc_dointvec,
	} ,
	{}
} ;

static struct ctl_table asf_proc_root_table[] = {
	{
		.procname       = "asf",
		.mode	   = 0555,
		.child	  = asf_proc_table,
	} ,
	{}
} ;

/* Will be used by FWD module */
struct ctl_table_header *asf_proc_header;
EXPORT_SYMBOL(asf_proc_header);
struct proc_dir_entry *asf_dir;
EXPORT_SYMBOL(asf_dir);

#define ASF_PROC_GLOBAL_STATS_NAME	"global_stats"
#ifdef ASF_FFP_XTRA_STATS
#define ASF_PROC_XTRA_GLOBAL_STATS_NAME	"xglobal_stats"
#define ASF_PROC_XTRA_FLOW_STATS_NAME	"xflow_stats"
#endif
#define ASF_PROC_VSG_STATS_NAME		"vsg_stats"
#define ASF_PROC_RESET_STATS_NAME	"reset_stats"
#define ASF_PROC_IFACE_MAPS		"ifaces"
#define ASF_PROC_FLOW_STATS_NAME	"flow_stats"
#ifdef ASF_IPV6_FP_SUPPORT
#define ASF_PROC_FLOW_IPV6_STATS_NAME	"flow_ipv6_stats"
#endif
#define ASF_PROC_FLOW_DEBUG_NAME	"flow_debug"


#define GSTATS_SUM(a) (total.ul##a += gstats->ul##a)
#define GSTATS_TOTAL(a) (ULONG) total.ul##a


#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
static int display_asf_proc_global_stats(struct seq_file *m, void *v)
#else
static int display_asf_proc_global_stats(char *page, char **start,
					 off_t off, int count,
					 int *eof, void *data)
#endif
{
	ASFFFPGlobalStats_t total;
	int cpu;

	memset(&total, 0, sizeof(total));

	for_each_online_cpu(cpu)
	{
		ASFFFPGlobalStats_t *gstats;
		gstats = asfPerCpuPtr(asf_gstats, cpu);
		GSTATS_SUM(InPkts);
		GSTATS_SUM(InPktFlowMatches);
		GSTATS_SUM(OutPkts);
		GSTATS_SUM(OutBytes);
		GSTATS_SUM(FlowAllocs);
		GSTATS_SUM(FlowFrees);
		GSTATS_SUM(FlowAllocFailures);
		GSTATS_SUM(FlowFreeFailures);
		GSTATS_SUM(ErrCsum);
		GSTATS_SUM(ErrIpHdr);
		GSTATS_SUM(ErrIpProtoHdr);
		GSTATS_SUM(ErrAllocFailures);
		GSTATS_SUM(MiscFailures);
		GSTATS_SUM(ErrTTL);
		GSTATS_SUM(PktsToFNP);
	}

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
	seq_printf(m, "IN %lu IN-MATCH %lu OUT %lu OUT-BYTES %lu\n",
	       GSTATS_TOTAL(InPkts), GSTATS_TOTAL(InPktFlowMatches), GSTATS_TOTAL(OutPkts), GSTATS_TOTAL(OutBytes));

	seq_printf(m, "FLOW: ALLOC %lu FREE %lu ALLOC-FAIL %lu FREE-FAIL %lu\n",
	       GSTATS_TOTAL(FlowAllocs), GSTATS_TOTAL(FlowFrees),
	       GSTATS_TOTAL(FlowAllocFailures), GSTATS_TOTAL(FlowFreeFailures));

	seq_printf(m, "ERR: CSUM %lu IPH %lu IPPH %lu AllocFail %lu MiscFail %lu TTL %lu\n",
	       GSTATS_TOTAL(ErrCsum), GSTATS_TOTAL(ErrIpHdr),
	       GSTATS_TOTAL(ErrIpProtoHdr), GSTATS_TOTAL(ErrAllocFailures),
	       GSTATS_TOTAL(MiscFailures), GSTATS_TOTAL(ErrTTL));

	seq_printf(m, "MISC: TO-FNP %lu\n", GSTATS_TOTAL(PktsToFNP));
#else
	printk("IN %lu IN-MATCH %lu OUT %lu OUT-BYTES %lu\n",
	       GSTATS_TOTAL(InPkts), GSTATS_TOTAL(InPktFlowMatches), GSTATS_TOTAL(OutPkts), GSTATS_TOTAL(OutBytes));

	printk("FLOW: ALLOC %lu FREE %lu ALLOC-FAIL %lu FREE-FAIL %lu\n",
	       GSTATS_TOTAL(FlowAllocs), GSTATS_TOTAL(FlowFrees),
	       GSTATS_TOTAL(FlowAllocFailures), GSTATS_TOTAL(FlowFreeFailures));

	printk("ERR: CSUM %lu IPH %lu IPPH %lu AllocFail %lu MiscFail %lu TTL %lu\n",
	       GSTATS_TOTAL(ErrCsum), GSTATS_TOTAL(ErrIpHdr),
	       GSTATS_TOTAL(ErrIpProtoHdr), GSTATS_TOTAL(ErrAllocFailures),
	       GSTATS_TOTAL(MiscFailures), GSTATS_TOTAL(ErrTTL));

	printk("MISC: TO-FNP %lu\n", GSTATS_TOTAL(PktsToFNP));
#endif

	return 0;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
static int display_asf_proc_global_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, display_asf_proc_global_stats, NULL);
}
#endif


#ifdef ASF_FFP_XTRA_STATS
#define XGSTATS_SUM(a) (total.ul##a += xgstats->ul##a)
#define XGSTATS_TOTAL(a) total.ul##a
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
#define XGSTATS_DISP(m, a) seq_printf(m, " " #a " = %lu\n", total.ul##a)
#else
#define XGSTATS_DISP(a) printk(" " #a " = %lu\n", total.ul##a)
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
static int display_asf_proc_global_stats(struct seq_file *m, void *v)
#else
static int display_asf_proc_xtra_global_stats(char *page, char **start,
					      off_t off, int count,
					      int *eof, void *data)
#endif
{
	ASFFFPXtraGlobalStats_t total;
	int cpu;

	memset(&total, 0, sizeof(total));

	for_each_online_cpu(cpu)
	{
		ASFFFPXtraGlobalStats_t *xgstats;
		xgstats = asfPerCpuPtr(asf_xgstats, cpu);

		XGSTATS_SUM(BridgePkts);
		XGSTATS_SUM(InvalidBridgeDev);
		XGSTATS_SUM(VlanPkts);
		XGSTATS_SUM(InvalidVlanDev);
		XGSTATS_SUM(PPPoEPkts);
		XGSTATS_SUM(PPPoEUnkPkts);
		XGSTATS_SUM(InvalidPPPoEDev);
		XGSTATS_SUM(NonIpPkts);
		XGSTATS_SUM(NonTcpUdpPkts);
		XGSTATS_SUM(VsgSzoneUnk);
		XGSTATS_SUM(InvalidCsum);
		XGSTATS_SUM(IpOptPkts);
		XGSTATS_SUM(LocalCsumVerify);
		XGSTATS_SUM(LocalBadCsum);
		XGSTATS_SUM(UdpBlankCsum);
		XGSTATS_SUM(IpOptProcFail);
		XGSTATS_SUM(IpFragPkts);
		XGSTATS_SUM(bDropPkts);
		XGSTATS_SUM(Condition1);
		XGSTATS_SUM(Condition2);
		XGSTATS_SUM(UdpPkts);
		XGSTATS_SUM(TcpPkts);
		XGSTATS_SUM(TcpHdrLenErr);
		XGSTATS_SUM(TcpTimeStampErr);
		XGSTATS_SUM(TcpOutOfSequenceErr);
		XGSTATS_SUM(TcpProcessErr);
		XGSTATS_SUM(NatPkts);
		XGSTATS_SUM(BlankL2blobInd);
		XGSTATS_SUM(FragAndXmit);
		XGSTATS_SUM(NormalXmit);
		XGSTATS_SUM(L2hdrAdjust);
		XGSTATS_SUM(DevXmitErr);
		XGSTATS_SUM(FlowEndInd);
		XGSTATS_SUM(PktCtxInacRefreshInd);
		XGSTATS_SUM(PktCtxL2blobInd);
		XGSTATS_SUM(NetIfQStopped);
		XGSTATS_SUM(CreateFlowsCmd);
		XGSTATS_SUM(CreateFlowsCmdVsgErr);
		XGSTATS_SUM(CreateFlowsCmdErrDown);
		XGSTATS_SUM(CreateFlowsCmdErrDown1);
		XGSTATS_SUM(CreateFlowsCmdErrDown2);
		XGSTATS_SUM(CreateFlowsCmdFailures);
		XGSTATS_SUM(DeleteFlowsCmd);
		XGSTATS_SUM(DeleteFlowsCmdFailures);
		XGSTATS_SUM(ModifyFlowsCmd);
		XGSTATS_SUM(ModifyFlowsCmdFailures);
		XGSTATS_SUM(BlobTmrCalls);
		XGSTATS_SUM(TmrCtxL2blobInd);
		XGSTATS_SUM(BlobTmrCtxBadFlow);
		XGSTATS_SUM(InacTmrCalls);
		XGSTATS_SUM(TmrCtxInacInd);
		XGSTATS_SUM(InacTmrCtxBadFlow1);
		XGSTATS_SUM(InacTmrCtxBadFlow2);
		XGSTATS_SUM(InacTmrCtxAutoFlowDel);
		XGSTATS_SUM(PktCmdTxInPkts);
		XGSTATS_SUM(PktCmdTxBlobRefresh);
		XGSTATS_SUM(PktCmdTxAutoFlowCreate);
		XGSTATS_SUM(PktCmdTxAutoFlowBlobRefresh);
		XGSTATS_SUM(PktCmdTxLogicalDevErr);
		XGSTATS_SUM(PktCmdTxNonIpErr);
		XGSTATS_SUM(PktCmdTxDummyPkt);
		XGSTATS_SUM(PktCmdTxValidPkt);
		XGSTATS_SUM(PktCmdTxFlowFound);
		XGSTATS_SUM(PktCmdTxBlobInitialUpdates);
		XGSTATS_SUM(PktCmdTxBlobTmrErr);
		XGSTATS_SUM(PktCmdTxInacTmrErr);
		XGSTATS_SUM(PktCmdTxVlanTag);
		XGSTATS_SUM(PktCmdTxSkbFrees);
		XGSTATS_SUM(PktCmdTxInvalidFlowErr);
		XGSTATS_SUM(PktCtxAutoFlowDel);
		XGSTATS_SUM(AutoFlowBlobRefreshSentUp);
		XGSTATS_SUM(AutoFlowCreateSentUp);
		XGSTATS_SUM(PktCmdTxHdrSizeErr);
		XGSTATS_SUM(PktCmdBlobSkbFrees);
		XGSTATS_SUM(PktCmdTxAutoDelFlows);
		XGSTATS_SUM(PktCmdTxAutoFlowCreateErr);
	}
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
	XGSTATS_DISP(m, BridgePkts);
	XGSTATS_DISP(m, InvalidBridgeDev);
	XGSTATS_DISP(m, VlanPkts);
	XGSTATS_DISP(m, InvalidVlanDev);
	XGSTATS_DISP(m, PPPoEPkts);
	XGSTATS_DISP(m, PPPoEUnkPkts);
	XGSTATS_DISP(m, InvalidPPPoEDev);
	XGSTATS_DISP(m, NonIpPkts);
	XGSTATS_DISP(m, NonTcpUdpPkts);
	XGSTATS_DISP(m, VsgSzoneUnk);
	XGSTATS_DISP(m, InvalidCsum);
	XGSTATS_DISP(m, IpOptPkts);
	XGSTATS_DISP(m, LocalCsumVerify);
	XGSTATS_DISP(m, LocalBadCsum);
	XGSTATS_DISP(m, UdpBlankCsum);
	XGSTATS_DISP(m, IpOptProcFail);
	XGSTATS_DISP(m, IpFragPkts);
	XGSTATS_DISP(m, bDropPkts);
	XGSTATS_DISP(m, Condition1);
	XGSTATS_DISP(m, Condition2);
	XGSTATS_DISP(m, UdpPkts);
	XGSTATS_DISP(m, TcpPkts);
	XGSTATS_DISP(m, TcpHdrLenErr);
	XGSTATS_DISP(m, TcpTimeStampErr);
	XGSTATS_DISP(m, TcpOutOfSequenceErr);
	XGSTATS_DISP(m, TcpProcessErr);
	XGSTATS_DISP(m, NatPkts);
	XGSTATS_DISP(m, BlankL2blobInd);
	XGSTATS_DISP(m, FragAndXmit);
	XGSTATS_DISP(m, NormalXmit);
	XGSTATS_DISP(m, L2hdrAdjust);
	XGSTATS_DISP(m, DevXmitErr);
	XGSTATS_DISP(m, FlowEndInd);
	XGSTATS_DISP(m, PktCtxInacRefreshInd);
	XGSTATS_DISP(m, PktCtxL2blobInd);
	XGSTATS_DISP(m, NetIfQStopped);
	XGSTATS_DISP(m, CreateFlowsCmd);
	XGSTATS_DISP(m, CreateFlowsCmdVsgErr);
	XGSTATS_DISP(m, CreateFlowsCmdErrDown);
	XGSTATS_DISP(m, CreateFlowsCmdErrDown1);
	XGSTATS_DISP(m, CreateFlowsCmdErrDown2);
	XGSTATS_DISP(m, CreateFlowsCmdFailures);
	XGSTATS_DISP(m, DeleteFlowsCmd);
	XGSTATS_DISP(m, DeleteFlowsCmdFailures);
	XGSTATS_DISP(m, ModifyFlowsCmd);
	XGSTATS_DISP(m, ModifyFlowsCmdFailures);
	XGSTATS_DISP(m, BlobTmrCalls);
	XGSTATS_DISP(m, TmrCtxL2blobInd);
	XGSTATS_DISP(m, BlobTmrCtxBadFlow);
	XGSTATS_DISP(m, InacTmrCalls);
	XGSTATS_DISP(m, TmrCtxInacInd);
	XGSTATS_DISP(m, InacTmrCtxBadFlow1);
	XGSTATS_DISP(m, InacTmrCtxBadFlow2);
	XGSTATS_DISP(m, InacTmrCtxAutoFlowDel);
	XGSTATS_DISP(m, PktCmdTxInPkts);
	XGSTATS_DISP(m, PktCmdTxBlobRefresh);
	XGSTATS_DISP(m, PktCmdTxAutoFlowCreate);
	XGSTATS_DISP(m, PktCmdTxAutoFlowBlobRefresh);
	XGSTATS_DISP(m, PktCmdTxLogicalDevErr);
	XGSTATS_DISP(m, PktCmdTxNonIpErr);
	XGSTATS_DISP(m, PktCmdTxDummyPkt);
	XGSTATS_DISP(m, PktCmdTxValidPkt);
	XGSTATS_DISP(m, PktCmdTxFlowFound);
	XGSTATS_DISP(m, PktCmdTxBlobInitialUpdates);
	XGSTATS_DISP(m, PktCmdTxBlobTmrErr);
	XGSTATS_DISP(m, PktCmdTxInacTmrErr);
	XGSTATS_DISP(m, PktCmdTxVlanTag);
	XGSTATS_DISP(m, PktCmdTxSkbFrees);
	XGSTATS_DISP(m, PktCmdTxInvalidFlowErr);
	XGSTATS_DISP(m, PktCtxAutoFlowDel);
	XGSTATS_DISP(m, AutoFlowBlobRefreshSentUp);
	XGSTATS_DISP(m, AutoFlowCreateSentUp);
	XGSTATS_DISP(m, PktCmdTxHdrSizeErr);
	XGSTATS_DISP(m, PktCmdBlobSkbFrees);
	XGSTATS_DISP(m, PktCmdTxAutoDelFlows);
	XGSTATS_DISP(m, PktCmdTxAutoFlowCreateErr);
#else
	XGSTATS_DISP(BridgePkts);
	XGSTATS_DISP(InvalidBridgeDev);
	XGSTATS_DISP(VlanPkts);
	XGSTATS_DISP(InvalidVlanDev);
	XGSTATS_DISP(PPPoEPkts);
	XGSTATS_DISP(PPPoEUnkPkts);
	XGSTATS_DISP(InvalidPPPoEDev);
	XGSTATS_DISP(NonIpPkts);
	XGSTATS_DISP(NonTcpUdpPkts);
	XGSTATS_DISP(VsgSzoneUnk);
	XGSTATS_DISP(InvalidCsum);
	XGSTATS_DISP(IpOptPkts);
	XGSTATS_DISP(LocalCsumVerify);
	XGSTATS_DISP(LocalBadCsum);
	XGSTATS_DISP(UdpBlankCsum);
	XGSTATS_DISP(IpOptProcFail);
	XGSTATS_DISP(IpFragPkts);
	XGSTATS_DISP(bDropPkts);
	XGSTATS_DISP(Condition1);
	XGSTATS_DISP(Condition2);
	XGSTATS_DISP(UdpPkts);
	XGSTATS_DISP(TcpPkts);
	XGSTATS_DISP(TcpHdrLenErr);
	XGSTATS_DISP(TcpTimeStampErr);
	XGSTATS_DISP(TcpOutOfSequenceErr);
	XGSTATS_DISP(TcpProcessErr);
	XGSTATS_DISP(NatPkts);
	XGSTATS_DISP(BlankL2blobInd);
	XGSTATS_DISP(FragAndXmit);
	XGSTATS_DISP(NormalXmit);
	XGSTATS_DISP(L2hdrAdjust);
	XGSTATS_DISP(DevXmitErr);
	XGSTATS_DISP(FlowEndInd);
	XGSTATS_DISP(PktCtxInacRefreshInd);
	XGSTATS_DISP(PktCtxL2blobInd);
	XGSTATS_DISP(NetIfQStopped);
	XGSTATS_DISP(CreateFlowsCmd);
	XGSTATS_DISP(CreateFlowsCmdVsgErr);
	XGSTATS_DISP(CreateFlowsCmdErrDown);
	XGSTATS_DISP(CreateFlowsCmdErrDown1);
	XGSTATS_DISP(CreateFlowsCmdErrDown2);
	XGSTATS_DISP(CreateFlowsCmdFailures);
	XGSTATS_DISP(DeleteFlowsCmd);
	XGSTATS_DISP(DeleteFlowsCmdFailures);
	XGSTATS_DISP(ModifyFlowsCmd);
	XGSTATS_DISP(ModifyFlowsCmdFailures);
	XGSTATS_DISP(BlobTmrCalls);
	XGSTATS_DISP(TmrCtxL2blobInd);
	XGSTATS_DISP(BlobTmrCtxBadFlow);
	XGSTATS_DISP(InacTmrCalls);
	XGSTATS_DISP(TmrCtxInacInd);
	XGSTATS_DISP(InacTmrCtxBadFlow1);
	XGSTATS_DISP(InacTmrCtxBadFlow2);
	XGSTATS_DISP(InacTmrCtxAutoFlowDel);
	XGSTATS_DISP(PktCmdTxInPkts);
	XGSTATS_DISP(PktCmdTxBlobRefresh);
	XGSTATS_DISP(PktCmdTxAutoFlowCreate);
	XGSTATS_DISP(PktCmdTxAutoFlowBlobRefresh);
	XGSTATS_DISP(PktCmdTxLogicalDevErr);
	XGSTATS_DISP(PktCmdTxNonIpErr);
	XGSTATS_DISP(PktCmdTxDummyPkt);
	XGSTATS_DISP(PktCmdTxValidPkt);
	XGSTATS_DISP(PktCmdTxFlowFound);
	XGSTATS_DISP(PktCmdTxBlobInitialUpdates);
	XGSTATS_DISP(PktCmdTxBlobTmrErr);
	XGSTATS_DISP(PktCmdTxInacTmrErr);
	XGSTATS_DISP(PktCmdTxVlanTag);
	XGSTATS_DISP(PktCmdTxSkbFrees);
	XGSTATS_DISP(PktCmdTxInvalidFlowErr);
	XGSTATS_DISP(PktCtxAutoFlowDel);
	XGSTATS_DISP(AutoFlowBlobRefreshSentUp);
	XGSTATS_DISP(AutoFlowCreateSentUp);
	XGSTATS_DISP(PktCmdTxHdrSizeErr);
	XGSTATS_DISP(PktCmdBlobSkbFrees);
	XGSTATS_DISP(PktCmdTxAutoDelFlows);
	XGSTATS_DISP(PktCmdTxAutoFlowCreateErr);
#endif

	return 0;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
static int display_asf_proc_xtra_global_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, display_asf_proc_xtra_global_stats, NULL);
}
#endif

#endif


#define VSTATS_SUM(a) (total.ul##a += vstats->ul##a)
#define VSTATS_TOTAL(a) (ULONG)total.ul##a

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
static int display_asf_proc_vsg_stats(struct seq_file *m, void *v)
#else
static int display_asf_proc_vsg_stats(char *page, char **start,
				      off_t off, int count,
				      int *eof, void *data)
#endif
{
	ASFFFPVsgStats_t total;
	int cpu, vsg;

	local_bh_disable();
	for (vsg = 0; vsg < asf_max_vsgs; vsg++) {
		memset(&total, 0, sizeof(total));
		for_each_online_cpu(cpu)
		{
			ASFFFPVsgStats_t *vstats;
			vstats = asfPerCpuPtr(asf_vsg_stats, cpu)+vsg;
			VSTATS_SUM(InPkts);
			VSTATS_SUM(InPktFlowMatches);
			VSTATS_SUM(OutPkts);
			VSTATS_SUM(OutBytes);
		}
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
		if (VSTATS_TOTAL(InPkts)) {
			seq_printf(m, "%d: IN %lu FLOW_MATCHES %lu OUT %lu OUT-BYTES %lu\n", vsg,
			       VSTATS_TOTAL(InPkts),
			       VSTATS_TOTAL(InPktFlowMatches),
			       VSTATS_TOTAL(OutPkts),
			       VSTATS_TOTAL(OutBytes));
		}
#else
		if (VSTATS_TOTAL(InPkts)) {
			printk("%d: IN %lu FLOW_MATCHES %lu OUT %lu OUT-BYTES %lu\n", vsg,
			       VSTATS_TOTAL(InPkts),
			       VSTATS_TOTAL(InPktFlowMatches),
			       VSTATS_TOTAL(OutPkts),
			       VSTATS_TOTAL(OutBytes));
		}
#endif
	}
	local_bh_enable();
	return 0;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
static int display_asf_proc_vsg_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, display_asf_proc_vsg_stats, NULL);
}
#endif

extern int asf_max_ifaces;
extern ASFNetDevEntry_t **asf_ifaces; /* array of strcuture pointers indexed by common interface id */
static inline char *__asf_get_dev_type(ASF_uint32_t ulDevType)
{
	if (ulDevType == ASF_IFACE_TYPE_ETHER)
		return "ETHER";
	else if (ulDevType == ASF_IFACE_TYPE_BRIDGE)
		return "BRIDGE";
	else if (ulDevType == ASF_IFACE_TYPE_VLAN)
		return "VLAN";
	else if (ulDevType == ASF_IFACE_TYPE_PPPOE)
		return "PPPOE";
	else
		return "INVALID";
}
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
static int display_asf_proc_iface_maps(struct seq_file *m, void *v)
#else
static int display_asf_proc_iface_maps(char *page, char **start,
				       off_t off, int count,
				       int *eof, void *data)
#endif
{
	int i;
	ASFNetDevEntry_t *dev;

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
	seq_printf(m, "CII\tNAME\tTYPE\tVSG\tZONE\tID\tPAR-CII\tBR-CII\n");
#else
	printk("CII\tNAME\tTYPE\tVSG\tZONE\tID\tPAR-CII\tBR-CII\n");
#endif
	for (i = 0; i < asf_max_ifaces; i++) {
		dev = asf_ifaces[i];
		if (!dev)
			continue;
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
		seq_printf("%u\t%s\t%s\t%d\t%d\t0x%x\t%u\t%u\n",
#else
		printk("%u\t%s\t%s\t%d\t%d\t0x%x\t%u\t%u\n",
#endif
		       dev->ulCommonInterfaceId,
		       dev->ndev ? dev->ndev->name : "-",
		       __asf_get_dev_type(dev->ulDevType),
		       (dev->ulVSGId != ASF_INVALID_VSG) ? dev->ulVSGId : -1,
		       (dev->ulZoneId != ASF_INVALID_ZONE) ? dev->ulZoneId : -1,
		       dev->usId,
		       dev->pParentDev ? dev->pParentDev->ulCommonInterfaceId : 0,
		       dev->pBridgeDev ? dev->pBridgeDev->ulCommonInterfaceId : 0);
	}
	return 0;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
static int display_asf_proc_iface_maps_open(struct inode *inode, struct file *file)
{
	return single_open(file, display_asf_proc_iface_maps, NULL);
}
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
void print_bigbuf(struct seq_file *m, char *s)
#else
void print_bigbuf(char *s)
#endif
{
	/* printk appears to truncate the buffer if > 2k.
	 * so print 1 line at a time
	 */
	char *c;

	while (*s && (c = strchr(s, '\n'))) {
		*c = '\0';
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
		seq_printf(m, "%s\n", s);
#else
		printk("%s\n", s);
		
#endif
		s = c+1;
	}
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
	seq_printf(m, s);
#else
	printk(s);
#endif
}
EXPORT_SYMBOL(print_bigbuf);


#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
static int display_asf_proc_flow_stats(struct seq_file *m, void *v)
#else
static int display_asf_proc_flow_stats(char *page, char **start,
				       off_t off, int count,
				       int *eof, void *data)
#endif
{
	int i, total = 0;
	ffp_flow_t      *head, *flow;
	char	    *buf, *p;
	unsigned int    min_entr = ~1, max_entr = 0, max_entr_idx = ~1, cur_entr = 0, empty_entr = 0;
	unsigned int    empty_l2blob = 0;
	unsigned int    disp_cnt = 0, display = 0;

	buf = (char *)  kmalloc(300*(ffp_debug_show_count+2), GFP_KERNEL);
	if (!buf) {
		printk("ffp_debug_show_count is too large : couldn't allocate memory!\n");
		return 0;
	}

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
	seq_printf(m, "HIDX {ID}\tDST\tV/Z/P\tSIP:SPORT\tDIP:DPORT\t"
		"SNIP:SNPORT\tDNIP:DNPORT\tPKTS IN-OUT\n");
#else
	printk(KERN_INFO"HIDX {ID}\tDST\tV/Z/P\tSIP:SPORT\tDIP:DPORT\t"
		"SNIP:SNPORT\tDNIP:DNPORT\tPKTS IN-OUT\n");
#endif
	p = buf;
	*p = '\0';
	for (i = 0; i < ffp_hash_buckets; i++) {
		head = (ffp_flow_t *)  &ffp_flow_table[i];

		if (head == head->pNext)
			empty_entr++;

		if (i == ffp_debug_show_index)
			display = 1;

		cur_entr = 0;
		spin_lock_bh(&ffp_flow_table[i].lock);
		for (flow = head->pNext; flow != head; flow = flow->pNext) {

			total++;
			cur_entr++;
			if (flow->l2blob_len == 0)
				empty_l2blob++;
			if (flow == flow->pNext) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
				seq_printf(m, "possible infinite loop.. exiting this bucket!\n");
#else
				printk("possible infinite loop.. exiting this bucket!\n");
#endif
				break;
			}

			if (!display)
				continue;
			p += sprintf(p, "%d {%u, %u}\t%s\t%u/%u/%s\t%d.%d.%d.%d:%d\t%d.%d.%d.%d:%d\t%d.%d.%d.%d:%d\t%d.%d.%d.%d:%d\t%u\n",
				     i,
				     flow->id.ulArg1, flow->id.ulArg2,
				     flow->odev ? flow->odev->name : "UNK",
				     flow->ulVsgId,
				     flow->ulZoneId,
				     (flow->ucProtocol == 6) ? "TCP" : "UDP",

				     NIPQUAD(flow->ulSrcIp),
				     ntohs((flow->ulPorts&0xffff0000) >> 16),
				     NIPQUAD(flow->ulDestIp),
				     ntohs(flow->ulPorts&0xffff),

				     NIPQUAD(flow->ulSrcNATIp),
				     ntohs((flow->ulNATPorts&0xffff0000) >> 16),
				     NIPQUAD(flow->ulDestNATIp),
				     ntohs(flow->ulNATPorts&0xffff),
				     flow->stats.ulOutPkts);
			disp_cnt++;
			if (disp_cnt >= ffp_debug_show_count) {
				display = 0;
			}
		}
		spin_unlock_bh(&ffp_flow_table[i].lock);

		if (min_entr > cur_entr)
			min_entr = cur_entr;
		if (max_entr < cur_entr) {
			max_entr = cur_entr;
			max_entr_idx = i;
		}
	}
	if ((p-buf) > (200*(ffp_debug_show_count+2))) {
		printk("Ooops! buffer is overwriten! allocated %u and required %lu to display %d items\n",
		       200*(ffp_debug_show_count+2), (ULONG)(p-buf), ffp_debug_show_count);
	}

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
	print_bigbuf(m,buf);
#else
	print_bigbuf(buf);
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
	seq_printf(m,"\nTotal %d (empty_l2blob %u)\n(max/bkt %u max-bkt-idx %u min/bkt %u empty-bkts %u)\n",
	       total, empty_l2blob, max_entr, max_entr_idx, min_entr, empty_entr);
#else
	printk("\nTotal %d (empty_l2blob %u)\n(max/bkt %u max-bkt-idx %u min/bkt %u empty-bkts %u)\n",
	       total, empty_l2blob, max_entr, max_entr_idx, min_entr, empty_entr);
#endif
	kfree(buf);
	return 0;
}
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
static int display_asf_proc_flow_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, display_asf_proc_flow_stats, NULL);
}
#endif


#ifdef ASF_IPV6_FP_SUPPORT

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
static int display_asf_proc_flow_ipv6_stats(struct seq_file *m, void *v)
#else
static int display_asf_proc_flow_ipv6_stats(char *page, char **start,
				       off_t off, int count,
				       int *eof, void *data)
#endif
{
	int i, total = 0;
	ffp_flow_t      *head, *flow;
	char	    *buf, *p;
	unsigned int    min_entr = ~1, max_entr = 0, max_entr_idx = ~1, cur_entr = 0, empty_entr = 0;
	unsigned int    empty_l2blob = 0;
	unsigned int    disp_cnt = 0, display = 0;

	buf = (char *)  kmalloc(300*(ffp_debug_show_count+2), GFP_KERNEL);
	if (!buf) {
		printk(KERN_INFO"ffp_debug_show_count is too large : couldn't allocate memory!\n");
		return 0;
	}

	p = buf;
	*p = '\0';
	p += sprintf(p, "\n======================================================================\n");
	for (i = 0; i < ffp_ipv6_hash_buckets; i++) {
		head = (ffp_flow_t *)  &ffp_ipv6_flow_table[i];

		if (head == head->pNext)
			empty_entr++;

		if (i == ffp_debug_show_index)
			display = 1;

		cur_entr = 0;
		spin_lock_bh(&ffp_ipv6_flow_table[i].lock);
		for (flow = head->pNext; flow != head; flow = flow->pNext) {

			total++;
			cur_entr++;
			if (flow->l2blob_len == 0)
				empty_l2blob++;
			if (flow == flow->pNext) {
				printk(KERN_INFO"possible infinite loop.. exiting this bucket!\n");
				break;
			}

			if (!display)
				continue;
			p += sprintf(p, "Src IP      = %x:%x:%x:%x:%x:%x:%x:%x	Port = %u\n", PRINT_IPV6_OTH(flow->ipv6SrcIp), ntohs((flow->ulPorts&0xffff0000) >> 16));
			p += sprintf(p, "Dest IP     = %x:%x:%x:%x:%x:%x:%x:%x	Port = %u\n", PRINT_IPV6_OTH(flow->ipv6DestIp), ntohs(flow->ulPorts&0xffff));
			p += sprintf(p, "NAT Src IP  = %x:%x:%x:%x:%x:%x:%x:%x	Port = %u\n", PRINT_IPV6_OTH(flow->ipv6SrcNATIp), ntohs((flow->ulNATPorts&0xffff0000) >> 16));
			p += sprintf(p, "NAT Dest IP = %x:%x:%x:%x:%x:%x:%x:%x	Port = %u\n", PRINT_IPV6_OTH(flow->ipv6DestNATIp), ntohs(flow->ulNATPorts&0xffff));
			p += sprintf(p, "Proto = %s  Out dev = %s   l2blob len = %u   VSG = %u  Zone = %u\n", ((flow->ucProtocol == 6) ? "TCP" : "UDP"),
																(flow->odev ? flow->odev->name : "UNK"),
																flow->l2blob_len,
																flow->ulVsgId,
																flow->ulZoneId);
			p += sprintf(p, "In pkts = %u	Out pkts = %u\n", flow->stats.ulInPkts, flow->stats.ulOutPkts);
			p += sprintf(p, "======================================================================\n\n");
			disp_cnt++;
			if (disp_cnt >= ffp_debug_show_count)
				display = 0;
		}
		spin_unlock_bh(&ffp_ipv6_flow_table[i].lock);

		if (min_entr > cur_entr)
			min_entr = cur_entr;
		if (max_entr < cur_entr) {
			max_entr = cur_entr;
			max_entr_idx = i;
		}
	}
	if ((p-buf) > (200*(ffp_debug_show_count+2))) {
		printk(KERN_INFO"Ooops! buffer is overwriten! allocated %u and required %lu to display %d items\n",
		       200*(ffp_debug_show_count+2), (ULONG)(p-buf), ffp_debug_show_count);
	}
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
	print_bigbuf(m, buf);
#else
	print_bigbuf(buf);
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
	seq_printf(m, "\nTotal %d (empty_l2blob %u)\n(max/bkt %u max-bkt-idx %u min/bkt %u empty-bkts %u)\n",
	       total, empty_l2blob, max_entr, max_entr_idx, min_entr, empty_entr);
#else
	printk(KERN_INFO"\nTotal %d (empty_l2blob %u)\n(max/bkt %u max-bkt-idx %u min/bkt %u empty-bkts %u)\n",
	       total, empty_l2blob, max_entr, max_entr_idx, min_entr, empty_entr);
#endif
	kfree(buf);
	return 0;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
static int display_asf_proc_flow_ipv6_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, display_asf_proc_flow_ipv6_stats, NULL);
}
#endif

#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
static int display_asf_proc_flow_debug(struct seq_file *m, void *v)
#else
static int display_asf_proc_flow_debug(char *page, char **start,
				       off_t off, int count,
				       int *eof, void *data)
#endif
{
	int i, total = 0;
	ffp_flow_t      *head, *flow;
	char	    *buf, *p;
	unsigned int    disp_cnt = 0, display = 0;
	ULONG curTime = jiffies, last_in, ulIdleTime;

	buf = (char *)  kmalloc(300*(ffp_debug_show_count+2), GFP_KERNEL);
	if (!buf) {
		printk("ffp_debug_show_count is too large : couldn't allocate memory!\n");
		return 0;
	}

	/* display private information for each for debugging */

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
	seq_printf(m, "{ID}\t{OTH-ID}\tFLAGS\tPMTU\tSEQDLT\tBLEN\tTXVID\tIDLE/INAC\t{BLOB}\n");
#else
	printk("{ID}\t{OTH-ID}\tFLAGS\tPMTU\tSEQDLT\tBLEN\tTXVID\tIDLE/INAC\t{BLOB}\n");
#endif
	p = buf;
	*p = '\0';
	for (i = 0; i < ffp_hash_buckets; i++) {
		head = (ffp_flow_t *)  &ffp_flow_table[i];
		if (i == ffp_debug_show_index)
			display = 1;

		spin_lock_bh(&ffp_flow_table[i].lock);
		for (flow = head->pNext; flow != head; flow = flow->pNext) {
			total++;
			if (flow == flow->pNext) {
				printk("possible infinite loop.. exiting this bucket!\n");
				break;
			}

			if (!display)
				continue;

			last_in = flow->ulLastPktInAt;
			if (curTime > last_in) {
				ulIdleTime = curTime - last_in;
			} else {
				ulIdleTime = (((2^32)-1) - (last_in) + curTime);
			}
			ulIdleTime = ulIdleTime/HZ;


#if 0 /* Subha 02/11 part of ROUTE_ARP_CACHE_IN_FLOW */
			p += sprintf(p, "{%u, %u}\t{%u, %u}\t%c%c%c%c%c%c%c%c\t%u\t%c%u\t%u\t%u\t%lu/%lu\t%pM:%pM..%02x%02x\n",
				     flow->id.ulArg1, flow->id.ulArg2,
				     flow->other_id.ulArg1, flow->other_id.ulArg2,

				     flow->bDrop ? 'D' : '-',  /* drop all packets */
				     flow->l2blob_len ? 'B' : '-', /* valid l2blob or not */
				     flow->bNat ? 'N' : '-',
				     flow->bVLAN ? 'V' : '-',
				     flow->bPPPoE ? 'P' : '-',
				     flow->bIPsecIn ? 'I' : '-',
				     flow->bIPsecOut ? 'O' : '-',
				     ASF_TCP_IS_BIT_SET(flow, FIN_RCVD) ? 'F' : (ASF_TCP_IS_BIT_SET(flow, RST_RCVD) ? 'R' : '-'),

				     flow->pmtu,
				     flow->tcpState.bPositiveDelta ? '+' : '-',
				     flow->tcpState.ulSeqDelta,
				     flow->l2blob_len,
				     flow->tx_vlan_id,
				     ulIdleTime,
				     flow->ulInacTime,
				     flow->l2blob,
				     flow->l2blob+6,
				     flow->l2blob[flow->l2blob_len-2],
				     flow->l2blob[flow->l2blob_len-1]);
#else
			p += sprintf(p, "{%u, %u}\t{%u, %u}\t%c%c%c%c%c%c%c%c\t%u\t%c%u\t%u\t%u\t%lu/%lu\n",
				     flow->id.ulArg1, flow->id.ulArg2,
				     flow->other_id.ulArg1, flow->other_id.ulArg2,

				     flow->bDrop ? 'D' : '-',  /* drop all packets */
				     flow->l2blob_len ? 'B' : '-', /* valid l2blob or not */
				     flow->bNat ? 'N' : '-',
				     flow->bVLAN ? 'V' : '-',
				     flow->bPPPoE ? 'P' : '-',
				     flow->bIPsecIn ? 'I' : '-',
				     flow->bIPsecOut ? 'O' : '-',
				     ASF_TCP_IS_BIT_SET(flow, FIN_RCVD) ? 'F' : (ASF_TCP_IS_BIT_SET(flow, RST_RCVD) ? 'R' : '-'),

				     flow->pmtu,
				     flow->tcpState.bPositiveDelta ? '+' : '-',
				     flow->tcpState.ulSeqDelta,
				     flow->l2blob_len,
				     flow->tx_vlan_id,
				     ulIdleTime,
				     flow->ulInacTime);
#endif

			disp_cnt++;
			if (disp_cnt >= ffp_debug_show_count) {
				display = 0;
			}
		}
		spin_unlock_bh(&ffp_flow_table[i].lock);
	}
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
	print_bigbuf(m, buf);
#else
	print_bigbuf(buf);
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
	seq_printf(m, "\nTotal %d\n", total);
#else
	printk("\nTotal %d\n", total);
#endif
	kfree(buf);
	return 0;
}
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
static int display_asf_proc_flow_debug_open(struct inode *inode, struct file *file)
{
	return single_open(file, display_asf_proc_flow_debug, NULL);
}
#endif

#ifdef ASF_FFP_XTRA_STATS
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
static int display_asf_proc_xtra_flow_stats(struct seq_file *m, void *v)
#else
static int display_asf_proc_xtra_flow_stats(char *page, char **start,
					    off_t off, int count,
					    int *eof, void *data)
#endif
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
	seq_printf("No xtra flow stats for now!\n");
#else
	printk("No xtra flow stats for now!\n");
#endif
	return 0;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
static int display_asf_proc_xtra_flow_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, display_asf_proc_xtra_flow_stats, NULL);
}
#endif
#endif


#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
static const struct file_operations proc_file_global_stats_fops = {
	.open = display_asf_proc_global_stats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

#ifdef ASF_FFP_XTRA_STATS
static const struct file_operations proc_file_xtra_global_stats_fops = {
	.open = display_asf_proc_xtra_global_stats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};
#endif
static const struct file_operations proc_file_vsg_stats_fops = {
	.open = display_asf_proc_vsg_stats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static const struct file_operations proc_file_exec_cmd_clear_stats_fops = {
	.open = asf_exec_cmd_clear_stats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static const struct file_operations proc_file_iface_maps_fops = {
	.open = display_asf_proc_iface_maps_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};
static const struct file_operations proc_flow_stats_fops = {
	.open = display_asf_proc_flow_stats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

#ifdef ASF_IPV6_FP_SUPPORT
static const struct file_operations proc_flow_ipv6_stats_fops = {
	.open = display_asf_proc_flow_ipv6_stats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};
#endif

#ifdef ASF_FFP_XTRA_STATS
static const struct file_operations proc_xtra_flow_stats_fops = {
	.open = display_asf_proc_xtra_flow_stats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};
#endif

static const struct file_operations proc_flow_debug_fops = {
	.open = display_asf_proc_flow_debug_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};


#endif

int asf_register_proc(void)
{
	struct proc_dir_entry   *proc_file;

	/* register sysctl tree */
	asf_proc_header = register_sysctl_table(asf_proc_root_table);
	if (!asf_proc_header)
		return -ENOMEM;
	/* register other under /proc/asf */
	asf_dir =  proc_mkdir("asf", NULL);

	if (asf_dir == NULL)
		return -ENOMEM;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	asf_dir->owner = THIS_MODULE;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
	proc_file = create_proc_read_entry(
					  ASF_PROC_GLOBAL_STATS_NAME,
					  0444, asf_dir,
					  display_asf_proc_global_stats,
					  NULL);
#else
	printk("Doing proc_create: asf_proc_global_stats\n");
	
	proc_file = proc_create(ASF_PROC_GLOBAL_STATS_NAME, 0444,
		asf_dir, &proc_file_global_stats_fops);
	
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	if (proc_file)
		proc_file->owner = THIS_MODULE;
#endif

#ifdef ASF_FFP_XTRA_STATS
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
	proc_file = create_proc_read_entry(
					  ASF_PROC_XTRA_GLOBAL_STATS_NAME,
					  0444, asf_dir,
					  display_asf_proc_xtra_global_stats,
					  NULL);
#else
	printk("Doing proc_create: asf_proc_xtra_global_stats\n");

	proc_file = proc_create(ASF_PROC_XTRA_GLOBAL_STATS_NAME,
				0444, asf_dir,
				&proc_file_xtra_global_stats_fops);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	if (proc_file)
		proc_file->owner = THIS_MODULE;
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
	proc_file = create_proc_read_entry(
					  ASF_PROC_VSG_STATS_NAME,
					  0444, asf_dir,
					  display_asf_proc_vsg_stats,
					  NULL);
#else
	printk("Doing proc_create: asf_proc_vsg_stats\n");
	
	proc_file = proc_create(ASF_PROC_VSG_STATS_NAME, 0444,
		asf_dir, &proc_file_vsg_stats_fops);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	if (proc_file)
		proc_file->owner = THIS_MODULE;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
	proc_file = create_proc_read_entry(
					  ASF_PROC_RESET_STATS_NAME,
					  0444, asf_dir,
					  asf_exec_cmd_clear_stats,
					  NULL);
#else
	printk("Doing proc_create: asf_exec_cmd_clear_stats\n");

	proc_file = proc_create(ASF_PROC_RESET_STATS_NAME,
			0444, asf_dir,
			&proc_file_exec_cmd_clear_stats_fops);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	if (proc_file)
		proc_file->owner = THIS_MODULE;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
	proc_file = create_proc_read_entry(
					  ASF_PROC_IFACE_MAPS,
					  0444, asf_dir,
					  display_asf_proc_iface_maps,
					  NULL);
#else
	printk("Doing proc_create: display_asf_proc_iface_maps\n");

	proc_file = proc_create(ASF_PROC_IFACE_MAPS, 0444,
		asf_dir, &proc_file_iface_maps_fops);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	if (proc_file)
		proc_file->owner = THIS_MODULE;
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
	proc_file = create_proc_read_entry(
					  ASF_PROC_FLOW_STATS_NAME,
					  0444, asf_dir,
					  display_asf_proc_flow_stats,
					  NULL);
#else
	printk("Doing proc_create: display_asf_proc_flow_stats \n");

	proc_file = proc_create(ASF_PROC_FLOW_STATS_NAME, 0444,
		asf_dir, &proc_flow_stats_fops);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	if (proc_file)
		proc_file->owner = THIS_MODULE;
#endif

#ifdef ASF_IPV6_FP_SUPPORT
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
	proc_file = create_proc_read_entry(
					  ASF_PROC_FLOW_IPV6_STATS_NAME,
					  0444, asf_dir,
					  display_asf_proc_flow_ipv6_stats,
					  NULL);
#else
	printk("Doing proc_create: display_asf_proc_flow_ipv6_stats\n");
	proc_file = proc_create(ASF_PROC_FLOW_IPV6_STATS_NAME,
		0444, asf_dir,
		&proc_flow_ipv6_stats_fops);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	if (proc_file)
		proc_file->owner = THIS_MODULE;
#endif
#endif

#ifdef ASF_FFP_XTRA_STATS
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
	proc_file = create_proc_read_entry(
					  ASF_PROC_XTRA_FLOW_STATS_NAME,
					  0444, asf_dir,
					  display_asf_proc_xtra_flow_stats,
					  NULL);
#else
	printk("proc_create: display_asf_proc_xtra_flow_stats");
	
	proc_file = proc_create(ASF_PROC_XTRA_FLOW_STATS_NAME,
		0444, asf_dir,
		&proc_xtra_flow_stats_fops);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	if (proc_file)
		proc_file->owner = THIS_MODULE;
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
	proc_file = create_proc_read_entry(
					  ASF_PROC_FLOW_DEBUG_NAME,
					  0444, asf_dir,
					  display_asf_proc_flow_debug,
					  NULL);
#else
	printk("proc_create: display_asf_proc_flow_debug\n");
	proc_file = proc_create(ASF_PROC_FLOW_DEBUG_NAME,
			0444, asf_dir,
			&proc_flow_debug_fops);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	if (proc_file)
		proc_file->owner = THIS_MODULE;
#endif

	return 0;
}


int asf_unregister_proc(void)
{
	if (asf_proc_header)
		unregister_sysctl_table(asf_proc_header);
#ifdef ASF_FFP_XTRA_STATS
	remove_proc_entry(ASF_PROC_XTRA_GLOBAL_STATS_NAME, asf_dir);
#endif
	remove_proc_entry(ASF_PROC_GLOBAL_STATS_NAME, asf_dir);
	remove_proc_entry(ASF_PROC_VSG_STATS_NAME, asf_dir);

#ifdef ASF_FFP_XTRA_STATS
	remove_proc_entry(ASF_PROC_XTRA_FLOW_STATS_NAME, asf_dir);
#endif
	remove_proc_entry(ASF_PROC_RESET_STATS_NAME, asf_dir);
	remove_proc_entry(ASF_PROC_IFACE_MAPS, asf_dir);
	remove_proc_entry(ASF_PROC_FLOW_STATS_NAME, asf_dir);
#ifdef ASF_IPV6_FP_SUPPORT
	remove_proc_entry(ASF_PROC_FLOW_IPV6_STATS_NAME, asf_dir);
#endif
	remove_proc_entry(ASF_PROC_FLOW_DEBUG_NAME, asf_dir);

	remove_proc_entry("asf", NULL);

	return 0;
}
