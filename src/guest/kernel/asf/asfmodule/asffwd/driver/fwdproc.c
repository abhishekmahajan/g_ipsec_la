/**************************************************************************
 * Copyright 2014-2015, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	fwdproc.c
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

extern ASF_uint32_t asf_fwd_max_vsgs;
#define ASF_PROC_FWD_GLOBAL_STATS_NAME   "fwd_global_stats"
#define ASF_PROC_FWD_VSG_STATS_NAME	 "fwd_vsg_stats"
#define ASF_PROC_FWD_FLOW_STATS_NAME	 "fwd_flow_status"


extern ASFFwdGlobalStats_t *fwd_gstats;
extern ASFFwdVsgStats_t *fwd_vsg_stats;
extern int fwd_hash_buckets; 
extern fwd4_bucket_t *fwd_flow_cache;

extern int fwd_debug_show_index;
extern int fwd_debug_show_count;
extern struct proc_dir_entry *asf_dir;

#define _GSTATS_SUM(a) (total.ul##a += gfwdstats->ul##a)
#define _GSTATS_TOTAL(a) (unsigned long) total.ul##a

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
void print_bigbuf(struct seq_file *m, char *s);
#else
void print_bigbuf(char *s);
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 11, 0)
static int display_asf_proc_fwd_global_stats(struct seq_file *m, void *v)
{
	ASFFwdGlobalStats_t total;
	int cpu;

	memset(&total, 0, sizeof(total));

	for_each_online_cpu(cpu)
	{
		ASFFwdGlobalStats_t *gfwdstats;
		gfwdstats = asfPerCpuPtr(fwd_gstats, cpu);
		_GSTATS_SUM(InPkts);
		_GSTATS_SUM(InPktCacheHits);
		_GSTATS_SUM(OutPkts);
		_GSTATS_SUM(OutBytes);
		_GSTATS_SUM(FlowAllocs);
		_GSTATS_SUM(FlowFrees);
		_GSTATS_SUM(FlowAllocFailures);
		_GSTATS_SUM(FlowFreeFailures);
	}

	seq_printf(m, "IN %lu IN-MATCH %lu OUT %lu OUT-BYTES %lu\n",
	       _GSTATS_TOTAL(InPkts), _GSTATS_TOTAL(InPktCacheHits), _GSTATS_TOTAL(OutPkts), _GSTATS_TOTAL(OutBytes));

	seq_printf(m, "FLOW: ALLOC %lu FREE %lu ALLOC-FAIL %lu FREE-FAIL %lu\n",
	       _GSTATS_TOTAL(FlowAllocs), _GSTATS_TOTAL(FlowFrees),
	       _GSTATS_TOTAL(FlowAllocFailures), _GSTATS_TOTAL(FlowFreeFailures));
	return 0;
}
#define _VSTATS_SUM(a) (total.ul##a += vsgstats->ul##a)
#define _VSTATS_TOTAL(a) (unsigned long)total.ul##a
static int display_asf_proc_fwd_vsg_stats(struct seq_file *m, void *v)
{
	ASFFwdVsgStats_t total;
	int cpu;
	int ii;

	memset(&total, 0, sizeof(total));

	for_each_online_cpu(cpu)
	{
		ASFFwdVsgStats_t *vsgstats;
		for (ii=0 ; ii < asf_fwd_max_vsgs; ii++)
		{
			vsgstats = asfPerCpuPtr(fwd_vsg_stats, cpu) + ii;
			_VSTATS_SUM(InPkts);
			_VSTATS_SUM(InPktFlowMatches);
			_VSTATS_SUM(OutPkts);
			_VSTATS_SUM(OutBytes);
		}
	}

	seq_printf(m, "IN %lu IN-MATCH %lu OUT %lu OUT-BYTES %lu\n",
	       _VSTATS_TOTAL(InPkts), _VSTATS_TOTAL(InPktFlowMatches), _VSTATS_TOTAL(OutPkts), _VSTATS_TOTAL(OutBytes));

	return 0;
}
static int display_asf_proc_fwd_flow_stats(struct seq_file *m, void *v)
{
	int i, total = 0;
	fwd_flow4_t      *head, *flow;
	char	    *buf, *p;
	unsigned int    min_entr = ~1, max_entr = 0, max_entr_idx = ~1, cur_entr = 0, empty_entr = 0;
	unsigned int    empty_l2blob = 0;
	unsigned int    disp_cnt = 0, display = 0;

	buf = (char *)  kmalloc(300*(fwd_debug_show_count+2), GFP_KERNEL);
	if (!buf) {
		printk("fwd_debug_show_count is too large : couldn't allocate memory!\n");
		return 0;
	}

	seq_printf(m, "HIDX {ID}\tDST\tV/Z/P\tSIP\tDIP\tTOS\t"
		"\tPKTS IN-OUT\n");

	p = buf;
	*p = '\0';
	for (i = 0; i < fwd_hash_buckets; i++) {
		head = (fwd_flow4_t *)  &fwd_flow_cache[i];

		if (head == head->pNext)
			empty_entr++;

		if (i == fwd_debug_show_index)
			display = 1;

		cur_entr = 0;
		for (flow = head->pNext; flow != head; flow = flow->pNext) {

			total++;
			cur_entr++;
			if (flow == flow->pNext) {
				seq_printf(m, "possible infinite loop.. exiting this bucket!\n");
				break;
			}

			if (!display)
				continue;
			p += sprintf(p, "%d {%u, %u}\t%s\t%u/\t%d.%d.%d.%d\t%d.%d.%d.%d\t%u\t%u\n",
				     i,
				     flow->id.ulArg1, flow->id.ulArg2,
				     flow->odev ? flow->odev->name : "UNK",
				     flow->ulVsgId,

				     NIPQUAD(flow->ulSrcIp),
				     NIPQUAD(flow->ulDestIp),
				     flow->ucTos, 
			             flow->stats.ulOutPkts);

			disp_cnt++;
			if (disp_cnt >= fwd_debug_show_count) {
				display = 0;
			}
		}

		if (min_entr > cur_entr)
			min_entr = cur_entr;
		if (max_entr < cur_entr) {
			max_entr = cur_entr;
			max_entr_idx = i;
		}
	}
	if ((p-buf) > (200*(fwd_debug_show_count+2))) {
		printk("Ooops! buffer is overwriten! allocated %u and required %lu to display %d items\n",
		       200*(fwd_debug_show_count+2), (unsigned long)(p-buf), fwd_debug_show_count);
	}

	print_bigbuf(m,buf);

	seq_printf(m,"\nTotal %d (max/bkt %u max-bkt-idx %u min/bkt %u empty-bkts %u)\n",
	       total, max_entr, max_entr_idx, min_entr, empty_entr);
	kfree(buf);
	return 0;
}
static int display_asf_proc_fwd_global_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, display_asf_proc_fwd_global_stats, NULL);
}
static int display_asf_proc_fwd_vsg_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, display_asf_proc_fwd_vsg_stats, NULL);
}

static int display_asf_proc_fwd_flow_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, display_asf_proc_fwd_flow_stats, NULL);
}

static const struct file_operations proc_file_fwd_global_stats_fops = {
	.open = display_asf_proc_fwd_global_stats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static const struct file_operations proc_file_fwd_vsg_stats_fops = {
	.open = display_asf_proc_fwd_vsg_stats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static const struct file_operations proc_file_fwd_flow_stats_fops = {
	.open = display_asf_proc_fwd_flow_stats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};
#endif

int fwd_register_proc(void)
{
	struct proc_dir_entry   *proc_file;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
#else
	proc_file = proc_create(ASF_PROC_FWD_GLOBAL_STATS_NAME,
				0444, asf_dir,
				&proc_file_fwd_global_stats_fops);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
#else
	proc_file = proc_create(ASF_PROC_FWD_VSG_STATS_NAME,
				0444, asf_dir,
				&proc_file_fwd_vsg_stats_fops);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
#else
	proc_file = proc_create(ASF_PROC_FWD_FLOW_STATS_NAME,
				0444, asf_dir,
				&proc_file_fwd_flow_stats_fops);
#endif
}


int asf_unregister_proc(void)
{
	remove_proc_entry(ASF_PROC_FWD_GLOBAL_STATS_NAME, asf_dir);
	remove_proc_entry(ASF_PROC_FWD_VSG_STATS_NAME, asf_dir);
	remove_proc_entry(ASF_PROC_FWD_FLOW_STATS_NAME, asf_dir);
}

