/**************************************************************************
 * Copyright 2010-2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfctrl_netns.c
 *
 * Description: Control module for Configuring ASF and integrating it with
 * Linux Networking Stack
 *
 * Authors:	Subha Venkataramanan
 *
 */
/*
 * History
*  Version     Date         Author              Change Description
*  1.0        10/20/2014    Subha Venkataramanan Initial Development
*/
/***************************************************************************/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/inetdevice.h>
#include <net/dst.h>
#include <linux/if_vlan.h>
#include <linux/if_arp.h>
#ifdef CONFIG_DPA
#include <dpa/dpaa_eth.h>
#else
#if 0 /* Subha */
#include <gianfar.h>
#else
#include <e1000.h>
#endif
#endif
#include <net/neighbour.h>
#include <net/net_namespace.h>
#include <net/dst.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <net/route.h>
#ifdef ASF_IPV6_FP_SUPPORT
#include <net/ip6_route.h>
#endif
#ifdef ASFCTRL_TERM_FP_SUPPORT
#include <linux/if_pmal.h>
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33))
#include <8021q/vlan.h>
#endif
#include "../../../asfffp/driver/gplcode.h"
#include "../../../asfffp/driver/asfcmn.h"
#include "../../../asfffp/driver/asf.h"
#include "asfctrl.h"
#include <net/ipv6.h>
#include "asfctrl_netns.h"


asfctrl_netns_vsg_t **netns_vsg;
asfctrl_netns_vsg_hash_node_t *netns_vsg_hash_list;
ASF_uint32_t asf_max_vsgs = 256;
static ASF_uint32_t ulNumVsgsInUse = 0;
static spinlock_t netns_vsg_lock;

#define ASFCTRL_NETNS_VSG_HASH_LIST_SIZE 	(asf_max_vsgs/4)
#define ASFCTRL_NETNS_VSG_HASH(x)	((ASF_uint32_t )(x) % ASFCTRL_NETNS_VSG_HASH_LIST_SIZE)

void print_hash_bucket(ASF_uint32_t hashVal)
{
	asfctrl_netns_vsg_hash_node_t *pHead = &(netns_vsg_hash_list[hashVal]);
	asfctrl_netns_vsg_t *node;

	printk("head = 0x%p, head->pNext = 0x%p\n", pHead, pHead->pNext);
	for (node = pHead->pNext; node != pHead; node = node->pNext)
	{
		printk("Searching: node =0x%p, node->net = 0x%p\n", node, node->net);
	}
}

/*
 * asf_net_init
 */
static int __net_init asf_net_init(struct net *net)
{
	printk("NAMESPACE_CREATE:Net Init called %p\n", net);
	asfctrl_netns_vsg_create(net);
	printk("asfctrl_linux_register_ffp_byname called\n");
	asfctrl_linux_register_ffp_byname(net);
	print_hash_bucket(0);
	return 0;
}

static int __net_exit asf_net_exit(struct net *net)
{
	int ii;
	printk("NAMESPACE_DELETE:Net Exit called %p\n", net);
	asfctrl_linux_unregister_ffp_byname(net);

	asfctrl_netns_vsg_delete(net);
/*
	for (ii= 0; ii < asf_max_vsgs; ii++)
	{
		netns_vsg[ii] = 0;
		printk("address of netns_vsg[%d] = %p, value = 0x%x \n", ii, &(netns_vsg[ii]), netns_vsg[ii]);
	}
*/
	return 0;
}

static __net_initdata struct pernet_operations asf_net_ops = {
	.init = asf_net_init,
	.exit = asf_net_exit,
};


#define ASF_SPIN_LOCK(bLockFlag, spinLock) do { \
                bLockFlag = in_softirq(); \
                if (bLockFlag) { \
                        spin_lock(spinLock); \
                } else { \
                        spin_lock_bh(spinLock); \
                } \
        } while (0)

#define ASF_SPIN_UNLOCK(bLockFlag, spinLock) do { \
                if (bLockFlag) { \
                        spin_unlock(spinLock); \
                } else { \
                        spin_unlock_bh(spinLock); \
                } \
        } while (0)


static void _netns_add_to_hash_list(asfctrl_netns_vsg_t *node)
{
	ASF_uint32_t hashVal;
	asfctrl_netns_vsg_t *head, *temp;
	hashVal = ASFCTRL_NETNS_VSG_HASH(node->net);
	printk("hashVal = %d\n", hashVal);
	printk("Adding node = %p\n", node);
	head = (asfctrl_netns_vsg_t *)(&netns_vsg_hash_list[hashVal]);
	printk("Adding in hash list %p\n", head);
	if (node != NULL)
	{
		printk("Adding to hash list\n");
		temp = node->pNext = head->pNext;
		node->pPrev = head;
		//rcu_assign_pointer(head->pNext, node);
		head->pNext = node;
		printk("node = 0x%p, head->pNext = 0x%p\n", node, head->pNext);
		printk("node->pNext = %p\n", node->pNext);
		temp->pPrev = node;
	}
		
}
extern ASF_uint32_t asfctrl_vsg_config_id;
ASF_int32_t asfctrl_netns_vsg_create(struct net *net)
{
	/* to hold net */
	bool bLockFlag;
	ASF_uint32_t ii;

	printk("asfctrl_netns_vsg_create called\n");

	ASF_SPIN_LOCK(bLockFlag, &netns_vsg_lock);
	if (ulNumVsgsInUse == asf_max_vsgs)
	{
		ASF_SPIN_UNLOCK(bLockFlag, &netns_vsg_lock);
		printk("No more VSGs available\n");
		return T_FAILURE;
	}
	for (ii=0; ii < asf_max_vsgs; ii++)
	{
		if (netns_vsg[ii] == 0)
			break;
	}
	if (ii > asf_max_vsgs)
	{
		ASF_SPIN_UNLOCK(bLockFlag, &netns_vsg_lock);
		printk("Should not happen: Index unavailable\n");
		return T_FAILURE;
	}
	netns_vsg[ii] = kmalloc(sizeof(asfctrl_netns_vsg_t), GFP_ATOMIC);
	if (netns_vsg[ii] == NULL)
	{
		ASF_SPIN_UNLOCK(bLockFlag, &netns_vsg_lock);
		printk("Memory allocation for netns_vsg failed\n");
		return T_FAILURE;
	}

	netns_vsg[ii]->ulVSGId =  ii;
	
	printk("netns added %p\n", netns_vsg[ii]);

	/* to hold and keep it
	*/
	netns_vsg[ii]->net = hold_net(net);
	printk("holding %p \n", netns_vsg[ii]->net);
/*
	netns_vsg[ii]->net =  0;
*/
	/* Add into the hash list */
	_netns_add_to_hash_list(netns_vsg[ii]);
	ulNumVsgsInUse ++;
	ASF_SPIN_UNLOCK(bLockFlag, &netns_vsg_lock);
	
	if(ASFCreateVSG(netns_vsg[ii]->ulVSGId, asfctrl_vsg_config_id) != ASF_SUCCESS)
	{
		printk("ASFCreateVSG failed\n");
		asfctrl_netns_vsg_delete(net);
		return T_FAILURE;
	}
	printk("ASFCreateVSG succeeded\n");
	return T_SUCCESS;
}

asfctrl_netns_vsg_t* netns_lookup(struct net *net, 
	asfctrl_netns_vsg_hash_node_t * pHead)
{
	asfctrl_netns_vsg_t *node;

	printk("Searching in hash list %p\n", pHead);
	printk("pHead->pNext = 0x%p\n", pHead->pNext);
	for (node = pHead->pNext; node != pHead; node = node->pNext)
	{
		printk("Searching: node->net = 0x%p\n", node->net);
		if (node->net == net) /* found a match */	
			return node;
	}
	return NULL;
}

void _netns_flow_remove(asfctrl_netns_vsg_t *netns)
{
	netns->pNext->pPrev = netns->pPrev;
	netns->pPrev->pNext = netns->pNext;
}

struct net *asfctrl_netns_vsg_to_net(ASF_uint32_t ulVSGId)
{
	rcu_read_lock();
	if (ulVSGId < asf_max_vsgs)
	{
		if (netns_vsg[ulVSGId])
		{
			rcu_read_unlock();
			return (netns_vsg[ulVSGId]->net);
		}
	}
	rcu_read_unlock();
	return 0;
}


ASF_uint32_t asfctrl_netns_net_to_vsg(struct net *net)
{
	ASF_uint32_t hashVal;
	asfctrl_netns_vsg_t *netns;

	rcu_read_lock();

	hashVal = ASFCTRL_NETNS_VSG_HASH(net);
	printk("hashVal = %d\n", hashVal);

	netns = netns_lookup(net,  &(netns_vsg_hash_list[hashVal]));
	if (netns)
	{
		printk("netns found %p\n", netns);
		rcu_read_unlock();
		return (netns->ulVSGId);
	}
	rcu_read_unlock();
	return asf_max_vsgs;
}

ASF_int32_t asfctrl_netns_vsg_delete(struct net *net)
{
	/* to release net */
	bool bLockFlag;
	ASF_uint32_t hashVal;
	asfctrl_netns_vsg_t *netns;

	printk("asfctrl_netns_vsg_delete called\n");

	hashVal = ASFCTRL_NETNS_VSG_HASH(net);
	printk("hashVal = %d\n", hashVal);

	ASF_SPIN_LOCK(bLockFlag, &netns_vsg_lock);
	netns = netns_lookup(net,  &(netns_vsg_hash_list[hashVal]));
	if (netns)
	{
		printk("netns found %p\n", netns);
		release_net(netns->net);
		printk("Released %p \n", netns->net);
		_netns_flow_remove(netns);
		netns_vsg[netns->ulVSGId] = 0;
		printk("netns->ulVSGId = %d, netns_vsg[netns->ulVSGId] = %d\n", netns->ulVSGId, netns_vsg[netns->ulVSGId]);
		ulNumVsgsInUse --;
	}
	else
	{
		printk("netns not found\n");
		ASF_SPIN_UNLOCK(bLockFlag, &netns_vsg_lock);
		return T_SUCCESS;
	}

	ASF_SPIN_UNLOCK(bLockFlag, &netns_vsg_lock);

	if(ASFDeleteVSG(netns->ulVSGId) != ASF_SUCCESS)
	{
		printk("ASFDeleteVSG failed\n");
	}
	if (netns)
	{
		smp_wmb();
		call_rcu(netns, kfree);
	}
	
	return T_SUCCESS;
}

ASF_int32_t asfctrl_netns_vsg_init(void)
{
	ASF_uint32_t ii;
	ASF_int32_t ret;
	uint32_t kmalloc_size;


	kmalloc_size = sizeof(asfctrl_netns_vsg_t *) * asf_max_vsgs;
	netns_vsg = kmalloc(kmalloc_size, GFP_ATOMIC);
	printk("netns_vsg = %p\n, kmalloc_size = %d", netns_vsg, kmalloc_size);

	if (netns_vsg == NULL)
	{
		printk("Allocation of pointer array for VSG failed\n");
		return T_FAILURE;
	}
	for (ii= 0; ii < asf_max_vsgs; ii++)
	{
		netns_vsg[ii] = 0;
		//printk("address of netns_vsg[%d] = %p, value = 0x%x \n", ii, &(netns_vsg[ii]), netns_vsg[ii]);
	}
	kmalloc_size = (ASFCTRL_NETNS_VSG_HASH_LIST_SIZE* (sizeof(asfctrl_netns_vsg_hash_node_t )));
	netns_vsg_hash_list = kmalloc(kmalloc_size, GFP_ATOMIC);
	if (netns_vsg_hash_list == NULL)
	{
		printk("Allocation of Netns VSG HASH List size failed\n");
		kfree(netns_vsg);
		return T_FAILURE;
	}
	printk("netns_vsg_hash_list = %p kmalloc_size = %d\n", netns_vsg_hash_list, kmalloc_size);
	for (ii=0; ii < ASFCTRL_NETNS_VSG_HASH_LIST_SIZE; ii++)
	{
		netns_vsg_hash_list[ii].pNext = &(netns_vsg_hash_list[ii]);
		netns_vsg_hash_list[ii].pPrev = &(netns_vsg_hash_list[ii]); 
		//printk("Next = %p \n", netns_vsg_hash_list[ii].pNext);
		//printk("Prev = %p \n", netns_vsg_hash_list[ii].pPrev);
	}
	spin_lock_init(&netns_vsg_lock);

 	ret = register_pernet_subsys(&asf_net_ops);
	printk("register_pernet_subsys returned %d\n", ret);
	return T_SUCCESS;
}

void asfctrl_netns_cleanup(void)
{
	ASF_uint32_t ii;

	for (ii=0; ii < asf_max_vsgs; ii++)
	{
		if(netns_vsg[ii] != 0)
		{
			printk("asfctrl_netns_cleanup() netns_vsg[%d] not NULL = %d\n", ii, (netns_vsg[ii]));
//			kfree(netns_vsg[ii]);
		}
	}
}

ASF_int32_t asfctrl_netns_vsg_deinit(void)
{
	printk("asfctrl_netns_vsg_deinit called\n");
	unregister_pernet_subsys(&asf_net_ops);

	printk("Freeing :netns_vsg = %p\n", netns_vsg);
	printk("netns_vsg_hash_list = %p\n", netns_vsg_hash_list);
	kfree(netns_vsg_hash_list);
	asfctrl_netns_cleanup();
	kfree(netns_vsg);

	return T_SUCCESS;
}
