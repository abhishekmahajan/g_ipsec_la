/* An IPsec protocol driver using virtio.
 *
 * Copyright 2015 Freescale Semiconductor
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* Header files */
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/virtio_types.h>
#include <linux/skbuff.h>
#include <linux/stddef.h>
#include <linux/interrupt.h>
#include <linux/threads.h>
#include <linux/kernel.h>
//#include <drivers/virtio/virtio_pci_common.h>
#include "virtio_pci_common.h"
#include <linux/wait.h>
#include <linux/cpu.h>
#include "virtio_ipsec_api.h"
#include "virtio_ipsec_msg.h"
#include "virtio_ipsec.h"


/* Macros */

/* Enumerations */

/* Global Data Structures */

/* List of free virtio ipsec devices */
#define VIRTIO_IPSEC_MAX_DEVICES 	128
#define VIRTIO_IPSEC_MAX_APPS		128
#define VIRTIO_IPSEC_MAX_GROUPS		64
#define VIRTIO_IPSEC_MAX_SAS		8192
#define EXPAND_HANDLE(ptr)	((u32 *)(ptr))[0], ((u32 *)(ptr))[1]


static struct safe_ref_array v_ipsec_devices;
static struct safe_ref_array v_ipsec_apps;
static struct safe_ref_array v_ipsec_app_hndl_refs;

static struct safe_ref_array v_ipsec_grps;
static struct safe_ref_array v_ipsec_grp_hndl_refs;

static struct safe_ref_array v_ipsec_sas;
static struct safe_ref_array v_ipsec_sa_hndl_refs;

static struct list_head _device_list; 
static struct spinlock device_list_lock;
static int num_devices;

#define VIRT_IPSEC_MGR_GET_APP(handle)	\
	 ((*(u32 *)((u8 *)(handle)+4)) == \
		safe_ref_get_magic_num(&v_ipsec_apps, (*(u32 *)(handle)))) ?	\
		safe_ref_get_data(&v_ipsec_apps, (*(u32 *)(handle))) : NULL

#define VIRT_IPSEC_MGR_GET_APP_REF(handle)	\
	 ((*(u32 *)((u8 *)(handle)+4)) == \
		safe_ref_get_magic_num(&v_ipsec_app_hndl_refs, (*(u32 *)(handle)))) ?	\
		safe_ref_get_data(&v_ipsec_app_hndl_refs, (*(u32 *)(handle))) : NULL


#define VIRT_IPSEC_MGR_GET_DEVICE(handle)	\
	 ((*(u32 *)(handle+4)) == \
		safe_ref_get_magic_num(&v_ipsec_devices, (*(u32 *)(&handle[0])))) ?	\
		safe_ref_get_data(&v_ipsec_devices, (*(u32 *)(&handle[0]))) : NULL


#define VIRT_IPSEC_MGR_GET_GROUP(handle)	\
	 ((*(u32 *)((u8 *)(handle)+4)) == \
		safe_ref_get_magic_num(&v_ipsec_grps, (*(u32 *)(&handle[0])))) ?	\
		safe_ref_get_data(&v_ipsec_grps, (*(u32 *)(&handle[0]))) : NULL		
				
#define VIRT_IPSEC_MGR_GET_SA(handle)	\
	 ((*(u32 *)((u8 *)(handle)+4)) == \
		safe_ref_get_magic_num(&v_ipsec_sas, (*(u32 *)(&handle[0])))) ?	\
		safe_ref_get_data(&v_ipsec_sas, (*(u32 *)(&handle[0]))) : NULL		

#define VIRT_IPSEC_MGR_GET_SA_REF(handle)	\
	 ((*(u32 *)((u8 *)(handle)+4)) == \
		safe_ref_get_magic_num(&v_ipsec_sa_hndl_refs, (*(u32 *)(&handle[0])))) ?	\
		safe_ref_get_data(&v_ipsec_sa_hndl_refs, (*(u32 *)(&handle[0]))) : NULL		

#define GET_INDEX_FROM_HANDLE(handle) \
	*(u32 *)(&handle[0])

struct v_ipsec_dev_hndl /*dev_handle_holder */ {
	u8 handle[G_IPSEC_LA_HANDLE_SIZE];
};

struct v_ipsec_dev_ref
{
	struct list_head list;
	struct v_ipsec_dev_hndl hndl;
};	

struct v_ipsec_device /*virt_ipsec_mgr_dev */
{
	struct rcu_head rcu;
	struct list_head link; /* device list */
	struct list_head apps; /* list of applications refering to this device */
	struct v_ipsec_dev_hndl hndl; 
	struct virt_ipsec_info *info;
	u8 mode; /* SHARED or EXCLUSIVE */
	u32 num_apps;
	spinlock_t lock;
};

struct v_ipsec_app_hndl {
	u8 handle[G_IPSEC_LA_HANDLE_SIZE];
};


struct v_ipsec_app_list_hndl{
	u8 handle[G_IPSEC_LA_INTERNAL_HANDLE_SIZE];
};

struct v_ipsec_app {
	struct rcu_head rcu;
	//struct list_head list; /* Pointer to next app if applicable */
	struct v_ipsec_dev_hndl dev_handle;	
	g_ipsec_la_instance_broken_cbk_fn cb_fn;	/* Callback function to be called when the connection to the underlying accelerator is broken */
	void *cb_arg;	/* Callback argument */
	int32_t cb_arg_len;	/* Callback argument length */
	char *identity;
	u8 mode; /* SHARED or EXCLUSIVE */
	u32 num_groups;
	bool has_groups;
	struct v_ipsec_app_list_hndl list_hndl;
	union
	{
		struct {
			struct list_head groups; /* List of sub-application context blocks */
		}groups_wrapper;
		struct {
			struct list_head cmd_context;
			struct list_head sas;
			struct virt_ipsec_notify_cb_info *hooks;
			u32 num_sa_ops_pending;
		}no_groups_wrapper;
	}u;
	spinlock_t lock;
};
struct v_ipsec_app_hndl_ref {
	struct rcu_head rcu;
	struct list_head link;
	struct v_ipsec_app_hndl hndl;
	
};

struct v_ipsec_app_grp_hndl {
	u8 handle[G_IPSEC_LA_GROUP_HANDLE_SIZE];
};

struct v_ipsec_app_grp_list_hndl{
	u8 handle[G_IPSEC_LA_INTERNAL_HANDLE_SIZE];
};


struct v_ipsec_app_grp
{
	struct rcu_head rcu;
	char *identity;
	bool b_half_open;
	u32 hw_handle[VIRTIO_IPSEC_GROUP_HANDLE_SIZE];
	struct v_ipsec_app_hndl app_hdl;
	struct v_ipsec_app_grp_list_hndl list_hdl;
	struct list_head sas;
	struct list_head cmd_context;
	u32 num_sa_ops_pending;
	struct virt_ipsec_notify_cb_info *hooks;
	spinlock_t lock;
};

struct v_ipsec_app_grp_hndl_ref {
	struct rcu_head rcu;
	struct list_head link;
	struct v_ipsec_app_grp_hndl hndl;
};

struct v_ipsec_sa_list_hndl{
	u8 handle[G_IPSEC_LA_INTERNAL_HANDLE_SIZE];
};


struct v_ipsec_sa{
	struct rcu_head rcu;
	//struct list_head link;
	u32 hw_sa_handle[VIRTIO_IPSEC_SA_HANDLE_SIZE];
	bool in_group;
	union {
		struct v_ipsec_app_grp_hndl grp_hndl;
		struct v_ipsec_app_hndl app_hndl;
	};
	struct list_head cmd_ctxt;           /* list of cmd on this SA */
	//struct list_head data_ctxt;
	u32 num_data_ctx;
	struct v_ipsec_sa_list_hndl list_hdl;/* safe-ref to SA safe-ref, why??? */
	spinlock_t lock;
};


struct v_ipsec_sa_hndl_ref {
	struct rcu_head rcu;
	struct list_head link;      /* used to link SAs in app or group */
	struct v_ipsec_sa_hndl hndl;/* safe-ref (index,magic) of SA */
};

struct virt_ipsec_cmd_ctx {
	bool b_wait;
	wait_queue_head_t  waitq;
	bool cond;
	g_ipsec_la_resp_cbfn cb_fn;/* Response function */
	void *cb_arg;              /* Response callback argument */
	int32_t cb_arg_len;        /* Callback argument length */
	void *cmd_buffer;          /* Command buffer */
	int32_t cmd_buffer_len;    /* Command buffer length */
	bool b_group;
	u8 hndl[G_IPSEC_LA_INTERNAL_HANDLE_SIZE];
	struct list_head link;
	void *out_args;
	u8 *result_ptr;
};

struct virt_ipsec_notify_cb_info {
	struct g_ipsec_la_notification_hooks hooks;
};

void dbg_prt_blk(char *str, void *key, int keylen)
{
#define __MAX_WORDS_PER_LINE   8
    char tstr[9 * __MAX_WORDS_PER_LINE];
    char *pstr;
    unsigned char *ptr = key;
    int jj;

    printk("%s ptr %p len %d\n", str, key, keylen);
    jj = 0; pstr = tstr;
    while (keylen-- > 0) {
        sprintf(pstr, "%02X", *ptr++);
        ++jj; pstr += 2;
        if ((jj & 3) == 0) {
            if ((jj >> 2) == __MAX_WORDS_PER_LINE) {
                /* print this line */
                *pstr = '\0'; printk("%s\n", tstr);
                pstr = tstr; jj = 0;
            } else {
                /* add a blank after 4 bytes */
                *pstr++ = ' ';
            }
        }
    }
    /* print last line */
    if (jj) {
        *pstr = '\0'; printk("%s\n", tstr);
    }
}
EXPORT_SYMBOL(dbg_prt_blk);

#if 0
struct virt_ipsec_info *g_ipsec_dev = NULL;
void dbg_prt_info(char *func, int line)
{
	printk("%s:%d: ", func, line);
	dbg_prt_blk("ipsec info:", g_ipsec_dev, sizeof(struct virt_ipsec_info));
}
EXPORT_SYMBOL(dbg_prt_info);
#endif

int32_t safe_ref_array_setup(
	struct safe_ref_array *table,  
	u32 num_entries, bool b_lock)
{
	int ii;
	struct safe_ref_array_node *node;

	node = (struct safe_ref_array_node *)
		kzalloc((sizeof(struct safe_ref_array_node)*num_entries), GFP_KERNEL);

	if (NULL == node) {
		return -ENOMEM;
	}
	table->head = table->base = node;
	table->num_entries = num_entries;
	table->magic_num= 1;

	/* Set up first node */
	node[0].prev = NULL;
	node[0].next = &(node[1]);
	for (ii = 1; ii < (num_entries-1); ii++) {
		node[ii].next = &(node[ii+1]);
		node[ii].prev = &(node[ii-1]);
	}
	/* Set up Last node */
	node[ii].next = NULL;
	node[ii].prev = &(node[ii-1]);

	if (b_lock)
		spin_lock_init(&table->lock);

	table->num_cur_entries = 0;
	table->b_lock = b_lock;

	return 0;
}

void safe_ref_array_cleanup(struct safe_ref_array *table)
{
	if (table->base)
		kfree(table->base);
}

/* ptrArray_add */
static inline unsigned int safe_ref_array_add(
	struct safe_ref_array *table,  void *data)
{
	unsigned int index;
	struct safe_ref_array_node *node;

	if (table->b_lock)
		spin_lock_bh(&table->lock);

	if (table->num_cur_entries >= table->num_entries)	{
		spin_unlock_bh(&table->lock);
		index = table->num_entries;
		goto err_max_table;
	}
	
	if (table->head == NULL) {
		node = NULL;
	} else {
		node = table->head;
		table->head = table->head->next;
		if (table->head)
			table->head->prev = NULL;

	}
	table->num_cur_entries++;
	if (table->b_lock)
		spin_unlock_bh(&table->lock);

	if (node) {
		node->next = NULL;
		node->prev = NULL;
		node->data = data;
		node->magic_num = table->magic_num;
		table->magic_num = (table->magic_num + 1) == 0 ? 1 :  table->magic_num+1;
		index = node - table->base;
		smp_wmb();
	} else {
		index= table->num_entries +1;
	}

#ifdef POINTER_ARRAY_DEBUG
	printk("safe_ref_array_add : Index =%d, pNode = 0x%x, pTable->base = 0x%x\r\n", ulIndex, pNode, pTable->base);
#endif

err_max_table:
	return index;
}

static inline void safe_ref_array_node_delete(
	struct safe_ref_array *table, 
	u32 index,
	void (*func)(struct rcu_head *rcu))
{
	struct safe_ref_array_node *node = &(table->base[index]);
	struct rcu_head *data;


	node->magic_num= 0;
	data = node->data;
	node->data = NULL;

	smp_wmb();

	if (table->b_lock)
		spin_lock_bh(&table->lock);
	if (table->head) {
		node->next = table->head;
		table->head->prev = node;
	}
	table->head = node;
	if (table->b_lock)
		spin_unlock_bh(&table->lock);

	if (func != NULL)
		call_rcu(data,  func);
}
static inline void add_notification_hooks_to_app(
	struct v_ipsec_app *app,
	struct virt_ipsec_notify_cb_info *notify) {

	spin_lock_bh(&app->lock);
	app->u.no_groups_wrapper.hooks = notify;
	spin_unlock_bh(&app->lock);
	
}

static inline void remove_notification_hooks_from_app(
	struct v_ipsec_app *app) {
	
	struct virt_ipsec_notify_cb_info *hooks;
	spin_lock_bh(&app->lock);
	hooks = app->u.no_groups_wrapper.hooks;
	app->u.no_groups_wrapper.hooks = NULL;
	spin_unlock_bh(&app->lock);
	kfree(hooks);
}
	
static inline void add_notification_hooks_to_group(
	struct v_ipsec_app_grp *grp,
	struct virt_ipsec_notify_cb_info *notify) {
	
	spin_lock_bh(&grp->lock);
	grp->hooks = notify;
	spin_unlock_bh(&grp->lock);
		
}

static inline void remove_notification_hooks_from_group(
	struct v_ipsec_app_grp *grp) {

	struct virt_ipsec_notify_cb_info *hooks;

	spin_lock_bh(&grp->lock);
	hooks = grp->hooks;
	grp->hooks = NULL;
	spin_unlock_bh(&grp->lock);
	kfree(hooks);
}
	

static inline void add_app_to_dev(struct v_ipsec_device *dev,
	struct v_ipsec_app_hndl_ref *app_ref) {
	
	spin_lock_bh(&dev->lock);
	list_add_tail(&app_ref->link, &dev->apps);
	spin_unlock_bh(&dev->lock);
}

static inline void remove_app_from_dev(struct v_ipsec_device *dev,
	struct v_ipsec_app_hndl_ref * app_ref) {

	spin_lock_bh(&dev->lock);
	list_del(&app_ref->link);
	spin_unlock_bh(&dev->lock);
}


/* App related list functions */
static inline void add_group_to_app(struct v_ipsec_app *app,
	struct v_ipsec_app_grp_hndl_ref*grp_ref) {
	
	spin_lock_bh(&app->lock);
	list_add_tail(&grp_ref->link, &app->u.groups_wrapper.groups);
	spin_unlock_bh(&app->lock);
}

static inline void remove_group_from_app(struct v_ipsec_app *app,
	struct v_ipsec_app_grp_hndl_ref * grp) {

	spin_lock_bh(&app->lock);
	list_del(&grp->link);
	spin_unlock_bh(&app->lock);
}

static inline void add_cmd_ctx_to_app(struct v_ipsec_app *app,
	struct virt_ipsec_cmd_ctx *cmd) {

	spin_lock_bh(&app->lock);
	list_add_tail(&cmd->link, &app->u.no_groups_wrapper.cmd_context);
	spin_unlock_bh(&app->lock);
}

static inline void remove_cmd_ctx_from_app(struct v_ipsec_app *app,
	struct virt_ipsec_cmd_ctx *cmd) {

	spin_lock_bh(&app->lock);
	list_del(&cmd->link);
	spin_unlock_bh(&app->lock);
}

static inline void add_sa_to_app(struct v_ipsec_app *app,
	struct v_ipsec_sa_hndl_ref *sa_ref) {
	spin_lock_bh(&app->lock);
	list_add_tail(&sa_ref->link, &app->u.no_groups_wrapper.sas);
	spin_unlock_bh(&app->lock);
}

static inline void remove_sa_from_app(struct v_ipsec_app *app,
	struct v_ipsec_sa_hndl_ref *sa_ref) {
	spin_lock_bh(&app->lock);
	list_del(&sa_ref->link);
	spin_unlock_bh(&app->lock);
}

static inline void num_pending_sa_ops_inc(struct v_ipsec_app *app,
	struct v_ipsec_app_grp *group, struct v_ipsec_sa *sa)
{
	if (sa->in_group == true) {
		spin_lock_bh(&group->lock);
		group->num_sa_ops_pending++;
		spin_unlock_bh(&group->lock);
		}
	else {
		spin_lock_bh(&app->lock);
		app->u.no_groups_wrapper.num_sa_ops_pending++;
		spin_unlock_bh(&app->lock);
		}
}

static inline void num_pending_sa_ops_dec(struct v_ipsec_app *app,
	struct v_ipsec_app_grp *group, bool flag)
{
	if (flag == true) {
		spin_lock_bh(&group->lock);
		group->num_sa_ops_pending--;
		spin_unlock_bh(&group->lock);
		}
	else {
		spin_lock_bh(&app->lock);
		app->u.no_groups_wrapper.num_sa_ops_pending--;
		spin_unlock_bh(&app->lock);
		}
}

static inline bool num_pending_sa_ops_check(struct v_ipsec_app *app,
	struct v_ipsec_app_grp *group, bool b_check_group)
{
	bool ret;
	if (b_check_group == true) {
		spin_lock_bh(&group->lock);
		ret = (group->num_sa_ops_pending > 0)? true: false;;
		spin_unlock_bh(&group->lock);
		}
	else {
		spin_lock_bh(&app->lock);
		ret = (app->u.no_groups_wrapper.num_sa_ops_pending > 0) ? true:false;
		spin_unlock_bh(&app->lock);
		}
	return ret;
}


/* Group related macros */
/* SA related macros */
static inline void add_sa_to_group(struct v_ipsec_app_grp *grp,
	struct v_ipsec_sa_hndl_ref *sa_ref) {
	spin_lock_bh(&grp->lock);
	list_add_tail(&sa_ref->link, &grp->sas);
	spin_unlock_bh(&grp->lock);
}

static inline void remove_sa_from_group(struct v_ipsec_app_grp *grp,
	struct v_ipsec_sa_hndl_ref *sa_ref) {
	spin_lock_bh(&grp->lock);
	list_del(&sa_ref->link);
	spin_unlock_bh(&grp->lock);
	
}

static inline void add_cmd_ctx_to_group(struct v_ipsec_app_grp *grp,
	struct virt_ipsec_cmd_ctx *cmd_ctxt)
{
	spin_lock_bh(&grp->lock);
	list_add_tail(&cmd_ctxt->link, &grp->cmd_context);
	spin_unlock_bh(&grp->lock);
}

static inline void remove_cmd_ctx_from_group(struct v_ipsec_app_grp *grp,
	struct virt_ipsec_cmd_ctx *cmd_ctxt)
{
	spin_lock_bh(&grp->lock);
	list_del(&cmd_ctxt->link);
	spin_unlock_bh(&grp->lock);
}

static inline void add_cmd_ctx_to_sa(struct v_ipsec_sa *sa,
	struct virt_ipsec_cmd_ctx *cmd_ctxt)
{
	spin_lock_bh(&sa->lock);
	list_add_tail(&cmd_ctxt->link, &sa->cmd_ctxt);
	spin_unlock_bh(&sa->lock);
}

static inline void remove_cmd_ctx_from_sa(struct v_ipsec_sa *sa,
	struct virt_ipsec_cmd_ctx *cmd_ctxt)
{
	spin_lock_bh(&sa->lock);
	list_del(&cmd_ctxt->link);
	spin_unlock_bh(&sa->lock);
}


static inline bool has_pending_data_blocks(struct v_ipsec_sa *sa)
{
	bool ret;
	spin_lock_bh(&sa->lock);
	ret = (sa->num_data_ctx > 0)? true: false;
	spin_unlock_bh(&sa->lock);

	return ret;
}

static inline void pending_data_blocks_inc(struct v_ipsec_sa *sa)
{
	spin_lock_bh(&sa->lock);
	sa->num_data_ctx++;
	spin_unlock_bh(&sa->lock);
}

static inline void pending_data_blocks_dec(struct v_ipsec_sa * sa)
{
	spin_lock_bh(&sa->lock);
	sa->num_data_ctx--;
	spin_unlock_bh(&sa->lock);
}

/* Macros */
#define VIRTIO_IPSEC_MAX_ENCAP_DECAP_QUEUES 	128

static struct tasklet_struct _encap_queue_cleanup[NR_CPUS];
static struct tasklet_struct _decap_queue_cleanup[NR_CPUS];

struct _job_cleanup_list{
	struct list_head list;
	spinlock_t lock;
};

static struct _job_cleanup_list _encap_cleanup_lists[NR_CPUS];
static struct _job_cleanup_list _decap_cleanup_lists[NR_CPUS];



/* To be reomoved SAI?
struct app_info {

	void (*op_complete_cbk)(
	struct scatterlist cmd_resp_sg[2];
	struct scatterlist data[2*(MAX_SKB_FRAGS+2)]);
};
*/


struct virtipsec_config
{
	/* Queue Information */
	__u32 device_num_queues; /* Number of Queues as set by the device */
	#define VIRTIO_IPSEC_MAX_QUEUES(x)	(x & 0xffff)
	#define VIRTIO_IPSEC_DSCP_BASED_QUEUES(x)	((x & 0xf0000) >> 16)
	#define VIRTIO_IPSEC_DEVICE_SIDE_SCALING(x)	((x & 0x3f00000)>>20 )
	#define VIRTIO_IPSEC_GUEST_SIDE_SCALING(x)	((x & 0xfc000000) >> 26)
	__u32 guest_num_queues;  /* Number of Queues as required by the guest */
} __attribute__ ((packed));


#define decap2vq(i) ((i*2)+1)
#define encap2vq(i) ((i*2)+2)
#define vq2dataqpair(vq) ((vq->index-1)/2)
#define vq2dataqpair(vq) ((vq->index-1)/2)


/* Tasklet functions */
static void _encap_done(unsigned long cpu)
{
	struct virt_ipsec_info *ipsec_dev;
	struct virtqueue *encap_q;
	struct ipsec_queue *queue;
	struct virt_ipsec_data_ctx *d_ctx;
	struct list_head *list, *next_queue;
	unsigned int len;
	struct v_ipsec_sa *sa;
	struct v_ipsec_app *app;
	struct v_ipsec_app_grp *grp;

	VIRTIO_IPSEC_ENTRY("\n");
	/* Get the lock and dequeue the first queue */
	spin_lock_bh(&_encap_cleanup_lists[cpu].lock);
	list = &_encap_cleanup_lists[cpu].list;
	INIT_LIST_HEAD(&(_encap_cleanup_lists[cpu].list));
	spin_unlock_bh(&_encap_cleanup_lists[cpu].lock);

	/* Dequeue first item from temporary list */
	next_queue = list->next;
	while (next_queue != list) {
		queue = (struct ipsec_queue *)next_queue;
		next_queue = queue->link.next;
		encap_q = queue->vq;
		ipsec_dev = encap_q->vdev->priv;
		
		while ((d_ctx = virtqueue_get_buf(encap_q, &len)) != NULL) {
			/* Update any stats: TBD : AVS */
			sa = VIRT_IPSEC_MGR_GET_SA(d_ctx->sa_hndl.handle);
			if (sa != NULL) {
				pending_data_blocks_dec(sa);

				/* find group or app from SA and decrement ops */
				if (sa->in_group == true) {
					grp = safe_ref_get_data(&v_ipsec_grps, GET_INDEX_FROM_HANDLE(sa->grp_hndl.handle));
					if (grp != NULL)
						num_pending_sa_ops_dec(app, grp, sa->in_group);
				}
				else {
					app = safe_ref_get_data(&v_ipsec_apps, GET_INDEX_FROM_HANDLE(sa->app_hndl.handle));
					if (app != NULL)
						num_pending_sa_ops_dec(app, grp, sa->in_group);
				}
			}
			/* Call the callback function Need to fill this up*/
			d_ctx->cb_fn(d_ctx->cb_arg, d_ctx->cb_arg_len, ((void *)(d_ctx->hdr.result)));
		}

		if (virtqueue_enable_cb(encap_q) == true) {
			/* there are pending buffers; so read them off */ 
			while ((d_ctx = virtqueue_get_buf(encap_q, &len)) != NULL) {
				/* Update any stats: TBD: AVS */
				sa = VIRT_IPSEC_MGR_GET_SA(d_ctx->sa_hndl.handle);
				if (sa != NULL) {
					pending_data_blocks_dec(sa);

					/* find group or app from SA and decrement ops */
					if (sa->in_group == true) {
						grp = safe_ref_get_data(
							&v_ipsec_grps, GET_INDEX_FROM_HANDLE(sa->grp_hndl.handle));
						if (grp != NULL)
							num_pending_sa_ops_dec(app, grp, sa->in_group);
					}
					else {
						app = safe_ref_get_data(&v_ipsec_apps, 
							GET_INDEX_FROM_HANDLE(sa->app_hndl.handle));
						if (app != NULL)
							num_pending_sa_ops_dec(app, grp, sa->in_group);
					}
				}
				/* Call the callback function: Need to fill this up */
				d_ctx->cb_fn(d_ctx->cb_arg, d_ctx->cb_arg_len, (void *)d_ctx->hdr.result);
			}
		}
	}
}

static void _decap_done(unsigned long cpu)
{
	struct virt_ipsec_info *ipsec_dev;
	struct virtqueue *decap_q;
	struct ipsec_queue *queue;
	struct virt_ipsec_data_ctx *d_ctx;
	struct list_head *list, *next_elem;
	unsigned int len;
	struct v_ipsec_sa *sa;
	struct v_ipsec_app *app;
	struct v_ipsec_app_grp *grp;

	VIRTIO_IPSEC_ENTRY("\n");
	/* Get the lock and dequeue the first queue */
	spin_lock_bh(&_decap_cleanup_lists[cpu].lock);
	list = &_decap_cleanup_lists[cpu].list;
	INIT_LIST_HEAD(&(_decap_cleanup_lists[cpu].list));
	spin_unlock_bh(&_decap_cleanup_lists[cpu].lock);
	
	/* Dequeue first item from temporary list */
	next_elem = list->next;
	while (next_elem != list) {
		queue = (struct ipsec_queue *)next_elem;
		next_elem = queue->link.next;
		decap_q = queue->vq;
		ipsec_dev = decap_q->vdev->priv;

		while ((d_ctx = virtqueue_get_buf(decap_q, &len)) != NULL) {
			/* Update any stats: TBD : AVS */
			sa = VIRT_IPSEC_MGR_GET_SA(d_ctx->sa_hndl.handle);
			if (sa != NULL) {
				pending_data_blocks_dec(sa);

				/* find group or app from SA and decrement ops */
				if (sa->in_group == true) {
					grp = safe_ref_get_data(&v_ipsec_grps, GET_INDEX_FROM_HANDLE(sa->grp_hndl.handle));
					if (grp != NULL)
						num_pending_sa_ops_dec(app, grp, sa->in_group);
				}
				else {
					app = safe_ref_get_data(&v_ipsec_apps, GET_INDEX_FROM_HANDLE(sa->app_hndl.handle));
					if (app != NULL)
						num_pending_sa_ops_dec(app, grp, sa->in_group);
				}
			}
			/* Call the callback function Need to fill this up*/
			d_ctx->cb_fn(d_ctx->cb_arg, d_ctx->cb_arg_len, (void *)d_ctx->hdr.result);
		}

		if (virtqueue_enable_cb(decap_q) == true) {
				/* there are pending buffers; so read them off */ 
				while ((d_ctx = virtqueue_get_buf(decap_q, &len)) != NULL) {
				/* Update any stats: TBD: AVS */
				sa = VIRT_IPSEC_MGR_GET_SA(d_ctx->sa_hndl.handle);
				if (sa != NULL) {
					pending_data_blocks_dec(sa);

					/* find group or app from SA and decrement ops */
					if (sa->in_group == true) {
						grp = safe_ref_get_data(
							&v_ipsec_grps, GET_INDEX_FROM_HANDLE(sa->grp_hndl.handle));
						if (grp != NULL)
							num_pending_sa_ops_dec(app, grp, sa->in_group);
					}
					else {
						app = safe_ref_get_data(&v_ipsec_apps, 
							GET_INDEX_FROM_HANDLE(sa->app_hndl.handle));
						if (app != NULL)
							num_pending_sa_ops_dec(app, grp, sa->in_group);
					}
				}
				/* Call the callback function: Need to fill this up */
				d_ctx->cb_fn(d_ctx->cb_arg, d_ctx->cb_arg_len, (void *)d_ctx->hdr.result);
			}
		}
	}
}

static void _init_tasklet_lists(void)
{
	uint32_t ii;

	for (ii=0; ii < NR_CPUS; ii++)
	{
		spin_lock_init(&_encap_cleanup_lists[ii].lock);
		INIT_LIST_HEAD(&(_encap_cleanup_lists[ii].list));

		spin_lock_init(&_decap_cleanup_lists[ii].lock);
		INIT_LIST_HEAD(&(_decap_cleanup_lists[ii].list));

		/* Initialize the tasklets */
		tasklet_init(&_decap_queue_cleanup[ii],
			_decap_done, (unsigned long)(ii));
		tasklet_init(&_encap_queue_cleanup[ii],
			_encap_done,(unsigned long)(ii));
	}
}

/* called in interrupt context */
static void control_job_done(struct virtqueue *c_vq)
{
	struct virt_ipsec_info *ipsec_dev = c_vq->vdev->priv;

	VIRTIO_IPSEC_ENTRY("\n");
	/* Disable all the encap_qs for this CPU TBD */
	virtqueue_disable_cb(c_vq);
	schedule_work(&ipsec_dev->c_work);
}
static void notify_done(struct virtqueue *c_vq)
{
	VIRTIO_IPSEC_ENTRY("===unexpected===\n");
}

static void encap_done(struct virtqueue *encap_q)
{
	struct virt_ipsec_info *ipsec_dev = encap_q->vdev->priv;
	struct ipsec_queue *ipsec_q;

	VIRTIO_IPSEC_ENTRY("\n");
	ipsec_q = &(ipsec_dev->data_q_pair[vq2dataqpair(encap_q)].encap_q); 
	
	/* Disable all the encap_qs for this CPU TBD */
	virtqueue_disable_cb(encap_q);

	/* Enqueue the virtqueue to the processor's list */
	list_add((&ipsec_q->link), &(_encap_cleanup_lists[smp_processor_id()].list)); 
	tasklet_schedule(&(_encap_queue_cleanup[smp_processor_id()]));
}

static void decap_done(struct virtqueue *decap_q)
{
	struct virt_ipsec_info *ipsec_dev = decap_q->vdev->priv;
	struct ipsec_queue *ipsec_q;

	VIRTIO_IPSEC_ENTRY("\n");
	ipsec_q = &(ipsec_dev->data_q_pair[vq2dataqpair(decap_q)].decap_q); 
	/* Disable all the encap_qs for this CPU TBD */
	virtqueue_disable_cb(decap_q);

	/* Enqueue the virtqueue to the processor's list */
	list_add((&ipsec_q->link), &(_decap_cleanup_lists[smp_processor_id()].list)); 
	tasklet_schedule(&(_decap_queue_cleanup[smp_processor_id()]));
}

void virt_ipsec_free(struct rcu_head *data)
{
	kfree(data);
};


static inline void sa_flush_list(
	struct virt_ipsec_cmd_ctx *ctx,
	struct v_ipsec_app *app,
	struct v_ipsec_app_grp *group) 
{
	struct v_ipsec_sa_hndl_ref *sa_ref;
	struct v_ipsec_sa *sa;
	u32 sa_ref_index, sa_index;

	do {
		if (ctx->b_group == true) {
			spin_lock_bh(&group->lock);
			sa_ref = list_first_entry_or_null(
				&(group->sas),struct v_ipsec_sa_hndl_ref,link);
			if (sa_ref != NULL)
				list_del(&sa_ref->link);
			spin_unlock_bh(&group->lock);
		}else {
			spin_lock_bh(&app->lock);
			sa_ref = list_first_entry_or_null(
				&(app->u.no_groups_wrapper.sas),
				struct v_ipsec_sa_hndl_ref, link);
			if (sa_ref != NULL)
				list_del(&sa_ref->link);
			spin_unlock_bh(&app->lock);
		}
		if (sa_ref != NULL)
		{
			sa_index = GET_INDEX_FROM_HANDLE(sa_ref->hndl.handle);
			sa = (struct v_ipsec_sa *) safe_ref_get_data(&v_ipsec_sas, sa_index);
			if (sa == NULL)
			{
				VIRTIO_IPSEC_DEBUG(
				"%s:%s:%d: Unable to parse result for sa_handle %d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(sa_ref->hndl.handle));

				/* Handle error : TBD */
			}
			sa_ref_index = GET_INDEX_FROM_HANDLE(sa->list_hdl.handle);
			safe_ref_array_node_delete(&v_ipsec_sas,sa_index,virt_ipsec_free);
			safe_ref_array_node_delete(&v_ipsec_sa_hndl_refs, sa_ref_index, virt_ipsec_free);
		}
		else 
			break;
	}while(1);
}

	


/* Forward Function Declarations */

static inline int32_t virt_ipsec_map_result(struct virtio_ipsec_ctrl_result *result)
{
	return(result->result);
}


void group_delete_cleanup(
	struct virt_ipsec_cmd_ctx *ctx,
	struct v_ipsec_app *app,
	struct v_ipsec_app_grp *group,
	struct v_ipsec_app_grp_hndl_ref *g_ref)
{
	u32 grp_index = GET_INDEX_FROM_HANDLE(g_ref->hndl.handle);
	u32 grp_ref_index = GET_INDEX_FROM_HANDLE(group->list_hdl.handle);
	
	remove_cmd_ctx_from_group(group, ctx);

	virt_ipsec_msg_release(ctx->cmd_buffer);

	kfree(ctx);

	remove_group_from_app(app, g_ref);

	safe_ref_array_node_delete(&v_ipsec_grps, grp_index, virt_ipsec_free);
	safe_ref_array_node_delete(&v_ipsec_grps, grp_ref_index, virt_ipsec_free);
}



void group_add_cleanup(
	struct virt_ipsec_cmd_ctx *cmd_ctx,
	struct v_ipsec_app *app,
	struct v_ipsec_app_grp *group,
	struct v_ipsec_app_grp_hndl_ref *g_ref)
{
	
	add_group_to_app(app,g_ref);
	/* Remove cmd context from group */
	remove_cmd_ctx_from_group(group,cmd_ctx);

	virt_ipsec_msg_release(cmd_ctx->cmd_buffer);
	kfree(cmd_ctx);
}

void sa_add_cleanup(
	struct virt_ipsec_cmd_ctx *cmd_ctx,
	struct v_ipsec_app *app,
	struct v_ipsec_app_grp *grp,
	struct v_ipsec_sa *sa, 
	struct v_ipsec_sa_hndl_ref *sa_ref) 
{

	if (sa->in_group == false)
		/* Add to app sa list: No groups  */
		add_sa_to_app(app,sa_ref);
	else
		add_sa_to_group(grp,sa_ref);

	num_pending_sa_ops_dec(app, grp, sa->in_group);
	
	/* Remove cmd context from group */
	remove_cmd_ctx_from_sa(sa,cmd_ctx);

	virt_ipsec_msg_release(cmd_ctx->cmd_buffer);
	kfree(cmd_ctx);
}

void sa_mod_cleanup(
	struct virt_ipsec_cmd_ctx *cmd_ctx,
	struct v_ipsec_app *app,
	struct v_ipsec_app_grp *grp,
	struct v_ipsec_sa *sa)
{
	num_pending_sa_ops_dec(app, grp, sa->in_group);
	
	remove_cmd_ctx_from_sa(sa, cmd_ctx);

	virt_ipsec_msg_release(cmd_ctx->cmd_buffer);
	kfree(cmd_ctx);
}


void sa_del_cleanup(
	struct virt_ipsec_cmd_ctx *cmd_ctx,
	struct v_ipsec_app *app,
	struct v_ipsec_app_grp *grp,
	struct v_ipsec_sa *sa, 
	struct v_ipsec_sa_hndl_ref *sa_ref) 
{

	u32 sa_index = GET_INDEX_FROM_HANDLE(sa_ref->hndl.handle);
	u32 sa_ref_index = GET_INDEX_FROM_HANDLE(sa->list_hdl.handle);
	

	/* Remove the SA from the group or application */
	if(sa->in_group == true)
		remove_sa_from_group(grp, sa_ref);
	else
		remove_sa_from_app(app, sa_ref);

	num_pending_sa_ops_dec(app, grp, sa->in_group);
	
	/* Remove cmd context from group */
	remove_cmd_ctx_from_sa(sa,cmd_ctx);

	virt_ipsec_msg_release(cmd_ctx->cmd_buffer);
	kfree(cmd_ctx);

	safe_ref_array_node_delete(&v_ipsec_sas, sa_index, virt_ipsec_free);
	safe_ref_array_node_delete(&v_ipsec_grps, sa_ref_index, virt_ipsec_free);

	
}


void capabilities_get_cleanup(struct virt_ipsec_cmd_ctx *cmd_ctxt,
	struct v_ipsec_app *app,
	struct v_ipsec_app_grp *group)
{
	if (cmd_ctxt->b_group == false) {
		/* remove command context from app */
		remove_cmd_ctx_from_app(app,cmd_ctxt);
	} 
	else {
		remove_cmd_ctx_from_group(group, cmd_ctxt);
	}

	/* free the message */
	virt_ipsec_msg_release(cmd_ctxt->cmd_buffer);

	/* free the context */
	kfree(cmd_ctxt);
}

/* Result handling functions */
static int32_t handle_group_add_result(
	struct virt_ipsec_cmd_ctx *cmd_ctx)
{
	struct virtio_ipsec_group_add *msg_group;
	struct virtio_ipsec_ctrl_result *result;
	struct v_ipsec_app *app;
	struct v_ipsec_app_grp *grp;
	struct v_ipsec_app_grp_hndl_ref *g_ref;
	struct g_ipsec_la_group_create_outargs *out;
	int32_t ret;

	if (virt_ipsec_msg_group_add_parse_result(cmd_ctx->cmd_buffer,
		cmd_ctx->cmd_buffer_len, &result, &msg_group,
		cmd_ctx->result_ptr) == VIRTIO_IPSEC_FAILURE)
	{
		/* call callback with error */
		/* TBD */
	}
	/* Need to check if this works SAI */
	grp = safe_ref_get_data(&v_ipsec_grps, GET_INDEX_FROM_HANDLE(cmd_ctx->hndl));

	if (grp == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Unable to parse result for group_handle :%d:%d\n",
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(cmd_ctx->hndl));

		/* Handle error : TBD */
	}

	g_ref = safe_ref_get_data(&v_ipsec_grp_hndl_refs, 
		GET_INDEX_FROM_HANDLE(grp->list_hdl.handle));
	if (g_ref == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Unable to parse result for sa_handle :%d:%d\n",
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(cmd_ctx->hndl));

		/* Handle error : TBD */
	}

	app = safe_ref_get_data(&v_ipsec_apps,GET_INDEX_FROM_HANDLE(grp->app_hdl.handle));
	if (app == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Unable to parse result for sa_handle :%d:%d\n",
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(cmd_ctx->hndl));

		/* Handle error : TBD */
	}

	/* Check the result */
	if (result->result != VIRTIO_IPSEC_SUCCESS)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Backend returned failure(0x%x:0x%x for add group:%d:%d\n",
			__FILE__, __func__, __LINE__, result->result, result->result_data, 
			EXPAND_HANDLE(cmd_ctx->hndl));
		/* Handle error: TBD */
	}
	
	/* Copy the hardware handle in group */
	memcpy(grp->hw_handle, msg_group->group_handle, VIRTIO_IPSEC_GROUP_HANDLE_SIZE);

	/* Reset the half-open state */
	grp->b_half_open = false;


	ret  = virt_ipsec_map_result(result); 

	
	out = (struct g_ipsec_la_group_create_outargs *)cmd_ctx->out_args;
	out->result = ret;
	memcpy(out->group_handle, cmd_ctx->hndl, G_IPSEC_LA_GROUP_HANDLE_SIZE);

	if (cmd_ctx->b_wait == true)
		return ret;

	/* Asynchronous response */
	cmd_ctx->cb_fn(cmd_ctx->cb_arg, cmd_ctx->cb_arg_len, out);

	group_add_cleanup(cmd_ctx,app,grp,g_ref);

	return G_IPSEC_LA_SUCCESS;
	
}


static int32_t handle_group_delete_result(
	struct virt_ipsec_cmd_ctx *cmd_ctx)
{
	struct v_ipsec_app *app;
	struct v_ipsec_app_grp *grp;
	struct v_ipsec_app_grp_hndl_ref *g_ref;
	struct g_ipsec_la_group_delete_outargs *out_arg;
	struct virtio_ipsec_ctrl_result *result;
	int32_t ret;
	/* TBD */

	if (virt_ipsec_msg_delete_group_parse_result(
		cmd_ctx->cmd_buffer,
		cmd_ctx->cmd_buffer_len, &result,
		cmd_ctx->result_ptr) == VIRTIO_IPSEC_FAILURE)
	{
		/* call callback with error */
		/* TBD */
	}
	
	
	grp = safe_ref_get_data(&v_ipsec_grps, GET_INDEX_FROM_HANDLE(cmd_ctx->hndl));
	if (grp == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Unable to parse result for sa_handle :%d:%d\n",
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(cmd_ctx->hndl));

		/* Handle error : TBD */
	}

	g_ref = safe_ref_get_data(&v_ipsec_grp_hndl_refs, 
		GET_INDEX_FROM_HANDLE(grp->list_hdl.handle));
	if (g_ref == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Unable to parse result for sa_handle :%d:%d\n",
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(cmd_ctx->hndl));

		/* Handle error : TBD */
	}

	app = safe_ref_get_data(&v_ipsec_apps,GET_INDEX_FROM_HANDLE(grp->app_hdl.handle));
	if (app == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Unable to parse result for sa_handle :%d:%d\n",
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(cmd_ctx->hndl));

		/* Handle error : TBD */
	}
	
	/* Check the result */
	if (result->result != VIRTIO_IPSEC_SUCCESS)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Backend returned failure(0x%x:0x%x for add group:%d:%d\n",
			__FILE__, __func__, __LINE__, result->result, result->result_data, 
			EXPAND_HANDLE(cmd_ctx->hndl));
		/* Handle error: TBD */
	}

	ret = virt_ipsec_map_result(result); 

	out_arg = (struct g_ipsec_la_group_delete_outargs *)cmd_ctx->out_args;
	out_arg->result = ret;
	
	if (cmd_ctx->b_wait == true)
		return ret;

	
	/* Asynchronous response */
	cmd_ctx->cb_fn(cmd_ctx->cb_arg, cmd_ctx->cb_arg_len, out_arg);

	/* Remove cmd context from group */
	group_delete_cleanup(cmd_ctx, app, grp, g_ref);
		
	return G_IPSEC_LA_SUCCESS;
}



static void get_caps(
	struct v_ipsec_device *dev,
	struct virtio_ipsec_ctrl_capabilities *caps, 
	struct g_ipsec_la_cap_get_outargs *out_arg)
{
	out_arg->caps.sg_features= dev->info->sg_buffer;
	out_arg->caps.ah_protocol = dev->info->ah;
	out_arg->caps.esp_protocol = 1; /* always supported */
	out_arg->caps.ipcomp_protocol = 0; /* Not supported */
	out_arg->caps.wesp_protocol = dev->info->wesp;
	out_arg->caps.multi_sec_protocol= dev->info->sa_bundles;
	out_arg->caps.udp_encap = dev->info->udp_encap;
	out_arg->caps.tfc = dev->info->tfc;
	out_arg->caps.esn = dev->info->esn;
	out_arg->caps.ecn = dev->info->ecn;
	out_arg->caps.df = dev->info->df;
	out_arg->caps.anti_replay_check = dev->info->anti_replay;
	out_arg->caps.ipv6_support = dev->info->ipv6_support;
	out_arg->caps.soft_lifetime_bytes_notify = dev->info->notify_lifetime;
	out_arg->caps.seqnum_overflow_notify = dev->info->notify_seqnum_overflow;
	out_arg->caps.seqnum_periodic_notify = dev->info->notify_seqnum_periodic;

	if (caps->hmac_algorithms & VIRTIO_IPSEC_HMAC_NULL)
		out_arg->caps.auth_algo_caps.none = 1;
	if (caps->hmac_algorithms & VIRTIO_IPSEC_HMAC_MD5)
		out_arg->caps.auth_algo_caps.md5 = 1;
	if ((caps->hmac_algorithms & VIRTIO_IPSEC_HMAC_SHA1) ||
		(caps->hmac_algorithms & VIRTIO_IPSEC_HMAC_SHA1_160))
		out_arg->caps.auth_algo_caps.sha1 = 1;
	if (caps->hmac_algorithms & VIRTIO_IPSEC_HMAC_AES_XCBC_MAC)
		out_arg->caps.auth_algo_caps.aes_xcbc = 1;

	if ((caps->hmac_algorithms & VIRTIO_IPSEC_HMAC_SHA256) || 
		(caps->hmac_algorithms & VIRTIO_IPSEC_HMAC_SHA384) || 
		(caps->hmac_algorithms & VIRTIO_IPSEC_HMAC_SHA384)) 
		out_arg->caps.auth_algo_caps.sha2 = 1;

	if (caps->cipher_algorithms & VIRTIO_IPSEC_DES_CBC)
		out_arg->caps.cipher_algo_caps.des= 1;
	if (caps->cipher_algorithms & VIRTIO_IPSEC_3DES_CBC)
		out_arg->caps.cipher_algo_caps.des_3= 1;
	if (caps->cipher_algorithms & VIRTIO_IPSEC_ESP_NULL)
		out_arg->caps.cipher_algo_caps.null= 1;
	if (caps->cipher_algorithms & VIRTIO_IPSEC_AES_CBC)
		out_arg->caps.cipher_algo_caps.aes= 1;
	if (caps->cipher_algorithms & VIRTIO_IPSEC_AESCTR)
		out_arg->caps.cipher_algo_caps.aes_ctr= 1;
	if ((caps->cipher_algorithms & VIRTIO_IPSEC_AES_CCM_ICV8) ||
		(caps->cipher_algorithms & VIRTIO_IPSEC_AES_CCM_ICV12)||
		(caps->cipher_algorithms & VIRTIO_IPSEC_AES_CCM_ICV16))
		out_arg->caps.comb_algo_caps.aes_ccm = 1;
	
	if ((caps->cipher_algorithms &	VIRTIO_IPSEC_AES_GCM_ICV8) ||
		(caps->cipher_algorithms &	VIRTIO_IPSEC_AES_GCM_ICV12)	||
		(caps->cipher_algorithms &	VIRTIO_IPSEC_AES_GCM_ICV16))
		out_arg->caps.comb_algo_caps.aes_gcm = 1;
	if (caps->cipher_algorithms &	VIRTIO_IPSEC_AES_GMAC)
		out_arg->caps.comb_algo_caps.aes_gmac = 1;
		
}


static int32_t handle_capabilities_get_result(
	struct virt_ipsec_cmd_ctx *cmd_ctx 
	) 
{
	struct virtio_ipsec_ctrl_capabilities *caps;
	struct virtio_ipsec_ctrl_result *result;
	struct g_ipsec_la_cap_get_outargs *out_arg;
	struct v_ipsec_app *app = NULL;
	struct v_ipsec_app_grp *group = NULL;
	struct v_ipsec_device *dev;
	int32_t ret;
	
	if (virt_ipsec_msg_capabilities_get_parse_result(
		cmd_ctx->cmd_buffer,
		cmd_ctx->cmd_buffer_len, &result, &caps,
		cmd_ctx->result_ptr) == VIRTIO_IPSEC_FAILURE)
	{
		/* call callback with error */
		/* TBD */
	}

	if (cmd_ctx->b_group == true) {
		group = safe_ref_get_data(&v_ipsec_grps, GET_INDEX_FROM_HANDLE(cmd_ctx->hndl));
		if (group == NULL)
		{
			VIRTIO_IPSEC_DEBUG("%s:%s:%d: Unable to parse result for sa_handle :%d:%d\n",
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(cmd_ctx->hndl));

			/* Handle error : TBD */
		}
		app = safe_ref_get_data(&v_ipsec_apps,GET_INDEX_FROM_HANDLE(group->app_hdl.handle));
		if (app == NULL)
		{
			VIRTIO_IPSEC_DEBUG("%s:%s:%d: Unable to parse result for sa_handle :%d:%d\n",
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(cmd_ctx->hndl));

		/* Handle error : TBD */
		}
	}
	else {
		app = safe_ref_get_data(&v_ipsec_apps,GET_INDEX_FROM_HANDLE(cmd_ctx->hndl));
		if (app == NULL)
		{
			VIRTIO_IPSEC_DEBUG("%s:%s:%d: Unable to parse result for sa_handle :%d:%d\n",
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(cmd_ctx->hndl));

		/* Handle error : TBD */
		}
	}

	dev = VIRT_IPSEC_MGR_GET_DEVICE(app->dev_handle.handle);
	if (dev == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d Unable to get device from handle: %d:%d\n", 
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(cmd_ctx->hndl));
		/* Handle Error */
	}

		/* Check the result */
	if (result->result != VIRTIO_IPSEC_SUCCESS)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Backend returned failure(0x%x:0x%x for capabilities_get:%d:%d\n",
			__FILE__, __func__, __LINE__, result->result, result->result_data, 
			EXPAND_HANDLE(cmd_ctx->hndl));
		/* Handle error: TBD */
	}
	ret = virt_ipsec_map_result(result);

	out_arg = (struct g_ipsec_la_cap_get_outargs*)cmd_ctx->out_args;
	out_arg->result = ret;
	get_caps(dev,  caps, out_arg);
	
	if (cmd_ctx->b_wait == true)
		return ret;

	/* Asynchronous response */
	cmd_ctx->cb_fn(cmd_ctx->cb_arg, cmd_ctx->cb_arg_len, out_arg);

	if (cmd_ctx->b_group) {
		if (group == NULL) {
			VIRTIO_IPSEC_ERROR("===expected non-null group here\n");
			return G_IPSEC_LA_FAILURE;
		}
	} else {
		if (app == NULL) {
			VIRTIO_IPSEC_ERROR("===expected non-null app here\n");
			return G_IPSEC_LA_FAILURE;
		}
	}
	capabilities_get_cleanup(cmd_ctx, app, group);
	return G_IPSEC_LA_SUCCESS;
}


static int32_t handle_sa_add_result(
	struct virt_ipsec_cmd_ctx *cmd_ctx
	)
{
	struct g_ipsec_la_sa_add_outargs *out_arg;
	struct virtio_ipsec_ctrl_result *result;
	struct virtio_ipsec_create_sa *msg_sa;
	struct v_ipsec_sa *sa;
	struct v_ipsec_sa_hndl_ref *sa_ref;
	struct v_ipsec_app *app;
	struct v_ipsec_app_grp *grp;
	int32_t ret;

	if (virt_ipsec_msg_sa_add_parse_result(
		cmd_ctx->cmd_buffer,
		cmd_ctx->cmd_buffer_len, &result, &msg_sa, 
		cmd_ctx->result_ptr) == VIRTIO_IPSEC_FAILURE)
	{
		/* call callback with error */
		/* TBD */
	}
	
	sa = safe_ref_get_data(&v_ipsec_sas, GET_INDEX_FROM_HANDLE(cmd_ctx->hndl));
	if (sa == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Unable to parse result for sa_handle :%d:%d\n",
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(cmd_ctx->hndl));

		/* Handle error : TBD */
	}

	sa_ref = safe_ref_get_data(&v_ipsec_sa_hndl_refs, 
		GET_INDEX_FROM_HANDLE(sa->list_hdl.handle));
	if (sa_ref == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Unable to parse result for sa_handle :%d:%d\n",
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(cmd_ctx->hndl));

		/* Handle error : TBD */
	}
	
	if (sa->in_group == true) {
		grp = safe_ref_get_data(&v_ipsec_grps, GET_INDEX_FROM_HANDLE(sa->grp_hndl.handle));
		if (grp == NULL) {
			
			VIRTIO_IPSEC_DEBUG("%s:%s:%d: Unable to parse result for sa_handle :%d:%d\n",
						__FILE__, __func__, __LINE__, EXPAND_HANDLE(cmd_ctx->hndl));
		}
		app = NULL;
	}
	else {
		app = safe_ref_get_data(&v_ipsec_apps, GET_INDEX_FROM_HANDLE(sa->app_hndl.handle));
		if (app == NULL) {
			
			VIRTIO_IPSEC_DEBUG("%s:%s:%d: Unable to parse result for sa_handle :%d:%d\n",
						__FILE__, __func__, __LINE__, EXPAND_HANDLE(cmd_ctx->hndl));
		}
		grp = NULL;
	}

	/* Check the result */
	if (result->result != VIRTIO_IPSEC_SUCCESS)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Backend returned failure(0x%x:0x%x for add group:%d:%d\n",
			__FILE__, __func__, __LINE__, result->result, result->result_data, 
			EXPAND_HANDLE(cmd_ctx->hndl));
		/* Handle error: TBD */
	}

	/* Copy the hardware handle in group */
	memcpy(sa->hw_sa_handle, msg_sa->sa_handle, VIRTIO_IPSEC_SA_HANDLE_SIZE);

	ret = virt_ipsec_map_result(result);
	VIRTIO_IPSEC_DBG("HW SA hndl 0x%x:%x SW SA handle %d:%d\n",
		EXPAND_HANDLE(msg_sa->sa_handle), EXPAND_HANDLE(cmd_ctx->hndl));
	out_arg = (struct g_ipsec_la_sa_add_outargs *)cmd_ctx->out_args;
	out_arg->result = ret;
	memcpy(out_arg->handle.ipsec_sa_handle, cmd_ctx->hndl, G_IPSEC_LA_SA_HANDLE_SIZE);

	/* Asynchronous response */
	if (cmd_ctx->b_wait == false)
		cmd_ctx->cb_fn(cmd_ctx->cb_arg, cmd_ctx->cb_arg_len, out_arg);

	sa_add_cleanup(cmd_ctx, app, grp, sa, sa_ref);
	return G_IPSEC_LA_SUCCESS;
}

static int32_t handle_sa_mod_result(
	struct virt_ipsec_cmd_ctx *cmd_ctx) 
{
 	struct virtio_ipsec_ctrl_result *result;
	struct v_ipsec_sa *sa;
	struct g_ipsec_la_sa_mod_outargs *out_arg;
	struct v_ipsec_app *app;
	struct v_ipsec_app_grp *grp;
	int32_t ret;

	if (virt_ipsec_msg_sa_mod_parse_result(
		cmd_ctx->cmd_buffer,
		cmd_ctx->cmd_buffer_len, &result, 
		cmd_ctx->result_ptr) == VIRTIO_IPSEC_FAILURE)
	{
		/* call callback with error */
		/* TBD */
	}

	sa = safe_ref_get_data(&v_ipsec_sas, GET_INDEX_FROM_HANDLE(cmd_ctx->hndl));
	if (sa == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Unable to parse result for sa_handle :%d:%d\n",
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(cmd_ctx->hndl));

		/* Handle error : TBD */
	}

	if (sa->in_group == true) {
		grp = safe_ref_get_data(&v_ipsec_grps, GET_INDEX_FROM_HANDLE(sa->grp_hndl.handle));
		if (grp == NULL) {
			
			VIRTIO_IPSEC_DEBUG("%s:%s:%d: Unable to parse result for sa_handle :%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(cmd_ctx->hndl));
		}
		app = NULL;
	}
	else {
		app = safe_ref_get_data(&v_ipsec_apps, GET_INDEX_FROM_HANDLE(sa->app_hndl.handle));
		if (app == NULL) {
			
			VIRTIO_IPSEC_DEBUG("%s:%s:%d: Unable to parse result for sa_handle :%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(cmd_ctx->hndl));
		}
		grp = NULL;
	}
	
	/* Check the result */
	if (result->result != VIRTIO_IPSEC_SUCCESS)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Backend returned failure(0x%x:0x%x for add group:%d:%d\n",
			__FILE__, __func__, __LINE__, result->result, result->result_data, 
			EXPAND_HANDLE(cmd_ctx->hndl));
		/* Handle error: TBD */
	}
	ret = virt_ipsec_map_result(result);
	out_arg = (struct g_ipsec_la_sa_mod_outargs *)cmd_ctx->out_args;
	out_arg->result = ret;

	if (cmd_ctx->b_wait == true)
		return VIRTIO_IPSEC_SUCCESS;

	sa_mod_cleanup(cmd_ctx, app, grp, sa);
	
	return G_IPSEC_LA_SUCCESS;
}

static int32_t handle_sa_del_result(
	struct virt_ipsec_cmd_ctx *cmd_ctx)
{
	struct g_ipsec_la_sa_del_outargs *out_arg;
	struct virtio_ipsec_ctrl_result *result;
	struct v_ipsec_sa *sa;
	struct v_ipsec_sa_hndl_ref *sa_ref;
	struct v_ipsec_app *app;
	struct v_ipsec_app_grp *grp;
	int32_t ret;

	if (virt_ipsec_msg_sa_del_parse_result(
		cmd_ctx->cmd_buffer,
		cmd_ctx->cmd_buffer_len, &result, 
		cmd_ctx->result_ptr) == VIRTIO_IPSEC_FAILURE)
	{
		/* call callback with error */
		/* TBD */
	}
	
	sa = safe_ref_get_data(&v_ipsec_sas, GET_INDEX_FROM_HANDLE(cmd_ctx->hndl));
	if (sa == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Unable to parse result for sa_handle :%d:%d\n",
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(cmd_ctx->hndl));

		/* Handle error : TBD */
	}

	sa_ref = safe_ref_get_data(&v_ipsec_sa_hndl_refs, GET_INDEX_FROM_HANDLE(sa->list_hdl.handle));
	if (sa_ref == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Unable to parse result for sa_handle :%d:%d\n",
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(cmd_ctx->hndl));

		/* Handle error : TBD */
	}
	
	if (sa->in_group == true) {
		grp = safe_ref_get_data(&v_ipsec_grps, GET_INDEX_FROM_HANDLE(sa->grp_hndl.handle));
		if (grp == NULL) {
			
			VIRTIO_IPSEC_DEBUG("%s:%s:%d: Unable to parse result for sa_handle :%d:%d\n",
						__FILE__, __func__, __LINE__, EXPAND_HANDLE(cmd_ctx->hndl));
		}
		app = NULL;
	}
	else {
		app = safe_ref_get_data(&v_ipsec_apps, GET_INDEX_FROM_HANDLE(sa->app_hndl.handle));
		if (app == NULL) {
			
			VIRTIO_IPSEC_DEBUG("%s:%s:%d: Unable to parse result for sa_handle :%d:%d\n",
						__FILE__, __func__, __LINE__, EXPAND_HANDLE(cmd_ctx->hndl));
		}
		grp = NULL;
	}

	/* Check the result */
	if (result->result != VIRTIO_IPSEC_SUCCESS)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Backend returned failure(0x%x:0x%x for add group:%d:%d\n",
			__FILE__, __func__, __LINE__, result->result, result->result_data, 
			EXPAND_HANDLE(cmd_ctx->hndl));
		/* Handle error: TBD */
	}

	ret = virt_ipsec_map_result(result);

	out_arg = (struct g_ipsec_la_sa_del_outargs *)cmd_ctx->out_args;
	out_arg->result = ret;

	if (cmd_ctx->b_wait == true)
		return VIRTIO_IPSEC_SUCCESS;

	

	/* Asynchronous response */
	cmd_ctx->cb_fn(cmd_ctx->cb_arg, cmd_ctx->cb_arg_len, out_arg);

	sa_del_cleanup(cmd_ctx, app, grp, sa, sa_ref);
	
	return G_IPSEC_LA_SUCCESS;
}

void sa_flush_cleanup(
	struct virt_ipsec_cmd_ctx *cmd_ctx, 
	struct v_ipsec_app *app, 
	struct v_ipsec_app_grp *group)
{
	/* Remove the command context from the group or application */
	if(cmd_ctx->b_group== true)
		remove_cmd_ctx_from_group(group, cmd_ctx);
	else
		remove_cmd_ctx_from_app(app, cmd_ctx);
	
	num_pending_sa_ops_dec(app, group, cmd_ctx->b_group);
		
	
	virt_ipsec_msg_release(cmd_ctx->cmd_buffer);
	kfree(cmd_ctx);
	
}

int32_t handle_sa_flush_result(
	struct virt_ipsec_cmd_ctx *cmd_ctx) 
{
	struct g_ipsec_la_sa_flush_outargs *out_arg;
	struct virtio_ipsec_ctrl_result *result;
	struct v_ipsec_app *app = NULL;
	struct v_ipsec_app_grp *group = NULL;
	int32_t ret;

	if (virt_ipsec_msg_sa_flush_parse_result(
		cmd_ctx->cmd_buffer,
		cmd_ctx->cmd_buffer_len, &result,  
		cmd_ctx->result_ptr) == VIRTIO_IPSEC_FAILURE)
	{
		/* call callback with error */
		/* TBD */
	}
	/* Check the result */
	if (result->result != VIRTIO_IPSEC_SUCCESS)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Backend returned failure(0x%x:0x%x for sa flush:%d:%d\n",
			__FILE__, __func__, __LINE__, result->result, result->result_data, 
			EXPAND_HANDLE(cmd_ctx->hndl));
		/* Handle error: TBD */
	}
	if (cmd_ctx->b_group == true) {
		group = safe_ref_get_data(&v_ipsec_grps, GET_INDEX_FROM_HANDLE(cmd_ctx->hndl));
		if (group == NULL) {
			VIRTIO_IPSEC_DEBUG("%s:%s:%d: Unable to parse result for sa_handle :%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(cmd_ctx->hndl));
			// TODO: Handle error : TBD
		}
	} else {
		app = safe_ref_get_data(&v_ipsec_apps,
			GET_INDEX_FROM_HANDLE(cmd_ctx->hndl));
		if (app == NULL)
		{
			VIRTIO_IPSEC_DEBUG("%s:%s:%d: Unable to parse result for sa flush :%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(cmd_ctx->hndl));
			// TODO: Handle error : TBD
		}
	}
	
	ret = virt_ipsec_map_result(result);
	out_arg = (struct g_ipsec_la_sa_flush_outargs *)cmd_ctx->out_args;
	out_arg->result = ret;

	if (cmd_ctx->b_group) {
		if (group == NULL) {
			VIRTIO_IPSEC_ERROR("===expected non-null group here\n");
			return G_IPSEC_LA_FAILURE;
		}
	} else {
		if (app == NULL) {
			VIRTIO_IPSEC_ERROR("===expected non-null app here\n");
			return G_IPSEC_LA_FAILURE;
		}
	}
	sa_flush_cleanup(cmd_ctx, app, group);
	sa_flush_list(cmd_ctx, app, group);
	if (cmd_ctx->b_wait == true)
		return ret;

	/* Asynchronous response */
	cmd_ctx->cb_fn(cmd_ctx->cb_arg, cmd_ctx->cb_arg_len, out_arg);
	return G_IPSEC_LA_SUCCESS;
}

int32_t handle_response(struct virt_ipsec_cmd_ctx *cmd_ctx)
{
	struct virtio_ipsec_ctrl_hdr *hdr = (struct virtio_ipsec_ctrl_hdr *)(cmd_ctx->cmd_buffer);
	int32_t ret = VIRTIO_IPSEC_FAILURE;

	VIRTIO_IPSEC_ENTRY("context %p\n", cmd_ctx);
	switch (hdr->class) {
		case VIRTIO_IPSEC_CTRL_GENERIC:	
			switch(hdr->cmd) {
				case VIRTIO_IPSEC_CTRL_GET_CAPABILITIES:
					ret = handle_capabilities_get_result(cmd_ctx);
					break;
			}
			break;	
		case VIRTIO_IPSEC_CTRL_SA:
			switch (hdr->cmd) {
				case VIRTIO_IPSEC_CTRL_ADD_GROUP:
					ret = handle_group_add_result(cmd_ctx);
					break;
				case VIRTIO_IPSEC_CTRL_DELETE_GROUP:
					ret = handle_group_delete_result(cmd_ctx);
					break;
				case VIRTIO_IPSEC_CTRL_ADD_OUT_SA:
				case VIRTIO_IPSEC_CTRL_ADD_IN_SA:
					ret = handle_sa_add_result(cmd_ctx);
					break;
				case VIRTIO_IPSEC_CTRL_UPDATE_OUT_SA:
				case VIRTIO_IPSEC_CTRL_UPDATE_IN_SA:
					ret = handle_sa_mod_result(cmd_ctx);
					break;
				case VIRTIO_IPSEC_CTRL_DEL_IN_SA:
				case VIRTIO_IPSEC_CTRL_DEL_OUT_SA:
					ret = handle_sa_del_result(cmd_ctx);
					break;
				case VIRTIO_IPSEC_CTRL_FLUSH_SA:
				case VIRTIO_IPSEC_CTRL_FLUSH_SA_ALL:
					ret = handle_sa_flush_result(cmd_ctx);
				default:
					break;
			}
			break;
		case VIRTIO_IPSEC_CTRL_GET_RAND_DATA: 
			break;	
		case VIRTIO_IPSEC_CTRL_ADVANCED:	
			break;	
		default:
			break;
	}
	VIRTIO_IPSEC_EXIT("error %d\n", ret);
	return ret;
}
/* Interface Functions */


static void _ipsec_control_job_done(struct work_struct *work)
{
	unsigned int len;
	struct virt_ipsec_cmd_ctx *cmd_ctx;
	struct virt_ipsec_info *virt_dev =
		container_of(work, struct virt_ipsec_info, c_work);

	VIRTIO_IPSEC_ENTRY("\n");
	while ((cmd_ctx = virtqueue_get_buf(virt_dev->cvq->vq, &len)) != NULL) {
		/* Update any stats : TBD: AVS */
		/* Call the callback function : Need to fill this up */
		if (cmd_ctx->b_wait == true) {
			cmd_ctx->cond = true;
			wake_up_interruptible(&cmd_ctx->waitq);
		} else { /* Call the callback function */
			handle_response(cmd_ctx);
		}
	}
	if (virtqueue_enable_cb(virt_dev->cvq->vq) == true) {
		/* there are pending buffers; so read them off */ 
		while ((cmd_ctx = virtqueue_get_buf(virt_dev->cvq->vq, &len)) != NULL) {
			/* Update any stats: TBD: AVS */
			if (cmd_ctx->b_wait == true) {
				cmd_ctx->cond = true;
				wake_up_interruptible(&cmd_ctx->waitq);
			} else {
				/* Call the callback function: Need to fill this up */
				handle_response(cmd_ctx);
			}
		}
	}
}

int32_t virt_ipsec_send_cmd(struct virt_ipsec_info *dev, 
	struct virt_ipsec_cmd_ctx *cmd_ctx)
{
	struct scatterlist *sgs[1], data;
	struct virtio_ipsec_ctrl_hdr *hdr = (struct virtio_ipsec_ctrl_hdr *)cmd_ctx->cmd_buffer;

	VIRTIO_IPSEC_ENTRY("dev_info %p class %d cmd %d\n", dev, hdr->class, hdr->cmd);
	sg_init_one(&data, cmd_ctx->cmd_buffer, cmd_ctx->cmd_buffer_len);
	sgs[0] = &data;

	/* Need to check if lock is required here */
	virtqueue_add_sgs(dev->cvq->vq, sgs, 1, 0, cmd_ctx, GFP_ATOMIC);
	cmd_ctx->cond = false;	/* do this before vq kick */
	// TODO: find why kick does not work - if (unlikely(!virtqueue_kick(dev->cvq->vq)))
	if (unlikely(!virtqueue_notify(dev->cvq->vq)))
		return VIRTIO_IPSEC_FAILURE;

	if (cmd_ctx->b_wait == true) {
		wait_event_interruptible(cmd_ctx->waitq,cmd_ctx->cond);
	}
	return VIRTIO_IPSEC_SUCCESS;
}

/*
   * Function Name :
   * Input: 
   * Output: 
   * Description:
   */
int32_t virt_ipsec_la_open(
		enum g_ipsec_la_mode mode, 
		struct g_ipsec_la_open_inargs *in, 
		struct g_ipsec_la_open_outargs *out)
{
	char *ptr;
	struct v_ipsec_device *dev;
	uint32_t index;
	struct v_ipsec_app *app;
	struct v_ipsec_app_hndl_ref *app_ref;
	u32 index_ref;
	u32 magic;
	u32 *index_ptr;

	VIRTIO_IPSEC_ENTRY("\n");
	/* Validate Vendor id, device id */
	if ((in->pci_vendor_id != VIRTIO_IPSEC_VENDOR_ID) || (in->device_id != VIRTIO_IPSEC_DEVICE_ID))
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d Device Id:0x%x or Vendor ID:0x%x does not match\n",
			__FILE__, __func__, __LINE__, in->pci_vendor_id, in->device_id);
		return G_IPSEC_LA_FAILURE; 
	}
	/* validate callback function */
	if (!(in->cb_fn))
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d Callback function pointer invalid\n", __FILE__,__func__,
				__LINE__);
		return G_IPSEC_LA_FAILURE;
	}
		
	/* Reach to the '-' in the name */
	ptr = strchr(in->accl_name, '-');
	if (ptr == NULL) {
		VIRTIO_IPSEC_DEBUG("%s:%s:%d Cannot parse accelerator name\n",
		 	__FILE__, __func__, __LINE__);
		return G_IPSEC_LA_FAILURE;
	}
	sscanf(ptr+1, "%d", &index);
	VIRTIO_IPSEC_DEBUG("%s:%s:%d: Accelerator Index =%d\n", 
		__FILE__, __func__, __LINE__, index);
	
	dev = safe_ref_get_data(&v_ipsec_devices,index);
	if (dev == NULL) {
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Cannot access device at index %d\n", __FILE__, __func__,
			__LINE__, index);
		return G_IPSEC_LA_FAILURE;
	}

	switch(dev->mode)
	{
		case 0: /* Not used */
			dev->mode = mode;
			break;

		case G_IPSEC_LA_INSTANCE_EXCLUSIVE:
			/* Already in exclusive mode; return err */
			VIRTIO_IPSEC_DEBUG("%s:%s:%d: Accessed device %s is already in exclusive mode\n",__FILE__,
				__func__, __LINE__, in->accl_name);
			goto err_fail;
			break;

		case G_IPSEC_LA_INSTANCE_SHARED:
			if (mode != G_IPSEC_LA_INSTANCE_SHARED) {
				VIRTIO_IPSEC_DEBUG("%s:%s:%d: Requesting exclusive access on shared device %s\n",__FILE__,
				__func__, __LINE__, in->accl_name);
				goto err_fail;
			}
			break;
		default:
			goto err_fail;
	}

	/* Allocate the application block */
	app = kzalloc((sizeof(struct v_ipsec_app)+ (strlen(in->app_identity)+1) + in->cb_arg_len), GFP_KERNEL);
	if (app == NULL)
		return -ENOMEM;

	app_ref = kzalloc((sizeof(struct v_ipsec_app_hndl_ref)), GFP_KERNEL);
	if (app_ref == NULL)
		goto err_app_hndl_ref;
	init_rcu_head(&app_ref->rcu);

	dev->num_apps++;
	app->identity = (u8 *)app + sizeof(struct v_ipsec_app);
	app->cb_arg = (u8 *)(app->identity) + strlen(in->app_identity)+1; 

	init_rcu_head(&app->rcu);
	spin_lock_init(&app->lock);
	//INIT_LIST_HEAD(&app->list);

	/* Revisit and add this to a macro */
	index_ptr = (u32 *)&(app->dev_handle.handle[0]);
	*index_ptr = index;
	*(index_ptr+1) = safe_ref_get_magic_num(&v_ipsec_devices,index);

	strcpy(app->identity, in->app_identity);
	app->mode = mode;
	app->num_groups = 0;
	app->cb_arg_len = in->cb_arg_len;
	memcpy(app->cb_arg, in->cb_arg, in->cb_arg_len);
	app->cb_fn = in->cb_fn;
	app->has_groups = true; /* till the first SA command is sent out without group creation */
	INIT_LIST_HEAD(&(app->u.no_groups_wrapper.sas));
	
	index = safe_ref_array_add(&v_ipsec_apps,app);
	if (index == VIRTIO_IPSEC_MAX_APPS) {
		
		VIRTIO_IPSEC_DEBUG("%s:%s:%d:Exceeding Max applications\n", __FILE__, __func__, __LINE__);
		goto err_safe_ref_app;		
	}

	/* Put app in safe reference array */
	index_ref = safe_ref_array_add(&v_ipsec_app_hndl_refs, app_ref);
	if (index_ref == VIRTIO_IPSEC_MAX_APPS) {
		VIRTIO_IPSEC_DEBUG("%s:%s:%d:Exceeding Max applications\n", __FILE__, __func__, __LINE__);
		goto err_safe_ref_app_ref;
	}

	/* Put the app index and magic number in app ref */
	index_ptr = (u32 *)&(app_ref->hndl.handle[0]);
	*index_ptr = index;
	magic = *(index_ptr+1) = safe_ref_get_magic_num(&v_ipsec_apps, index);
	INIT_LIST_HEAD(&app_ref->link);

	/* Put the app handle index and reference number in app structure */
	index_ptr = (u32 *)&(app->list_hndl.handle[0]);
	*index_ptr = index_ref;
	*(index_ptr +1) = safe_ref_get_magic_num(&v_ipsec_app_hndl_refs, index_ref);

	/* Add application to the device list */
	add_app_to_dev(dev, app_ref);

	index_ptr = (u32 *)&(out->handle->handle[0]);
	*index_ptr = index;
	*(index_ptr + 1) = magic;
	index_ptr = (u32 *)&(out->handle->group_handle[0]);
	*index_ptr = G_IPSEC_LA_GROUP_INVALID;

	VIRTIO_IPSEC_ERROR("dev %p: app %p opened\n", dev, app);
	return VIRTIO_IPSEC_SUCCESS;

err_fail:
	VIRTIO_IPSEC_EXIT("failed\n");
	return -EPERM;

err_safe_ref_app_ref:
	safe_ref_array_node_delete(&v_ipsec_app_hndl_refs, index, virt_ipsec_free);
err_safe_ref_app:
	kfree(app_ref);
err_app_hndl_ref:
	kfree(app);
	VIRTIO_IPSEC_EXIT("failed\n");
	return -ENOMEM;
}
EXPORT_SYMBOL(virt_ipsec_la_open);
	
/* API Functions */
int32_t virt_ipsec_group_add(
	struct g_ipsec_la_handle *handle,
	struct g_ipsec_la_group_create_inargs *in,
	enum g_ipsec_la_control_flags flags,
	struct g_ipsec_la_group_create_outargs *out,
	struct g_ipsec_la_resp_args *resp, 
	u8 *msg,
	int32_t len)
{
	struct v_ipsec_app *app;
	struct v_ipsec_device *dev;
	struct v_ipsec_app_grp *group;
	struct v_ipsec_app_grp_hndl_ref *g_ref;

	struct virt_ipsec_cmd_ctx *cmd_ctx;
	uint32_t index, index_ref;
	uint32_t *ptr;
	//int32_t result;
	u8 *result_ptr;
	int32_t ret;

	VIRTIO_IPSEC_ENTRY("\n");
	app = VIRT_IPSEC_MGR_GET_APP(handle->handle);
	if (app == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d Invalid app handle: %d:%d\n", 
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle));
		return G_IPSEC_LA_FAILURE;
	}

	if (app->has_groups == false)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Application working in non-group mode: Fail:%d:%d\n",
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle));
		return G_IPSEC_LA_FAILURE;
	}

	dev = VIRT_IPSEC_MGR_GET_DEVICE(app->dev_handle.handle);
	if (dev == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d Unable to get device from handle: %d:%d\n", 
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle));
		return G_IPSEC_LA_FAILURE;
	}

	/* Allocate for the group */	
	group = kzalloc((sizeof(struct v_ipsec_app_grp)+ 
		(strlen(in->group_identity)+1)), GFP_KERNEL);
	if (group == NULL)
		return -ENOMEM;

	/* allocate for the group reference */
	g_ref = kzalloc(sizeof(struct v_ipsec_app_grp_hndl_ref), GFP_KERNEL);

	if (g_ref == NULL)
		goto err_g_handle_info;

	init_rcu_head(&(g_ref->rcu));

	/* allocate for the context */
	cmd_ctx = kzalloc(sizeof(struct virt_ipsec_cmd_ctx) + 
		sizeof(resp->cb_arg_len), GFP_KERNEL);
	if (cmd_ctx == NULL)
		goto err_ctx;

	/* If the first group created within the application manipulate the variables */
	if (app->num_groups == 0) {
		/* First time groups are created */
		//INIT_LIST_HEAD(&app->u.groups_wrapper.groups_in_creation);
		INIT_LIST_HEAD(&app->u.groups_wrapper.groups);
		app->num_groups++;
	}

	group->identity = (u8 *)(group) + sizeof(struct v_ipsec_app_grp);
	group->b_half_open = true;

	/* Initialize g_handle */
	init_rcu_head(&group->rcu);
	spin_lock_init(&group->lock);
	strcpy(group->identity, in->group_identity);

	/* Lists */
	INIT_LIST_HEAD(&(group->cmd_context));
	INIT_LIST_HEAD(&(group->sas));

	/* Assign APP Handle: structure copy */
	memcpy(group->app_hdl.handle,handle->handle,G_IPSEC_LA_INTERNAL_HANDLE_SIZE);

	if (virt_ipsec_msg_group_add(&len,&msg, &result_ptr)!= VIRTIO_IPSEC_SUCCESS)	
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Message creation failure (handle=%d:%d\n", 
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle));
		goto err_msg;
	}

	/* Allocate an index in safe  reference array */
	index = safe_ref_array_add(&v_ipsec_grps,(void *)group);
	if (index == VIRTIO_IPSEC_MAX_GROUPS) {
		VIRTIO_IPSEC_DEBUG("%s:%s:%d:Exceeding Max applications\n", __FILE__, __func__, __LINE__);
		goto err_safe_ref_grp;		
	}

	index_ref = safe_ref_array_add(&v_ipsec_grp_hndl_refs, (void *)g_ref);
	if (index_ref == VIRTIO_IPSEC_MAX_GROUPS) {
		VIRTIO_IPSEC_DEBUG("%s:%s:%d:Exceeding Max applications\n", __FILE__, __func__, __LINE__);
		goto err_safe_ref_grp_hndl_ref;		
	}

	/* Prepare g_ref*/
	ptr = (uint32_t *)(g_ref->hndl.handle);
	*ptr = index;
	*(ptr+1) = safe_ref_get_magic_num(&v_ipsec_grps, index);


	ptr = (u32 *)&(group->list_hdl.handle[0]);
	*ptr = index_ref;
	 *(ptr+1) = safe_ref_get_magic_num(&v_ipsec_grp_hndl_refs, index_ref);
		
	/* Add it to app list : Do it after it is success in backend 
	add_group_to_app(app,g_ref);
	*/

	
	/* Update command context block */
	cmd_ctx->cb_arg = (u8 *)(cmd_ctx) + sizeof(struct virt_ipsec_cmd_ctx);
	cmd_ctx->cmd_buffer = msg;
	cmd_ctx->cmd_buffer_len = len;
	memcpy(cmd_ctx->hndl, g_ref->hndl.handle, G_IPSEC_LA_INTERNAL_HANDLE_SIZE);
	cmd_ctx->out_args = (void *)out;
	cmd_ctx->result_ptr = result_ptr;
	
	add_cmd_ctx_to_group(group, cmd_ctx);
	
	if (flags & G_IPSEC_LA_CTRL_FLAG_ASYNC)
	{
		cmd_ctx->b_wait = false;
		cmd_ctx->cb_fn = resp->cb_fn;
		memcpy(cmd_ctx->cb_arg, resp->cb_arg, resp->cb_arg_len);
		cmd_ctx->cb_arg_len = resp->cb_arg_len;
		
	}
	else
	{
		cmd_ctx->b_wait = true;
		/* Initialize wait queue */
		init_waitqueue_head(&cmd_ctx->waitq);
	}

	ret = virt_ipsec_send_cmd(dev->info, cmd_ctx);

	if (flags & G_IPSEC_LA_CTRL_FLAG_ASYNC)
		return ret;

	/* Synchronous mode */
	ret = handle_response(cmd_ctx);
	//memcpy(out->handle, cmd_ctx->hndl.handle, G_IPSEC_LA_GROUP_HANDLE_SIZE);
	
	group_add_cleanup(cmd_ctx, app ,group,g_ref);
	return ret;;

err_safe_ref_grp_hndl_ref:
	safe_ref_array_node_delete(&v_ipsec_grps,index, virt_ipsec_free);
	
err_safe_ref_grp:
	virt_ipsec_msg_release(msg);
err_msg:
	kfree(cmd_ctx);
err_ctx:
	kfree(g_ref);

err_g_handle_info:
	kfree(group);
	return -ENOMEM;
}

int32_t virt_ipsec_sa_add(
	struct g_ipsec_la_handle *handle,
	const struct g_ipsec_la_sa_add_inargs *in,
	enum g_ipsec_la_control_flags flags,
	struct g_ipsec_la_sa_add_outargs *out,
	struct g_ipsec_la_resp_args *resp)
{
	/* Get the handles */
	struct v_ipsec_device *dev;
	struct v_ipsec_app *app;
	struct v_ipsec_app_grp *group = NULL;
	struct v_ipsec_sa *sa;
	struct v_ipsec_sa_hndl_ref *sa_ref;
	struct virt_ipsec_cmd_ctx *cmd_ctx;
	u8 *msg;
	u32 len;

	//u32 *app_index = (u32 *)&(handle->handle[0]);
	u32 *group_index = (u32 *)&(handle->group_handle[0]);
	u32 index, index_ref;
	u32 *ptr;
	int32_t ret;
	u8 *result_ptr;

	VIRTIO_IPSEC_ENTRY("\n");
	/* Validate input arguments */
	if ((in->dir != G_IPSEC_LA_SA_INBOUND) && (in->dir != G_IPSEC_LA_SA_OUTBOUND))
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Input arguments incorrect handle:%d:%d\n",
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle));
		return VIRTIO_IPSEC_FAILURE;
	}

	app = VIRT_IPSEC_MGR_GET_APP(handle->handle);
	if (app == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Invalid handle: [A]:%d:%d G:%d:%d\n", 
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle), 
			EXPAND_HANDLE(handle->group_handle));
		return VIRTIO_IPSEC_FAILURE;
	}

	if (*group_index != G_IPSEC_LA_GROUP_INVALID) { /* valid group index */
		group = VIRT_IPSEC_MGR_GET_GROUP(handle->group_handle);
		if (group == NULL)	{
			VIRTIO_IPSEC_DEBUG("%s:%s:%d: Invalid: handle A:%d:%d [G]:%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle),
				EXPAND_HANDLE(handle->group_handle));
			return VIRTIO_IPSEC_FAILURE;
		}
	}

	dev = safe_ref_get_data(&v_ipsec_devices, GET_INDEX_FROM_HANDLE(app->dev_handle.handle));
	if (dev == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Cannot retrieve device A:%d:%d G:%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle),
				EXPAND_HANDLE(handle->group_handle));
		return VIRTIO_IPSEC_FAILURE;
	}	
	VIRTIO_IPSEC_DBG("dev %p app %p group 0x%x\n", dev, app, *group_index);

	/* Need to check feature bits for compatibility 
	if ((in->sa_params->crypto_params.auth_algo == G_IPSEC_LA_AUTH_ALGO_NONE) &&
		(in->sa_params->crypto_params.cipher_algo == G_IPSEC_LA_CIPHER_ALGO_NULL))
	{
		return error;
	}
	*/

	/* allocate for an SA */
	sa = kzalloc(sizeof(struct v_ipsec_sa), GFP_KERNEL);
	if (sa == NULL)
		goto err_sa_alloc;


	/* allocate SA reference */
	sa_ref = kzalloc(sizeof(struct v_ipsec_sa_hndl_ref), GFP_KERNEL);
	if (sa_ref == NULL)
		goto err_sa_ref_alloc;

	init_rcu_head(&sa_ref->rcu);
	INIT_LIST_HEAD(&sa_ref->link);

	/* allocate for the context */
	cmd_ctx = kzalloc(sizeof(struct virt_ipsec_cmd_ctx) + 
		sizeof(resp->cb_arg_len), GFP_KERNEL);
	if (cmd_ctx == NULL)
		goto err_ctx;

	INIT_LIST_HEAD(&(sa->cmd_ctxt));
	init_rcu_head(&sa->rcu);
	spin_lock_init(&sa->lock);

	/* Assign APP Handle */
	if (group) {  /* part of group */
		sa->in_group = true;
		memcpy(sa->grp_hndl.handle, handle->group_handle, G_IPSEC_LA_INTERNAL_HANDLE_SIZE);
	} else {
		sa->in_group = false;
		memcpy(sa->app_hndl.handle, handle->handle, G_IPSEC_LA_INTERNAL_HANDLE_SIZE);
	}
	if(virt_ipsec_msg_sa_add(
		sa->in_group ? group->hw_handle : NULL,
		in, &len, &msg, &result_ptr)!= VIRTIO_IPSEC_SUCCESS)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Message Framing failed:handle:%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle));
		goto err_msg_fail;
	}

	/* Allocate an index in safe  reference array */
	index = safe_ref_array_add(&v_ipsec_sas,(void *)sa);
	if (index == VIRTIO_IPSEC_MAX_SAS) {
		VIRTIO_IPSEC_DEBUG("%s:%s:%d:Exceeding Max SAs\n", __FILE__, __func__, __LINE__);
		goto err_safe_ref_sa;		
	}

	index_ref = safe_ref_array_add(&v_ipsec_sa_hndl_refs, (void *)sa_ref);
	if (index_ref == VIRTIO_IPSEC_MAX_SAS) {
			VIRTIO_IPSEC_DEBUG("%s:%s:%d:Exceeding Max SAs\n", __FILE__, __func__, __LINE__);
			goto err_safe_ref_sa_ref;		
	}

	/* Update sa_ref */
	ptr = (uint32_t *)(sa_ref->hndl.handle);
	*ptr = index;
	*(ptr+1) = safe_ref_get_magic_num(&v_ipsec_sas, index);

	/* Update the sa with the list hndl */
	ptr = (u32 *)&(sa->list_hdl.handle[0]);
	*ptr = index_ref;
	*(ptr +1) = safe_ref_get_magic_num(&v_ipsec_sa_hndl_refs, index_ref);

	// TODO: do this after getting result from hw
	/* add the sa to app sa list or group sa list
	if (sa->in_group == false)
		add_sa_to_app(app,sa_ref);
	else
		add_sa_to_group(group,sa_ref); */

	/* Update command context block */
	cmd_ctx->cb_arg = (u8 *)(cmd_ctx) + sizeof(struct virt_ipsec_cmd_ctx);
	cmd_ctx->cmd_buffer = msg;
	cmd_ctx->cmd_buffer_len = len;
	memcpy((u8 *)cmd_ctx->hndl, sa_ref->hndl.handle, G_IPSEC_LA_INTERNAL_HANDLE_SIZE);
	cmd_ctx->out_args = (void *)out;
	cmd_ctx->result_ptr = result_ptr;

	add_cmd_ctx_to_sa(sa, cmd_ctx);
	num_pending_sa_ops_inc(app, group, sa);

	VIRTIO_IPSEC_DBG("cmd_ctx %p saref %d:%d sarefref %d:%d\n", cmd_ctx,
		EXPAND_HANDLE(sa_ref->hndl.handle), EXPAND_HANDLE(sa->list_hdl.handle));
	if (flags & G_IPSEC_LA_CTRL_FLAG_ASYNC) {
		cmd_ctx->b_wait = false;
		cmd_ctx->cb_fn = resp->cb_fn;
		memcpy(cmd_ctx->cb_arg, resp->cb_arg, resp->cb_arg_len);
		cmd_ctx->cb_arg_len = resp->cb_arg_len;
	} else {
		cmd_ctx->b_wait = true;
		/* Initialize wait queue */
		init_waitqueue_head(&cmd_ctx->waitq);
	}

	ret = virt_ipsec_send_cmd(dev->info, cmd_ctx);
	if (ret || (flags & G_IPSEC_LA_CTRL_FLAG_ASYNC))
		return ret;

	/* Synchronous mode */
	ret = handle_response(cmd_ctx);
	//memcpy(out->handle, sa_ref->hndl.handle, G_IPSEC_LA_SA_HANDLE_SIZE);
	
	return ret;

err_safe_ref_sa_ref:
	safe_ref_array_node_delete(&v_ipsec_sas,index, virt_ipsec_free);

err_safe_ref_sa:
	virt_ipsec_msg_release(msg);
	
err_msg_fail:
	kfree(cmd_ctx);
		
err_ctx:
	kfree(sa_ref);
		
err_sa_ref_alloc:
	kfree(sa);

err_sa_alloc:
	return -ENOMEM;

	
}
EXPORT_SYMBOL(virt_ipsec_sa_add);

int32_t virt_ipsec_get_api_version(char *version)
{
	strcpy(version, "0.1");
	return 0;
}
EXPORT_SYMBOL(virt_ipsec_get_api_version);

int32_t virt_ipsec_group_delete(
	struct g_ipsec_la_handle *handle,
	enum g_ipsec_la_control_flags flags,
	struct g_ipsec_la_group_delete_outargs *out,
	struct g_ipsec_la_resp_args *resp
	)
{
	struct v_ipsec_app *app;
	struct v_ipsec_app_grp *group;
	struct v_ipsec_app_grp_hndl_ref *g_ref;
	struct v_ipsec_device *dev;
	u32 *app_index = (u32 *)&(handle->handle[0]);
	u32 *group_index = (u32 *)&(handle->group_handle[0]);
	struct virt_ipsec_cmd_ctx *cmd_ctx;
	u8 *msg;
	u32 len;
	int32_t ret;
	u8 *result_ptr;

	VIRTIO_IPSEC_ENTRY("\n");
	app = safe_ref_get_data(&v_ipsec_apps,*app_index);
	if (app == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Invalid handle: [A]:%d:%d G:%d:%d\n", 
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle), 
			EXPAND_HANDLE(handle->group_handle));
		return VIRTIO_IPSEC_FAILURE;
	}

	if (*group_index != G_IPSEC_LA_GROUP_INVALID) { /* valid group index */
		group = safe_ref_get_data(&v_ipsec_grps, *group_index);
		if (group == NULL)	{
			VIRTIO_IPSEC_DEBUG("%s:%s:%d: Invalid: handle A:%d:%d [G]:%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle),
				EXPAND_HANDLE(handle->group_handle));
			return VIRTIO_IPSEC_FAILURE;
		}
		if (!list_empty(&group->sas)) {
			VIRTIO_IPSEC_DEBUG("%s:%s:%d:Group has active SAs A:%d:%d (G):%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle),
				EXPAND_HANDLE(handle->group_handle));
			return VIRTIO_IPSEC_FAILURE;
		}
		g_ref = safe_ref_get_data(&v_ipsec_grp_hndl_refs, 
			GET_INDEX_FROM_HANDLE(group->list_hdl.handle));
		if (g_ref == NULL) {
			VIRTIO_IPSEC_DEBUG("%s:%s:%d: Invalid: handle (g_ref) A:%d:%d [G]:%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle),
				EXPAND_HANDLE(handle->group_handle));
			return VIRTIO_IPSEC_FAILURE;
		}
	}
	else {
		VIRTIO_IPSEC_DEBUG("%s:%s:%d:App has no group A:%d:%d (G):%d:%d\n",
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle),
			EXPAND_HANDLE(handle->group_handle));
		return VIRTIO_IPSEC_FAILURE;
	}

	/* Need to handle this differently device dies on us */
	dev = safe_ref_get_data(&v_ipsec_devices, GET_INDEX_FROM_HANDLE(app->dev_handle.handle));
	if (dev == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Cannot retrieve device A:%d:%d G:%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle),
				EXPAND_HANDLE(handle->group_handle));
		return VIRTIO_IPSEC_FAILURE;
	}

	/* allocate for the context */
	cmd_ctx = kzalloc(sizeof(struct virt_ipsec_cmd_ctx) + 
		sizeof(resp->cb_arg_len), GFP_KERNEL);
	if (cmd_ctx == NULL)
		goto err_ctx;

	if (virt_ipsec_msg_group_delete(group->hw_handle, &len,&msg,
		&result_ptr)!= VIRTIO_IPSEC_SUCCESS)	
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Message creation failure (handle=%d:%d\n", 
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle));
		goto err_msg;
	}

	
	/* Update command context block */
	cmd_ctx->cb_arg = (u8 *)(cmd_ctx) + sizeof(struct virt_ipsec_cmd_ctx);
	cmd_ctx->cmd_buffer = msg;
	cmd_ctx->cmd_buffer_len = len;
	memcpy(cmd_ctx->hndl, handle->group_handle, G_IPSEC_LA_INTERNAL_HANDLE_SIZE);
	cmd_ctx->result_ptr = result_ptr;
	
	add_cmd_ctx_to_group(group, cmd_ctx);
		
	if (flags & G_IPSEC_LA_CTRL_FLAG_ASYNC)
	{
		cmd_ctx->b_wait = false;
		cmd_ctx->cb_fn = resp->cb_fn;
		memcpy(cmd_ctx->cb_arg, resp->cb_arg, resp->cb_arg_len);
		cmd_ctx->cb_arg_len = resp->cb_arg_len;
	}
	else
	{
		cmd_ctx->b_wait = true;
		/* Initialize wait queue */
		init_waitqueue_head(&cmd_ctx->waitq);
	}
	
	ret = virt_ipsec_send_cmd(dev->info, cmd_ctx);
	
	if (flags & G_IPSEC_LA_CTRL_FLAG_ASYNC)
		return ret;
	
	/* Synchronous mode */
	ret = handle_response(cmd_ctx);
	/* Need to handle failure case here: */

	group_delete_cleanup(cmd_ctx,
		app, group, g_ref);
	
	return ret;

err_msg:
	kfree(cmd_ctx);

err_ctx:
	return -ENOMEM;

}

/*
 * Description:
 * Nothing to be sent to backend:
 *  1. Check for pending groups, if groups have ben created 
 *  2. Check for pending SAs if no groups have been created
 *  3. Remove app ref from device list
 *  4. Delete Safe reference array app ref
 *  5. Delete Safe reference array app
  */
int32_t virt_ipsec_la_close(
	struct g_ipsec_la_handle *handle)
{
	struct v_ipsec_app *app;
	struct v_ipsec_app_hndl_ref *app_ref;
	struct v_ipsec_device *dev;
	u32 index, index_ref;

	VIRTIO_IPSEC_ENTRY("\n");
	/* Get the App */
	app = VIRT_IPSEC_MGR_GET_APP(handle->handle);
	if (app == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d Invalid app handle: %d:%d\n", 
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle));
		return G_IPSEC_LA_FAILURE;
	}

	app_ref = VIRT_IPSEC_MGR_GET_APP_REF(app->list_hndl.handle);
	if (app_ref == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d Invalid app handle: %d:%d\n", 
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle));
		return G_IPSEC_LA_FAILURE;
	}
	/* Get the device */
	dev = VIRT_IPSEC_MGR_GET_DEVICE(app->dev_handle.handle);
	if (dev == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d Unable to get device from handle: %d:%d\n", 
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle));

		/* Device broken logic */
	}
	if (app->has_groups) {
		/* Check if there are groups to be cleaned up */
		if (!list_empty(&app->u.groups_wrapper.groups))
		{
			VIRTIO_IPSEC_DEBUG("%s:%s:%d Has active Groups: Close failed %d:%d\n", 
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle));
			return G_IPSEC_LA_FAILURE;
		}
		else {
			if (!(list_empty(&app->u.no_groups_wrapper.sas)))
			{
				VIRTIO_IPSEC_DEBUG("%s:%s:%d Has active SAs: Close failed %d:%d\n", 
					__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle));
				return G_IPSEC_LA_FAILURE;
			}
			if (!(list_empty(&app->u.no_groups_wrapper.cmd_context)))
			{
				VIRTIO_IPSEC_DEBUG("%s:%s:%d Has active SAs: Close failed %d:%d\n", 
					__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle));
				return G_IPSEC_LA_FAILURE;
			}
		}
	}
	/* Remove app reference from device list */
	if (dev){
		remove_app_from_dev(dev,app_ref);
		}

	index = GET_INDEX_FROM_HANDLE(app_ref->hndl.handle);
	index_ref = GET_INDEX_FROM_HANDLE(app->list_hndl.handle);
	
	/* Delete safe reference array app */
	safe_ref_array_node_delete(&v_ipsec_apps,index,virt_ipsec_free);
	/* Delete safe reference array app_ref */
	safe_ref_array_node_delete(&v_ipsec_app_hndl_refs, index_ref, virt_ipsec_free);
	
	return G_IPSEC_LA_SUCCESS;
}

/*
 * Description: Frame a message to read the underlying capabilities
 * Handle the response sync or async
 */
int32_t virt_ipsec_capabilities_get(
	struct g_ipsec_la_handle *handle,
	enum g_ipsec_la_control_flags flags, 
	struct g_ipsec_la_cap_get_outargs *out, 
	struct g_ipsec_la_resp_args *resp)
{
	u8 *msg;
	u32 len;
	struct v_ipsec_app *app;
	struct v_ipsec_app_grp *group;
	struct v_ipsec_app_grp_hndl_ref *g_ref;
	struct v_ipsec_device *dev;
	struct virt_ipsec_cmd_ctx *cmd_ctx;
	u32 *group_index = (u32 *)&(handle->group_handle);
	u8 *result_ptr;
	int32_t ret;

	VIRTIO_IPSEC_ENTRY("\n");
	/* Get the app handle */
	app = VIRT_IPSEC_MGR_GET_APP(handle->handle);
	if (app == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d Invalid app handle: %d:%d\n", 
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle));
		return G_IPSEC_LA_FAILURE;
	}

	if (*group_index != G_IPSEC_LA_GROUP_INVALID) { /* valid group index */
		group = safe_ref_get_data(&v_ipsec_grps, *group_index);
		if (group == NULL)	{
			VIRTIO_IPSEC_DEBUG("%s:%s:%d: Invalid: handle A:%d:%d [G]:%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle),
				EXPAND_HANDLE(handle->group_handle));
			return VIRTIO_IPSEC_FAILURE;
		}
		if (!list_empty(&group->sas)) {
			VIRTIO_IPSEC_DEBUG("%s:%s:%d:Group has active SAs A:%d:%d (G):%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle),
				EXPAND_HANDLE(handle->group_handle));
			return VIRTIO_IPSEC_FAILURE;
		}
		g_ref = safe_ref_get_data(&v_ipsec_grp_hndl_refs, 
			GET_INDEX_FROM_HANDLE(group->list_hdl.handle));
			if (g_ref == NULL) {
			VIRTIO_IPSEC_DEBUG("%s:%s:%d: Invalid: handle (g_ref) A:%d:%d [G]:%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle),
				EXPAND_HANDLE(handle->group_handle));
			return VIRTIO_IPSEC_FAILURE;
		}
	}else  
		group = NULL;
	

	/* Get the device handle */
	dev = VIRT_IPSEC_MGR_GET_DEVICE(app->dev_handle.handle);
	if (dev == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d Unable to get device from handle: %d:%d\n", 
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle));
		return G_IPSEC_LA_FAILURE;
	}

	/* allocate for the context */
	cmd_ctx = kzalloc(sizeof(struct virt_ipsec_cmd_ctx) + 
		sizeof(resp->cb_arg_len), GFP_KERNEL);
	if (cmd_ctx == NULL)
		goto err_ctx;

	/* Frame the message */
	if (virt_ipsec_msg_get_capabilities(&len,&msg, &result_ptr)!= VIRTIO_IPSEC_SUCCESS)	
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Message creation failure handle=%d:%d\n", 
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle));
		goto err_msg;
	}

	
	/* Update command context block */
	cmd_ctx->cb_arg = (u8 *)(cmd_ctx) + sizeof(struct virt_ipsec_cmd_ctx);
	cmd_ctx->cmd_buffer = msg;
	cmd_ctx->cmd_buffer_len = len;
	memcpy(cmd_ctx->hndl, handle->handle, G_IPSEC_LA_INTERNAL_HANDLE_SIZE);
	
	cmd_ctx->result_ptr = result_ptr;

	if (group != NULL) {
		cmd_ctx->b_group = true;
		add_cmd_ctx_to_app(app, cmd_ctx);
	}
	else {
		cmd_ctx->b_group = false;
		add_cmd_ctx_to_group(group, cmd_ctx);
	}		
	if (flags & G_IPSEC_LA_CTRL_FLAG_ASYNC)
	{
		cmd_ctx->b_wait = false;
		cmd_ctx->cb_fn = resp->cb_fn;
		memcpy(cmd_ctx->cb_arg, resp->cb_arg, resp->cb_arg_len);
		cmd_ctx->cb_arg_len = resp->cb_arg_len;
	}
	else
	{
		cmd_ctx->b_wait = true;
		/* Initialize wait queue */
		init_waitqueue_head(&cmd_ctx->waitq);
	}
		
	ret = virt_ipsec_send_cmd(dev->info, cmd_ctx);
		
	if (flags & G_IPSEC_LA_CTRL_FLAG_ASYNC)
		return ret;
		
	/* Synchronous mode */
	handle_response(cmd_ctx);

	/* Need to handle failure case here: */
	capabilities_get_cleanup(cmd_ctx,app, group);
		
	return G_IPSEC_LA_SUCCESS;
	
err_msg:
	kfree(cmd_ctx);
	
err_ctx:
	return -ENOMEM;
	
}



int32_t virt_ipsec_notification_hooks_register(
	struct g_ipsec_la_handle *handle, /* Accelerator Handle */
	const struct g_ipsec_la_notification_hooks *in)
{
	struct v_ipsec_app *app;
	struct v_ipsec_app_grp *group;
	u32 *group_index = (u32 *)&(handle->group_handle[0]);
	struct virt_ipsec_notify_cb_info *hooks_holder;
	struct g_ipsec_la_notification_hooks *hooks;

	VIRTIO_IPSEC_ENTRY("\n");
	/* Get the app instance */
	app = VIRT_IPSEC_MGR_GET_APP(handle->handle);
	if (app == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d Invalid app handle: %d:%d\n", 
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle));
		return G_IPSEC_LA_FAILURE;
	}
	
	if (*group_index != G_IPSEC_LA_GROUP_INVALID) { /* valid group index */
		group = safe_ref_get_data(&v_ipsec_grps, *group_index);
		if (group == NULL)	{
			VIRTIO_IPSEC_DEBUG("%s:%s:%d: Invalid: handle A:%d:%d [G]:%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle),
				EXPAND_HANDLE(handle->group_handle));
			return VIRTIO_IPSEC_FAILURE;
		}
		else {
			group = NULL;
		}
	}
	hooks_holder = kzalloc((sizeof(struct virt_ipsec_notify_cb_info))
		+ in->seq_num_overflow_cbarg_len
		+ in->seq_num_periodic_cbarg_len
		+ in->soft_lifetimeout_cbarg_len,
		GFP_KERNEL);
	
	if (!hooks_holder)
		return -ENOMEM;

	hooks = &(hooks_holder->hooks);

	hooks->seq_num_overflow_cbarg = (u8 *)hooks +
		sizeof(struct virt_ipsec_notify_cb_info);
	hooks->seq_num_periodic_cbarg = (u8 *)(hooks->seq_num_overflow_cbarg)
		+ in->seq_num_overflow_cbarg_len;
	hooks->soft_lifetimeout_cbarg = (u8 *)(hooks->seq_num_periodic_cbarg)
		+ in->seq_num_periodic_cbarg_len;

	/* assign */
	if (hooks->seq_num_overflow_fn) {
		hooks->seq_num_overflow_fn = in->seq_num_overflow_fn;
		if (in->seq_num_overflow_cbarg_len != 0)
			memcpy(hooks->seq_num_overflow_cbarg, in->seq_num_overflow_cbarg, 
				in->seq_num_overflow_cbarg_len);
		hooks->seq_num_overflow_cbarg_len = in->seq_num_overflow_cbarg_len;
		}

	if (hooks->seq_num_periodic_update_fn) {
		hooks->seq_num_periodic_update_fn= in->seq_num_periodic_update_fn;
		if (in->seq_num_periodic_cbarg_len!= 0)
			memcpy(hooks->seq_num_periodic_cbarg, in->seq_num_periodic_cbarg, 
				in->seq_num_periodic_cbarg_len);
		hooks->seq_num_periodic_cbarg_len= in->seq_num_periodic_cbarg_len;
		}

	if (hooks->soft_lifetimeout_expirty_fn) {
		hooks->soft_lifetimeout_expirty_fn= in->soft_lifetimeout_expirty_fn;
		if (in->soft_lifetimeout_cbarg_len!= 0)
			memcpy(hooks->soft_lifetimeout_cbarg, in->soft_lifetimeout_cbarg, 
				in->soft_lifetimeout_cbarg_len);
		hooks->soft_lifetimeout_cbarg_len= in->soft_lifetimeout_cbarg_len;
		}

	/* Adds the hooks to either the app or the base */
	if (group != NULL)
		add_notification_hooks_to_group(group, hooks_holder);
	else
		add_notification_hooks_to_app(app, hooks_holder);

	return VIRTIO_IPSEC_SUCCESS;
}

int32_t virt_ipsec_notifications_hook_deregister( 
	struct g_ipsec_la_handle *handle  /* Accelerator Handle */ )
{
	struct v_ipsec_app *app;
	struct v_ipsec_app_grp *group;
	u32 *group_index = (u32 *)&(handle->group_handle[0]);
	//struct virt_ipsec_notify_cb_info *hooks;

	VIRTIO_IPSEC_ENTRY("\n");
	/* Get the app instance */
	app = VIRT_IPSEC_MGR_GET_APP(handle->handle);
	if (app == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d Invalid app handle: %d:%d\n", 
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle));
		return G_IPSEC_LA_FAILURE;
	}
	
	if (*group_index != G_IPSEC_LA_GROUP_INVALID) { /* valid group index */
		group = safe_ref_get_data(&v_ipsec_grps, *group_index);
		if (group == NULL)	{
			VIRTIO_IPSEC_DEBUG("%s:%s:%d: Invalid: handle A:%d:%d [G]:%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle),
				EXPAND_HANDLE(handle->group_handle));
			return VIRTIO_IPSEC_FAILURE;
		}
		else {
			group = NULL;
		}
	}
	if (group == NULL)
		remove_notification_hooks_from_app(app);
	else
		remove_notification_hooks_from_group(group);

	return VIRTIO_IPSEC_SUCCESS;
}



int32_t virt_ipsec_sa_mod(
	 struct g_ipsec_la_handle *handle, /* Accelerator Handle */
	 const struct g_ipsec_la_sa_mod_inargs *in, /* Input Arguments */
     enum g_ipsec_la_control_flags flags, /* Control flags: sync/async, response required or not */
     struct g_ipsec_la_sa_mod_outargs *out, /* Output Arguments */
     struct g_ipsec_la_resp_args *resp)
{
	struct v_ipsec_app *app;
	struct v_ipsec_app_grp *group = NULL;
	struct v_ipsec_device *dev;
	struct v_ipsec_sa *sa;
	struct v_ipsec_sa_hndl_ref *sa_ref;
	u32 *app_index = (u32 *)&(handle->handle[0]);
	u32 *group_index = (u32 *)(&handle->group_handle[0]);
	struct virt_ipsec_cmd_ctx *cmd_ctx;
	u32 len;
	u8 *msg;
	u32 *g_hw_handle;
	int32_t ret;
	u8 *result_ptr;

	VIRTIO_IPSEC_ENTRY("\n");
	app = safe_ref_get_data(&v_ipsec_apps,*app_index);
	if (app == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Invalid handle: [A]:%d:%d G:%d:%d\n", 
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle), 
			EXPAND_HANDLE(handle->group_handle));
		return VIRTIO_IPSEC_FAILURE;
	}
	
	if (*group_index != G_IPSEC_LA_GROUP_INVALID) { /* valid group index */
		group = safe_ref_get_data(&v_ipsec_grps, *group_index);
		if (group == NULL)	{
			VIRTIO_IPSEC_DEBUG("%s:%s:%d: Invalid: handle A:%d:%d [G]:%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle),
				EXPAND_HANDLE(handle->group_handle));
			return VIRTIO_IPSEC_FAILURE;
		}
	}

	//dev = safe_ref_get_data(&v_ipsec_devices, app->dev_handle.handle);
	dev = VIRT_IPSEC_MGR_GET_DEVICE(app->dev_handle.handle);
	if (dev == NULL){
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Cannot retrieve device A:%d:%d G:%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle),
				EXPAND_HANDLE(handle->group_handle));
		return VIRTIO_IPSEC_FAILURE;
	}	

	sa = VIRT_IPSEC_MGR_GET_SA(in->handle->ipsec_sa_handle);
	//sa = safe_ref_get_data(&v_ipsec_sas, in->handle->ipsec_sa_handle);
	if (sa == NULL) {
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Cannot retrieve SA handle=%d:%d\n",
			__FILE__, __func__, __LINE__, 
			EXPAND_HANDLE(in->handle->ipsec_sa_handle));
		return VIRTIO_IPSEC_FAILURE;
	}

	sa_ref = VIRT_IPSEC_MGR_GET_SA_REF(sa->list_hdl.handle);
	//sa_ref = safe_ref_get_data(&v_ipsec_sa_hndl_refs, sa->list_hdl.handle);
	if (sa_ref == NULL) {
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Cannot retrieve SA Ref handle=%d:%d\n",
			__FILE__, __func__, __LINE__, 
			EXPAND_HANDLE(in->handle->ipsec_sa_handle));
		return VIRTIO_IPSEC_FAILURE;
	}

	/* allocate for the context */
	cmd_ctx = kzalloc(sizeof(struct virt_ipsec_cmd_ctx) + 
		sizeof(resp->cb_arg_len), GFP_KERNEL);
	if (cmd_ctx == NULL)
		goto err_ctxt;

	g_hw_handle = NULL;
	if (sa->in_group == true) {
		if (group == NULL) {
			VIRTIO_IPSEC_ERROR("===expected non-null group here\n");
			goto err_ctxt;
		}
		g_hw_handle = group->hw_handle;
	}

	if (virt_ipsec_msg_sa_mod
		(g_hw_handle, sa->hw_sa_handle, in, &len,&msg,
		&result_ptr)!= VIRTIO_IPSEC_SUCCESS)	
		
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Message creation failure (handle=%d:%d\n", 
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle));
		goto err_msg;
	}

	/* Update command context block */
	cmd_ctx->cb_arg = (u8 *)(cmd_ctx) + sizeof(struct virt_ipsec_cmd_ctx);
	cmd_ctx->cmd_buffer = msg;
	cmd_ctx->cmd_buffer_len = len;
	memcpy(cmd_ctx->hndl, sa_ref->hndl.handle,G_IPSEC_LA_INTERNAL_HANDLE_SIZE);
	cmd_ctx->out_args = out;
	cmd_ctx->result_ptr = result_ptr;
	
	add_cmd_ctx_to_sa(sa, cmd_ctx);
	num_pending_sa_ops_inc(app, group, sa);
		
	if (flags & G_IPSEC_LA_CTRL_FLAG_ASYNC)
	{
		cmd_ctx->b_wait = false;
		cmd_ctx->cb_fn = resp->cb_fn;
		memcpy(cmd_ctx->cb_arg, resp->cb_arg, resp->cb_arg_len);
		cmd_ctx->cb_arg_len = resp->cb_arg_len;
	}
	else
	{
		cmd_ctx->b_wait = true;
		/* Initialize wait queue */
		init_waitqueue_head(&cmd_ctx->waitq);
	}
	
	ret = virt_ipsec_send_cmd(dev->info, cmd_ctx);
	
	if (flags & G_IPSEC_LA_CTRL_FLAG_ASYNC)
			return ret;
		
	/* Synchronous mode */
	ret = handle_response(cmd_ctx);

	/* Need to handle failure case here: */
	//sa_mod_cleanup(cmd_ctx, sa);
	sa_mod_cleanup(cmd_ctx, app, group, sa);
		
	return ret;
	
err_msg:
	kfree(cmd_ctx);
	
err_ctxt:
	return -ENOMEM;
	
}

int32_t virt_ipsec_sa_del(
	struct g_ipsec_la_handle *handle,
       const struct g_ipsec_la_sa_del_inargs *in,
       enum g_ipsec_la_control_flags flags,
       struct g_ipsec_la_sa_del_outargs *out,
       struct g_ipsec_la_resp_args *resp) 
{
	struct v_ipsec_app *app;
	struct v_ipsec_app_grp *group = NULL;
	struct v_ipsec_device *dev;
	struct v_ipsec_sa *sa;
	struct v_ipsec_sa_hndl_ref *sa_ref;
	u32 *app_index = (u32 *)&(handle->handle[0]);
	u32 *group_index = (u32 *)&(handle->group_handle[0]);
	struct virt_ipsec_cmd_ctx *cmd_ctx;
	u32 *g_hw_handle;
	u8 *msg, *result_ptr;
	int32_t ret;
	u32 len;
	
	VIRTIO_IPSEC_ENTRY("\n");
	app = safe_ref_get_data(&v_ipsec_apps,*app_index);
	if (app == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Invalid handle: [A]:%d:%d G:%d:%d\n", 
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle), 
			EXPAND_HANDLE(handle->group_handle));
		return VIRTIO_IPSEC_FAILURE;
	}
	
	if (*group_index != G_IPSEC_LA_GROUP_INVALID) { /* valid group index */
		group = safe_ref_get_data(&v_ipsec_grps, *group_index);
		if (group == NULL)	{
			VIRTIO_IPSEC_DEBUG("%s:%s:%d: Invalid: handle A:%d:%d [G]:%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle),
				EXPAND_HANDLE(handle->group_handle));
			return VIRTIO_IPSEC_FAILURE;
		}
	}

	dev = VIRT_IPSEC_MGR_GET_DEVICE(app->dev_handle.handle);
	if (dev == NULL){
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Cannot retrieve device A:%d:%d G:%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle),
				EXPAND_HANDLE(handle->group_handle));
		return VIRTIO_IPSEC_FAILURE;
	}	

	sa = VIRT_IPSEC_MGR_GET_SA(in->handle->ipsec_sa_handle);
	if (sa == NULL) {
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Cannot retrieve SA handle=%d:%d\n",
			__FILE__, __func__, __LINE__, 
			EXPAND_HANDLE(in->handle->ipsec_sa_handle));
		return VIRTIO_IPSEC_FAILURE;
	}

	
	sa_ref = VIRT_IPSEC_MGR_GET_SA_REF(sa->list_hdl.handle);
	if (sa_ref == NULL) {
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Cannot retrieve SA Ref handle=%d:%d\n",
			__FILE__, __func__, __LINE__, 
			EXPAND_HANDLE(in->handle->ipsec_sa_handle));
		return VIRTIO_IPSEC_FAILURE;
	}

	/* Check for pending command or data context blocks, if so return failure */
	if (!list_empty(&sa->cmd_ctxt) || (has_pending_data_blocks(sa) == true)) {
			VIRTIO_IPSEC_DEBUG("%s:%s:%d:SA has pending contexts A:%d:%d (SA):%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle),
				EXPAND_HANDLE(in->handle->ipsec_sa_handle));
			return VIRTIO_IPSEC_FAILURE;
		}

	/* allocate for the context */
	cmd_ctx = kzalloc(sizeof(struct virt_ipsec_cmd_ctx) + 
		sizeof(resp->cb_arg_len), GFP_KERNEL);
	if (cmd_ctx == NULL)
		goto err_context;

	g_hw_handle = NULL;
	if (sa->in_group == true) {
		if (group == NULL) {
			VIRTIO_IPSEC_ERROR("===expected non-null group here\n");
			goto err_context;
		}
		g_hw_handle = group->hw_handle;
	}
	
	if (virt_ipsec_msg_sa_del
		(g_hw_handle, sa->hw_sa_handle, in, &len,&msg,
		&result_ptr)!= VIRTIO_IPSEC_SUCCESS)	
		
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Message creation failure (handle=%d:%d\n", 
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle));
		goto err_msg;
	}

	/* Update command context block */
	cmd_ctx->cb_arg = (u8 *)(cmd_ctx) + sizeof(struct virt_ipsec_cmd_ctx);
	cmd_ctx->cmd_buffer = msg;
	cmd_ctx->cmd_buffer_len = len;
	memcpy(cmd_ctx->hndl, sa_ref->hndl.handle, G_IPSEC_LA_INTERNAL_HANDLE_SIZE);
	cmd_ctx->out_args = out;
	cmd_ctx->result_ptr = result_ptr;
	
	add_cmd_ctx_to_sa(sa, cmd_ctx);
	num_pending_sa_ops_inc(app, group, sa);
		
	if (flags & G_IPSEC_LA_CTRL_FLAG_ASYNC)
	{
		cmd_ctx->b_wait = false;
		cmd_ctx->cb_fn = resp->cb_fn;
		memcpy(cmd_ctx->cb_arg, resp->cb_arg, resp->cb_arg_len);
		cmd_ctx->cb_arg_len = resp->cb_arg_len;
	}
	else
	{
		cmd_ctx->b_wait = true;
		/* Initialize wait queue */
		init_waitqueue_head(&cmd_ctx->waitq);
	}
	
	ret = virt_ipsec_send_cmd(dev->info, cmd_ctx);
	
	if (flags & G_IPSEC_LA_CTRL_FLAG_ASYNC)
			return ret;
		
	/* Synchronous mode */
	ret = handle_response(cmd_ctx);

	/* Need to handle failure case here: */
	//sa_del_cleanup(cmd_ctx, sa);
	sa_del_cleanup(cmd_ctx, app, group, sa, sa_ref);
		
	return ret;
	
err_msg:
	kfree(cmd_ctx);
	
err_context:
	return -ENOMEM;
}
EXPORT_SYMBOL(virt_ipsec_sa_del);

#ifdef _NOT_USED_
int32_t virt_ipsec_sa_flush(
	struct g_ipsec_la_handle *handle,
	enum g_ipsec_la_control_flags flags,
	struct g_ipsec_la_sa_flush_outargs *out,
	struct g_ipsec_la_resp_args *resp)
{
	struct v_ipsec_app *app;
	struct v_ipsec_app_grp *group;
	struct v_ipsec_device *dev;
	struct v_ipsec_sa *sa;
	u32 *app_index = (u32 *)&(handle->handle[0]);
	u32 *group_index = (u32 *)&(handle->group_handle[0]);
	struct virt_ipsec_cmd_ctx *cmd_ctx;
	u32 len;
	u8 *msg, *result_ptr;
	u32 *g_hw_handle;
	int32_t ret;

	VIRTIO_IPSEC_ENTRY("\n");
	app = safe_ref_get_data(&v_ipsec_apps,*app_index);
	if (app == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Invalid handle: [A]:%d:%d G:%d:%d\n", 
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle), 
			EXPAND_HANDLE(handle->group_handle));
		return VIRTIO_IPSEC_FAILURE;
	}
	
	if (*group_index != G_IPSEC_LA_GROUP_INVALID) { /* valid group index */
		group = safe_ref_get_data(&v_ipsec_grps, *group_index);
		if (group == NULL)	{
			VIRTIO_IPSEC_DEBUG("%s:%s:%d: Invalid: handle A:%d:%d [G]:%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle),
				EXPAND_HANDLE(handle->group_handle));
			return VIRTIO_IPSEC_FAILURE;
		}
		g_hw_handle = group->hw_handle;
	}
	else  {
		group = NULL;
		g_hw_handle = NULL;
	}
	//dev = safe_ref_get_data(&v_ipsec_devices, app->dev_handle.handle);
	dev = VIRT_IPSEC_MGR_GET_DEVICE(app->dev_handle.handle);
	if (dev == NULL){
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Cannot retrieve device A:%d:%d G:%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle),
				EXPAND_HANDLE(handle->group_handle));
		return VIRTIO_IPSEC_FAILURE;
	}	

	/* Check for pending ops in app or group */
	if ((num_pending_sa_ops_check(app,group, (group != NULL)?true:false)) == true)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Pending ops: cannot flush A:%d:%d G:%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle),
				EXPAND_HANDLE(handle->group_handle));
		return VIRTIO_IPSEC_FAILURE;
	}
	
	
	/* allocate for the context */
	cmd_ctx = kzalloc(sizeof(struct virt_ipsec_cmd_ctx) + 
		sizeof(resp->cb_arg_len), GFP_KERNEL);
	if (cmd_ctx == NULL)
		goto err_ctx;

	if (virt_ipsec_msg_sa_flush(g_hw_handle, &len,&msg,
		&result_ptr)!= VIRTIO_IPSEC_SUCCESS)	
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Message creation failure (handle=%d:%d\n", 
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle));
		goto err_msg;
	}

	/* Update command context block */
	cmd_ctx->cb_arg = (u8 *)(cmd_ctx) + sizeof(struct virt_ipsec_cmd_ctx);
	cmd_ctx->cmd_buffer = msg;
	cmd_ctx->cmd_buffer_len = len;
	memcpy(cmd_ctx->hndl , ((g_hw_handle == NULL)?handle->handle: handle->group_handle),
		G_IPSEC_LA_INTERNAL_HANDLE_SIZE);
	cmd_ctx->out_args = out;
	cmd_ctx->result_ptr = result_ptr;

	if (g_hw_handle) {
		cmd_ctx->b_group = true;
		add_cmd_ctx_to_group(group, cmd_ctx);
		}
	else {
		cmd_ctx->b_group = false;
		add_cmd_ctx_to_app(app, cmd_ctx);
		}
	
	num_pending_sa_ops_inc(app, group, sa);
		
	if (flags & G_IPSEC_LA_CTRL_FLAG_ASYNC)
	{
		cmd_ctx->b_wait = false;
		cmd_ctx->cb_fn = resp->cb_fn;
		memcpy(cmd_ctx->cb_arg, resp->cb_arg, resp->cb_arg_len);
		cmd_ctx->cb_arg_len = resp->cb_arg_len;
	}
	else
	{
		cmd_ctx->b_wait = true;
		/* Initialize wait queue */
		init_waitqueue_head(&cmd_ctx->waitq);
	}
	
	ret = virt_ipsec_send_cmd(dev->info, cmd_ctx);
	
	if (flags & G_IPSEC_LA_CTRL_FLAG_ASYNC)
			return ret;
		
	/* Synchronous mode */
	ret = handle_response(cmd_ctx);

	/* Need to handle failure case here: */
	sa_flush_cleanup(cmd_ctx, app, group);
		
	return ret;
err_msg:
	kfree(cmd_ctx);
	
err_ctx:
	return -ENOMEM;

}
#endif

int32_t virt_ipsec_sa_get(
	struct g_ipsec_la_handle *handle,
	const struct g_ipsec_la_sa_get_inargs *in,
	enum g_ipsec_la_control_flags flags,
	struct g_ipsec_la_sa_get_outargs *out,
	struct g_ipsec_la_resp_args *resp){

	VIRTIO_IPSEC_ENTRY("\n");
	return VIRTIO_IPSEC_FAILURE;
}


int32_t virt_ipsec_packet_encap(
	struct g_ipsec_la_handle *handle, 
	enum g_ipsec_la_control_flags flags,
	struct g_ipsec_la_sa_handle *sa_handle, /* SA Handle */
	uint32_t num_sg, /* num of Scatter Gather elements */
	struct g_ipsec_la_data *in_data,
	/* Array of data blocks */
	struct g_ipsec_la_data *out_data, 
	/* Array of output data blocks */
	struct g_ipsec_la_resp_args *resp
	)
{
	struct v_ipsec_app *app;
	struct v_ipsec_device *dev;
	struct virt_ipsec_info *ipsec_dev;
	struct v_ipsec_sa *sa;
	struct v_ipsec_app_grp *group;
	struct v_ipsec_sa_hndl_ref *sa_ref;
	struct ipsec_data_q_pair *encap_q_pair;
	//struct virtqueue *vq, *next_vq;
	struct virtio_ipsec_hdr *hdr;
	struct data_q_per_cpu_vars *vars;
	struct virt_ipsec_data_ctx *d_ctx;
	u8 max;
	bool b_lock = false;
	int i, j;
	u32 *g_hw_handle;
	u32 *app_index = (u32 *)&(handle->handle[0]);
	u32 *group_index = (u32 *)&(handle->group_handle[0]);
	int32_t ret;

	VIRTIO_IPSEC_ENTRY("\n");
	if (resp->cb_arg_len > VIRTIO_IPSEC_MAX_CB_ARG_SIZE)
		goto api_err;

	if ((num_sg*2) > (MAX_SKB_FRAGS-1))
		goto api_err;

	app = safe_ref_get_data(&v_ipsec_apps,*app_index);
	if (app == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Invalid handle: [A]:%d:%d G:%d:%d\n", 
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle), 
			EXPAND_HANDLE(handle->group_handle));
		return VIRTIO_IPSEC_FAILURE;
	}

	if (*group_index != G_IPSEC_LA_GROUP_INVALID) { /* valid group index */
		group = safe_ref_get_data(&v_ipsec_grps, *group_index);
		if (group == NULL)	{
			VIRTIO_IPSEC_DEBUG("%s:%s:%d: Invalid: handle A:%d:%d [G]:%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle),
				EXPAND_HANDLE(handle->group_handle));
			return VIRTIO_IPSEC_FAILURE;
		}
		g_hw_handle = group->hw_handle;
	} else {
		group = NULL;
		g_hw_handle = NULL;
	}
	dev = VIRT_IPSEC_MGR_GET_DEVICE(app->dev_handle.handle);
	if (dev == NULL){
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Cannot retrieve device A:%d:%d G:%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle),
				EXPAND_HANDLE(handle->group_handle));
		return VIRTIO_IPSEC_FAILURE;
	}	
	ipsec_dev = dev->info;
	VIRTIO_IPSEC_DBG("dev %p app %p group 0x%x sa_hdl 0x%x:0x%x\n", dev, app,
		*group_index, EXPAND_HANDLE(sa_handle->ipsec_sa_handle));

	sa = VIRT_IPSEC_MGR_GET_SA(sa_handle->ipsec_sa_handle);
	if (sa == NULL) {
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Cannot retrieve SA handle=%d:%d\n",
			__FILE__, __func__, __LINE__, 
			EXPAND_HANDLE(sa_handle->ipsec_sa_handle));
		return VIRTIO_IPSEC_FAILURE;
	}
	sa_ref = VIRT_IPSEC_MGR_GET_SA_REF(sa->list_hdl.handle);
	if (sa_ref == NULL) {
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Cannot retrieve SA Ref handle=%d:%d\n",
			__FILE__, __func__, __LINE__, 
			EXPAND_HANDLE(sa_handle->ipsec_sa_handle));
		return VIRTIO_IPSEC_FAILURE;
	}

	if (ipsec_dev->num_q_pairs_per_vcpu != 0) {
		vars = per_cpu_ptr(ipsec_dev->dq_per_cpu_vars, smp_processor_id());
		max = ipsec_dev->num_q_pairs_per_vcpu;
	} else {
		vars = ipsec_dev->dq_per_cpu_vars;
		max = ipsec_dev->num_queues/2;
		b_lock = true;
	}
	encap_q_pair = &(ipsec_dev->data_q_pair[vars->data_q_pair_index_cur_encap]);
	vars->data_q_pair_index_cur_encap++;
	if ((vars->data_q_pair_index_cur_encap - vars->data_q_pair_index_start_encap) >= max)
		vars->data_q_pair_index_cur_encap = vars->data_q_pair_index_start_encap;

	d_ctx = encap_q_pair->encap_ctx;
	hdr = &((d_ctx + encap_q_pair->encap_q_index_cur)->hdr);
	encap_q_pair->encap_q_index_cur++;
	if (encap_q_pair->encap_q_index_cur == encap_q_pair->encap_q_index_max)
		encap_q_pair->encap_q_index_cur = 0;

	if (g_hw_handle)
		memcpy(hdr->group_handle, g_hw_handle, VIRTIO_IPSEC_GROUP_HANDLE_SIZE);
	else memset(hdr->group_handle, 0, VIRTIO_IPSEC_GROUP_HANDLE_SIZE);
	memcpy(hdr->sa_context_handle, sa->hw_sa_handle, VIRTIO_IPSEC_SA_HANDLE_SIZE);

	d_ctx->cb_fn = resp->cb_fn;
	d_ctx->cb_arg_len = resp->cb_arg_len;
	memcpy(d_ctx->cb_arg, resp->cb_arg, resp->cb_arg_len);
	memcpy(d_ctx->sa_hndl.handle, sa_ref->hndl.handle, G_IPSEC_LA_INTERNAL_HANDLE_SIZE);

	/* Need to see if we can get the headroom in the first buffer */
	sg_init_table(encap_q_pair->encap_q.sg, MAX_SKB_FRAGS+2);
	sg_init_one(&encap_q_pair->encap_q.sg[0], hdr, sizeof(struct virtio_ipsec_hdr));
	hdr->num_input_buffers = num_sg;
	hdr->input_data_length = 0;
	for (i=1, j=0; i < num_sg+1; i++, j++) {
		hdr->input_data_length += in_data[j].length;
		sg_init_one(&encap_q_pair->encap_q.sg[i],in_data[j].buffer,in_data[j].length);
	}
	hdr->num_output_buffers = num_sg;
	hdr->output_data_length = 0;
	for (j=0; i < 2*num_sg+1; i++, j++) {
		hdr->output_data_length += out_data[j].length;
		sg_init_one(&encap_q_pair->encap_q.sg[i], out_data[j].buffer, out_data[j].length);
	}
	VIRTIO_IPSEC_CHECK("HWhdl 0x%x:%x sgs %d len in/out %d/%d\n",
		EXPAND_HANDLE(sa->hw_sa_handle), num_sg,
		hdr->input_data_length, hdr->output_data_length);
	pending_data_blocks_inc(sa);
	num_pending_sa_ops_inc(app, group, sa);

	ret = virtqueue_add_sgs(encap_q_pair->encap_q.vq, encap_q_pair->encap_q.sg_ptr,
		num_sg+1, num_sg, d_ctx, GFP_ATOMIC);
	if (ret != VIRTIO_IPSEC_SUCCESS)
		goto err;

	// TODO: find why kick does not work - if (unlikely(!virtqueue_kick(dev->cvq->vq)))
	if (likely(virtqueue_notify(encap_q_pair->encap_q.vq)))
		goto done;
err:
	pending_data_blocks_dec(sa);
	num_pending_sa_ops_dec(app, group, sa);
	VIRTIO_IPSEC_EXIT("failed\n");
done:
	return ret;
	
api_err:
	VIRTIO_IPSEC_EXIT("api error\n");
	return -1;		

}
EXPORT_SYMBOL(virt_ipsec_packet_encap);

int32_t	virt_ipsec_packet_decap(
	struct g_ipsec_la_handle *handle, 
	enum g_ipsec_la_control_flags flags,
	struct g_ipsec_la_sa_handle *sa_handle, /* SA Handle */
	uint32_t num_sg,	/* number of Scatter Gather elements */
	struct g_ipsec_la_data *in_data,/* Array of data blocks */
	struct g_ipsec_la_data *out_data, /* Array of out data blocks*/
	struct g_ipsec_la_resp_args *resp
	)
{
	struct v_ipsec_app *app;
	struct v_ipsec_device *dev;
	struct virt_ipsec_info *ipsec_dev;
	struct v_ipsec_sa *sa;
	struct v_ipsec_sa_hndl_ref *sa_ref;
	struct v_ipsec_app_grp *group;
	u32 *g_hw_handle;
	u32 *app_index = (u32 *)&(handle->handle[0]);
	u32 *group_index = (u32 *)&(handle->group_handle[0]);
	struct ipsec_data_q_pair *decap_q_pair;
//	struct virtqueue *vq, *next_vq;
	struct virtio_ipsec_hdr *hdr;
	struct data_q_per_cpu_vars *vars;
	struct virt_ipsec_data_ctx *d_ctx;
	u8 max;
	bool b_lock = false;
	int i;
	int32_t ret;

	VIRTIO_IPSEC_ENTRY("\n");
	/* API Checks */
	if (resp->cb_arg_len > VIRTIO_IPSEC_MAX_CB_ARG_SIZE)
		goto api_err;

	if ((num_sg*2) > (MAX_SKB_FRAGS-1))
		goto api_err;

	app = safe_ref_get_data(&v_ipsec_apps,*app_index);
	if (app == NULL)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Invalid handle: [A]:%d:%d G:%d:%d\n", 
			__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle), 
			EXPAND_HANDLE(handle->group_handle));
		return VIRTIO_IPSEC_FAILURE;
	}

	if (*group_index != G_IPSEC_LA_GROUP_INVALID) { /* valid group index */

		group = safe_ref_get_data(&v_ipsec_grps, *group_index);
		if (group == NULL)	{
			VIRTIO_IPSEC_DEBUG("%s:%s:%d: Invalid: handle A:%d:%d [G]:%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle),
				EXPAND_HANDLE(handle->group_handle));
			return VIRTIO_IPSEC_FAILURE;
		}
		g_hw_handle = group->hw_handle;
	}
	else  {
		group = NULL;
		g_hw_handle = NULL;
	}
	dev = VIRT_IPSEC_MGR_GET_DEVICE(app->dev_handle.handle);
	if (dev == NULL){
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Cannot retrieve device A:%d:%d G:%d:%d\n",
				__FILE__, __func__, __LINE__, EXPAND_HANDLE(handle->handle),
				EXPAND_HANDLE(handle->group_handle));
		return VIRTIO_IPSEC_FAILURE;
	}	
	ipsec_dev = dev->info;
	sa = VIRT_IPSEC_MGR_GET_SA(sa_handle->ipsec_sa_handle);
	if (sa == NULL) {
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Cannot retrieve SA handle=%d:%d\n",
			__FILE__, __func__, __LINE__, 
			EXPAND_HANDLE(sa_handle->ipsec_sa_handle));
		return VIRTIO_IPSEC_FAILURE;
	}
	sa_ref = VIRT_IPSEC_MGR_GET_SA_REF(sa->list_hdl.handle);
	if (sa_ref == NULL) {
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Cannot retrieve SA Ref handle=%d:%d\n",
			__FILE__, __func__, __LINE__, 
			EXPAND_HANDLE(sa_handle->ipsec_sa_handle));
		return VIRTIO_IPSEC_FAILURE;
	}

	if (ipsec_dev->num_q_pairs_per_vcpu != 0) {
		vars = per_cpu_ptr(ipsec_dev->dq_per_cpu_vars, smp_processor_id());
		max = ipsec_dev->num_q_pairs_per_vcpu;
	}
	else {
		vars = ipsec_dev->dq_per_cpu_vars;
		max = ipsec_dev->num_queues/2;
		b_lock = true;
	}

	
	decap_q_pair = &(ipsec_dev->data_q_pair[vars->data_q_pair_index_cur_decap]);
	vars->data_q_pair_index_cur_decap++;
	if ((vars->data_q_pair_index_cur_decap - vars->data_q_pair_index_start_decap) >
		max) {
		vars->data_q_pair_index_cur_decap = vars->data_q_pair_index_start_decap;
	}
	
	d_ctx = decap_q_pair->decap_ctx;
	hdr = &((d_ctx + decap_q_pair->decap_q_index_cur)->hdr);
	decap_q_pair->decap_q_index_cur++;
	if (decap_q_pair->decap_q_index_cur == decap_q_pair->decap_q_index_max)
		decap_q_pair->decap_q_index_cur = 0;
		
	/* To change later; but for now, alloc */
	memcpy(hdr->group_handle, g_hw_handle, VIRTIO_IPSEC_GROUP_HANDLE_SIZE);
	memcpy(hdr->sa_context_handle, sa->hw_sa_handle, VIRTIO_IPSEC_SA_HANDLE_SIZE);
	hdr->num_input_buffers = num_sg;
	hdr->input_data_length = 0;
	for (i=0; i < hdr->num_input_buffers; i++)
	{
		hdr->input_data_length += in_data[i].length;
	}
	hdr->num_output_buffers = num_sg;
	hdr->output_data_length = 0;
	for (i=0; i < hdr->num_output_buffers; i++)
	{
		hdr->output_data_length += out_data[i].length;
	}
	d_ctx->cb_fn = resp->cb_fn;
	d_ctx->cb_arg_len = resp->cb_arg_len;
	memcpy(d_ctx->cb_arg, resp->cb_arg, resp->cb_arg_len);
	memcpy(d_ctx->sa_hndl.handle, sa_ref->hndl.handle, G_IPSEC_LA_INTERNAL_HANDLE_SIZE);

	sg_init_table(decap_q_pair->decap_q.sg,MAX_SKB_FRAGS+2);

	/* Need to see if we can get the headroom in the first buffer */
	sg_set_buf(&(decap_q_pair->decap_q.sg[0]), hdr, sizeof(struct virtio_ipsec_hdr));
	for (i=1; i < num_sg; i++)
	{
		sg_set_buf(&(decap_q_pair->decap_q.sg[i]),in_data[i].buffer,in_data[i].length);
	}
	for (; i < num_sg; i++)
	{
		sg_set_buf(&(decap_q_pair->decap_q.sg[i]), out_data[i].buffer, out_data[i].length);
	}

	pending_data_blocks_inc(sa);
	num_pending_sa_ops_inc(app, group, sa);

	ret = virtqueue_add_sgs(decap_q_pair->decap_q.vq, decap_q_pair->decap_q.sg_ptr,
		 num_sg, num_sg, d_ctx, GFP_ATOMIC);


	if (ret != VIRTIO_IPSEC_SUCCESS) {
		pending_data_blocks_dec(sa);
		num_pending_sa_ops_dec(app, group, sa);
	}
	else VIRTIO_IPSEC_EXIT("success\n");

	return ret;
api_err:
	return -1;
}
EXPORT_SYMBOL(virt_ipsec_packet_decap);


static int virtio_ipsec_find_vqs(struct virtio_device *vdev,
	unsigned int n_ctrl_vqs, unsigned int n_notify_vqs, unsigned int n_data_vq_pairs,
	unsigned int num_vq_pairs_per_vcpu,
	struct virtqueue *vqs[], vq_callback_t *callbacks[], const char *names[])
{
	int nvqs = n_ctrl_vqs + n_notify_vqs + (n_data_vq_pairs * 2);

	return(vdev->config->find_vqs(vdev, nvqs, vqs, callbacks,
					 names));

#if 0
	/* Try MSI-X with one vector per queue */
	err = vp_try_to_find_vqs(vdev, nvqs, vqs, callbacks,  names, true, true);
	if (!err)
		return 0;
	/*
	if (num_vq_pairs_per_vcpu)
	{
		err = vp_try_to_find_vqs_ipsec(vdev, n_ctrl_vqs, n_notify_vqs, n_data_vq_pairs, 
		num_vq_pairs_per_vcpu, vqs, callbacks, names); 
		if (!err)
			return 0;
	}
	*/

	err = vp_try_to_find_vqs(vdev, nvqs, vqs, callbacks, names, true, false);
	if (!err)
		return 0;

	err = vp_try_to_find_vqs(vdev, nvqs, vqs, callbacks, names, false, false);
	if (!err)
		return 0;
#endif
}


int32_t virt_ipsec_add_to_available_list(struct v_ipsec_device *v_ipsec_dev)
{
	u32 index;
	
	init_rcu_head(&v_ipsec_dev->rcu);
	spin_lock_init(&v_ipsec_dev->lock);
	INIT_LIST_HEAD(&v_ipsec_dev->apps);

	/* add it the safe reference array */
	index = safe_ref_array_add(&v_ipsec_devices, v_ipsec_dev);
	if (index == VIRTIO_IPSEC_MAX_DEVICES) {
		VIRTIO_IPSEC_DEBUG("%s:%s:%d:Exceeding Max Devicess\n",
			__FILE__, __func__, __LINE__);
		return VIRTIO_IPSEC_FAILURE;		
	}
	sprintf(v_ipsec_dev->info->name, "%s%3d", "ipsec-", index);
	printk("virtio-ipsec dev %p ipsec-%d created\n", v_ipsec_dev, index);

	spin_lock_bh(&device_list_lock);
	list_add(&(v_ipsec_dev->link), _device_list.prev);
	num_devices++;
	spin_unlock_bh(&device_list_lock);
	
	return VIRTIO_IPSEC_SUCCESS;
}

int32_t virt_ipsec_avail_devices_get_num(uint32_t *nr_devices) 
{
	*nr_devices = num_devices;
	return VIRTIO_IPSEC_SUCCESS;
}
EXPORT_SYMBOL(virt_ipsec_avail_devices_get_num);

int32_t virt_ipsec_avail_devices_get_info(
	struct g_ipsec_la_avail_devices_get_inargs *in,
	struct g_ipsec_la_avail_devices_get_outargs *out)
{
	struct v_ipsec_device *dev;
	u32 ii = 0, num_iter=0;
	bool index_found = true;

	VIRTIO_IPSEC_ENTRY("\n");
	if (in->last_device_read)
		index_found = false;
	
	do {
		if ((num_iter > 0) && (index_found == false)) {
			/* devce reference invalid */
			VIRTIO_IPSEC_EXIT("failed\n");
			return VIRTIO_IPSEC_FAILURE;
		}
		spin_lock_bh(&device_list_lock);
		dev = (struct v_ipsec_device *)list_first_entry_or_null(&(_device_list), 
			struct v_ipsec_device, link);
		spin_unlock_bh(&device_list_lock);
		if (dev) {
			if (index_found == false) {
				if (strcmp(in->last_device_read,dev->info->name)==0) {
					index_found = true;
					spin_lock_bh(&device_list_lock);
					dev = list_next_entry(dev,link);
					spin_unlock_bh(&device_list_lock);
					continue;
				} else {
					num_iter++;
				}
			} else {
				if (dev->mode == G_IPSEC_LA_INSTANCE_EXCLUSIVE) { /* skip */
					continue;
				}
				/* copy from device */
				strcpy(out->dev_info[ii].device_name, dev->info->name);
				out->dev_info[ii].mode = dev->mode;
				out->dev_info[ii].num_apps = dev->num_apps;
				ii++;
				if (ii == in->num_devices) {
					if (dev->link.next != NULL) {
						out->b_more_devices = true;
						strcpy(out->last_device_read, dev->info->name);
					}
					break;
				}
			}
		}
	}while(1);
	VIRTIO_IPSEC_EXIT("success\n");
	return VIRTIO_IPSEC_SUCCESS;
}
EXPORT_SYMBOL(virt_ipsec_avail_devices_get_info);

#if 0
#define G_IPSEC_APP_GRP_NAME_SIZE 256

struct g_ipsec_la_app_info
{
	char app_name[G_IPSEC_APP_GRP_NAME_SIZE];
	bool has_groups;
	union {
		u32 num_groups;
		u32 num_sas;
	};
};


int32_t virt_ipsec_get_available_devices(struct g_ipsec_la_get_available_list_inargs *in,
	struct g_ipsec_la_get_available_list_outargs *out)
{
}

int32_t virt_ipsec_remove_from_list(struct virt_ipsec_info *dev)
{
	struct v_ipsec_device *v_ipsec_dev = (struct v_ipsec_device *)
		((u8 *)dev - sizeof(struct v_ipsec_device));
	u32 index;
	
	if (v_ipsec_dev == NULL) {
		/* handle error */
		
		}
	index = GET_INDEX_FROM_HANDLE(v_ipsec_dev->hndl.handle);

	
	spin_lock_bh(&device_list_lock);
	list_del(&(v_ipsec_dev->link));
	spin_unlock_bh(&device_list_lock);

	safe_ref_array_node_delete(&v_ipsec_devices,index, virt_ipsec_free);

	return VIRTIO_IPSEC_SUCCESS;
}
#endif

static int virtipsec_alloc_queues(struct virt_ipsec_info *ipsec_dev)
{
	struct ipsec_data_q_pair *data_q_pair; 
	int ii, jj;
	
	//spin_lock_init(&ipsec_dev_queue_lock);

	/* Allocate the data queues */
	ipsec_dev->data_q_pair = kmalloc(
		(sizeof(struct ipsec_data_q_pair) * ipsec_dev->num_queues/2), GFP_KERNEL);

	if (!ipsec_dev->data_q_pair) 
		goto err_data_q_pair;

	for (ii=0; ii < ipsec_dev->num_queues/2; ii++)
	{
		data_q_pair = ipsec_dev->data_q_pair+ii;

		for (jj=0; jj < MAX_SKB_FRAGS+2; jj++)
		{
			data_q_pair->decap_q.sg_ptr[jj] = &(data_q_pair->decap_q.sg[jj]);
			data_q_pair->encap_q.sg_ptr[jj] = &(data_q_pair->encap_q.sg[jj]);
		}
	}


	/* Allocate the init_q-max_q for each VCPU if data_q_per_vcpu is enabled otherwise one global */
	if (ipsec_dev->num_q_pairs_per_vcpu) {
		ipsec_dev->dq_per_cpu_vars = __alloc_percpu(
			(sizeof(struct data_q_per_cpu_vars)),4);

		if (!ipsec_dev->dq_per_cpu_vars)
			goto err_data_q_per_cpu_vars;

	}
	else {
		ipsec_dev->dq_per_cpu_vars = kmalloc(
			sizeof(struct data_q_per_cpu_vars),GFP_KERNEL);
		if (!ipsec_dev->dq_per_cpu_vars)
			goto err_data_q_per_cpu_vars;
	}

	/* allocate the control queue */
	ipsec_dev->cvq = kmalloc(sizeof(struct ipsec_queue), GFP_KERNEL);
	if (!ipsec_dev->cvq)
		goto err_control_queue;

	if ((ipsec_dev->notify_lifetime) || (ipsec_dev->notify_seqnum_overflow) 
		|| (ipsec_dev->notify_seqnum_periodic))
	{
		ipsec_dev->nvq = kmalloc(sizeof(struct ipsec_queue), GFP_KERNEL);
		if (!ipsec_dev->nvq)
			goto err_notify_queue;
	} 

	return 0; 
		
err_notify_queue:
	kfree(ipsec_dev->cvq);

err_control_queue:
	if (ipsec_dev->num_q_pairs_per_vcpu != 0)
		free_percpu(ipsec_dev->dq_per_cpu_vars);
	else
		kfree(ipsec_dev->dq_per_cpu_vars);
err_data_q_per_cpu_vars:
	kfree(ipsec_dev->data_q_pair);
err_data_q_pair:
	return -1;
}
	
static int virtipsec_find_vqs(struct virt_ipsec_info *ipsec_dev)
{
	vq_callback_t **callbacks;
	struct virtqueue **vqs;
	int ret = -ENOMEM;
	int max_queue_pairs;
	struct data_q_per_cpu_vars *vars;
	struct ipsec_data_q_pair *data_q_pair; 
	
	int i, total_vqs, cpu;
	const char **names;
	struct virtio_pci_device *vp_dev;
	struct virtio_pci_vq_info *info;

	total_vqs = ipsec_dev->num_queues + 
		((ipsec_dev->b_notify_q == true)? 2 : 1);
	
	vqs = kzalloc(total_vqs * sizeof(*vqs), GFP_KERNEL);
	if (!vqs)
		goto err_vq;

	callbacks = kmalloc(total_vqs * sizeof(*callbacks), GFP_KERNEL);
	if (!callbacks)
		goto err_callback;

	names = kmalloc(total_vqs * sizeof(*names), GFP_KERNEL);
	if (!names)
		goto err_names;

	names[0] = "control";
	callbacks[0] = control_job_done;
	if (ipsec_dev->b_notify_q) {
		names[total_vqs-1] = "notify";
		callbacks[total_vqs-1] = notify_done;
	}

	max_queue_pairs = ipsec_dev->num_queues/2;
	for (i=0; i < max_queue_pairs; i++)
	{
		data_q_pair = ipsec_dev->data_q_pair+i;
		callbacks[decap2vq(i)] = decap_done;
		callbacks[encap2vq(i)] = encap_done;
		sprintf(ipsec_dev->data_q_pair[i].decap_q.name,
			"decap.%d", i);
		sprintf(ipsec_dev->data_q_pair[i].encap_q.name,
			"encap.%d", i);
		names[decap2vq(i)] = data_q_pair->decap_q.name;
		names[encap2vq(i)] = data_q_pair->encap_q.name;
	}

	ret = virtio_ipsec_find_vqs(ipsec_dev->vdev, 
		1, ((ipsec_dev->b_notify_q == true) ? 1 : 0),
		max_queue_pairs, ipsec_dev->num_q_pairs_per_vcpu, 
		vqs, callbacks, names);
	if (ret)
		goto err_find;
	for (i = 0; i < total_vqs; ++i)
		printk("vq[%d]=%p\n", i, vqs[i]);

	for (i=0; i < max_queue_pairs; i++) {
		ipsec_dev->data_q_pair[i].decap_q.vq = vqs[decap2vq(i)];
		ipsec_dev->data_q_pair[i].encap_q.vq = vqs[encap2vq(i)];
	}
	ipsec_dev->cvq->vq = vqs[0];
	if (ipsec_dev->b_notify_q)
		ipsec_dev->nvq->vq = vqs[total_vqs-1];

	/* Allocate per CPU variables or global ones */
	if (ipsec_dev->num_q_pairs_per_vcpu != 0) {
		i=0;
		for_each_online_cpu(cpu) {
			vars = per_cpu_ptr(ipsec_dev->dq_per_cpu_vars, cpu);
			vars->data_q_pair_index_start_decap = i;
			vars->data_q_pair_index_cur_decap = i;
			vars->data_q_pair_index_start_encap = i;
			vars->data_q_pair_index_cur_encap = i;
			i+= (ipsec_dev->num_q_pairs_per_vcpu);
		}
	} else {
		ipsec_dev->dq_per_cpu_vars->data_q_pair_index_start_decap = 0;
		ipsec_dev->dq_per_cpu_vars->data_q_pair_index_cur_decap = 0;
		ipsec_dev->dq_per_cpu_vars->data_q_pair_index_start_encap = 0;
		ipsec_dev->dq_per_cpu_vars->data_q_pair_index_cur_encap = 0;
	}

	/* Allocate the command and data hdr blocks */
	vp_dev =  to_vp_device(ipsec_dev->vdev);

	for (i=0; i < max_queue_pairs; i++) {
		printk("vpdev.vq pair %d decap %p size %d encap %p size %d\n", i,
			vp_dev->vqs[decap2vq(i)]->vq, vp_dev->vqs[decap2vq(i)]->num,
			vp_dev->vqs[encap2vq(i)]->vq, vp_dev->vqs[encap2vq(i)]->num);

		info = vp_dev->vqs[decap2vq(i)];
		ipsec_dev->data_q_pair[i].decap_ctx = (struct virt_ipsec_data_ctx *)kmalloc(
			sizeof(struct virt_ipsec_data_ctx) * info->num, GFP_KERNEL);
		if (!(ipsec_dev->data_q_pair[i].decap_ctx))
			goto err_ctx;

		info = vp_dev->vqs[encap2vq(i)];
		ipsec_dev->data_q_pair[i].encap_ctx = (struct virt_ipsec_data_ctx *)kmalloc(
			sizeof(struct virt_ipsec_data_ctx) * info->num, GFP_KERNEL);
		if (!(ipsec_dev->data_q_pair[i].encap_ctx))
			goto err_ctx;
	}			

	kfree(names);
	kfree(callbacks);
	kfree(vqs);
	return 0;

err_ctx:
	for (i=0; i < max_queue_pairs; i++) {
		if (ipsec_dev->data_q_pair[i].decap_ctx)
			kfree(ipsec_dev->data_q_pair[i].decap_ctx);
		if (ipsec_dev->data_q_pair[i].encap_ctx)
			kfree(ipsec_dev->data_q_pair[i].encap_ctx);
	}
err_find:
	kfree(names);	
err_names:
	kfree(callbacks);
err_callback:
	kfree(vqs);
err_vq:
	VIRTIO_IPSEC_EXIT("failed\n");
	return -1;
}        

static void virt_ipsec_clean_affinity(
	struct virt_ipsec_info *ipsec_dev, 
	long hcpu)
{
	int i;
	int max_queue_pairs = ipsec_dev->num_queues/2;

	if (ipsec_dev->affinity_hint_set) {
		for (i = 0; i < max_queue_pairs; i++) {
			virtqueue_set_affinity(ipsec_dev->data_q_pair[i].decap_q.vq, -1);
			virtqueue_set_affinity(ipsec_dev->data_q_pair[i].encap_q.vq, -1);
		}

		ipsec_dev->affinity_hint_set = false;
	}
}

static void virt_ipsec_set_affinity(
	struct virt_ipsec_info *ipsec_dev)
{
	int i;
	int cpu;
	//struct ipsec_data_q_pair *q_pair;
	struct data_q_per_cpu_vars *vars;

	/* In multiqueue mode, when the number of cpu is equal to the number of
	 * queue pairs, we let the queue pairs to be private to one cpu by
	 * setting the affinity hint to eliminate the contention.
	 */
	if (!ipsec_dev->num_q_pairs_per_vcpu) {
		virt_ipsec_clean_affinity(ipsec_dev, -1);
		return;
	}

	for_each_online_cpu(cpu) {
		vars = per_cpu_ptr(ipsec_dev->dq_per_cpu_vars, cpu);
		
		for (i= vars->data_q_pair_index_start_decap; 
			i < 
			(vars->data_q_pair_index_start_decap + ipsec_dev->num_q_pairs_per_vcpu);
			i++) {
				virtqueue_set_affinity(
					ipsec_dev->data_q_pair[i].decap_q.vq, cpu);
					
			}
		for (i=vars->data_q_pair_index_start_encap;
			i < 
			(vars->data_q_pair_index_start_encap + ipsec_dev->num_q_pairs_per_vcpu);
			i++) {
				virtqueue_set_affinity(
					ipsec_dev->data_q_pair[i].encap_q.vq, cpu);
				}
			}

	ipsec_dev->affinity_hint_set = true;
}

#ifdef _NOT_USED_
static int virt_ipsec_cpu_callback(struct notifier_block *nfb,
			        unsigned long action, void *hcpu)
{
	struct virt_ipsec_info *ipsec_dev = 
		container_of(nfb, struct virt_ipsec_info, nb);

	VIRTIO_IPSEC_ENTRY("\n");
	switch(action & ~CPU_TASKS_FROZEN) {
	case CPU_ONLINE:
	case CPU_DOWN_FAILED:
	case CPU_DEAD:
		virt_ipsec_set_affinity(ipsec_dev);
		break;
	case CPU_DOWN_PREPARE:
		virt_ipsec_clean_affinity(ipsec_dev, (long)hcpu);
		break;
	default:
		break;
	}

	return NOTIFY_OK;
}
#endif

static void virt_ipsec_free_queues(
	struct virt_ipsec_info *ipsec_dev)
{
	int i;

	/* Free the memory */
	kfree(ipsec_dev->cvq);
	if (ipsec_dev->num_q_pairs_per_vcpu != 0)
		free_percpu(ipsec_dev->dq_per_cpu_vars);
	else
		kfree(ipsec_dev->dq_per_cpu_vars);

	for (i=0; i < ipsec_dev->num_queues/2; i++) {
		if (ipsec_dev->data_q_pair[i].decap_ctx)
			kfree(ipsec_dev->data_q_pair[i].decap_ctx);
		if (ipsec_dev->data_q_pair[i].encap_ctx)
			kfree(ipsec_dev->data_q_pair[i].encap_ctx);
	}

	kfree(ipsec_dev->data_q_pair);
	
	if (ipsec_dev->b_notify_q)
		kfree(ipsec_dev->nvq);
	
}
static int init_vqs(struct virt_ipsec_info *ipsec_dev)
{
	int ret;

	/* Allocate the control, notification, encap, decap queue pairs */
	ret = virtipsec_alloc_queues(ipsec_dev);
	if (ret)
		goto err;
	
	ret = virtipsec_find_vqs(ipsec_dev);
	if (ret)
		goto err_free;
	
	get_online_cpus();
	virt_ipsec_set_affinity(ipsec_dev);
	put_online_cpus();

	return 0;

err_free:
	virt_ipsec_free_queues(ipsec_dev);

err:
	VIRTIO_IPSEC_EXIT("failed\n");
	return -1;

}

static void free_unused_bufs(struct virt_ipsec_info *ipsec_dev)
{
	int i;
	int max_queue_pairs = ipsec_dev->num_queues/2;
	struct virtqueue *vq;
	struct virt_ipsec_data_ctx *d_ctx;
	struct virt_ipsec_cmd_ctx *cmd_ctx;
	struct v_ipsec_sa *sa;
	struct v_ipsec_app *app;
	struct v_ipsec_app_grp *grp;

	VIRTIO_IPSEC_ENTRY("\n");
	for (i = 0; i < max_queue_pairs; i++) {
		 vq = ipsec_dev->data_q_pair[i].decap_q.vq; 
		while ((d_ctx = virtqueue_detach_unused_buf(vq))!= NULL){
			sa = VIRT_IPSEC_MGR_GET_SA(d_ctx->sa_hndl.handle);
			if (sa != NULL) {
				pending_data_blocks_dec(sa);

				/* find group or app from SA and decrement ops */
				if (sa->in_group == true) {
					grp = safe_ref_get_data(&v_ipsec_grps, GET_INDEX_FROM_HANDLE(sa->grp_hndl.handle));
					if (grp != NULL)
						num_pending_sa_ops_dec(app, grp, sa->in_group);
				}
				else {
					app = safe_ref_get_data(&v_ipsec_apps, GET_INDEX_FROM_HANDLE(sa->app_hndl.handle));
					if (app != NULL)
						num_pending_sa_ops_dec(app, grp, sa->in_group);
				}
			}
			/* Call the callback function Need to fill this up*/
			d_ctx->cb_fn(d_ctx->cb_arg, d_ctx->cb_arg_len, ((void *)(d_ctx->hdr.result)));
			}

		vq = ipsec_dev->data_q_pair[i].encap_q.vq;
		while ((d_ctx = virtqueue_detach_unused_buf(vq)) != NULL){
			sa = VIRT_IPSEC_MGR_GET_SA(d_ctx->sa_hndl.handle);
			if (sa != NULL) {
				pending_data_blocks_dec(sa);

				/* find group or app from SA and decrement ops */
				if (sa->in_group == true) {
					grp = safe_ref_get_data(&v_ipsec_grps, GET_INDEX_FROM_HANDLE(sa->grp_hndl.handle));
					if (grp != NULL)
						num_pending_sa_ops_dec(app, grp, sa->in_group);
				}
				else {
					app = safe_ref_get_data(&v_ipsec_apps, GET_INDEX_FROM_HANDLE(sa->app_hndl.handle));
					if (app != NULL)
						num_pending_sa_ops_dec(app, grp, sa->in_group);
				}
			}
			/* Call the callback function Need to fill this up*/
			d_ctx->cb_fn(d_ctx->cb_arg, d_ctx->cb_arg_len, ((void *)(d_ctx->hdr.result)));
		}
	}
	/* Control queue */
	vq = ipsec_dev->cvq->vq;
	while ((cmd_ctx = virtqueue_detach_unused_buf(vq)) != NULL) {
		if (cmd_ctx->b_wait == true) {
			cmd_ctx->cond = true;
			wake_up_interruptible(&cmd_ctx->waitq);
		}
		else { /* Call the callback function */
			//cmd_ctx->cb_fn(cmd_ctx->cb_arg, cmd_ctx->cb_arg_len, ...);
			handle_response(cmd_ctx);
		}
			
	}

#if 0
	/* Optional notification queue */
	if (ipsec_dev->b_notify_q)	 {
		vq = ipsec_dev->nvq.vq;

		while (buf = virtqueue_detach_unused_buf(vq)) {
			}
	}
#endif
			
}


/*
 * Function: virtio_ipsec_probe
 * Input : virtio_device
 * Description : Reads the PCI features, makes Virtio PCI layer calls to set up Vrings,
 *               Interrupts and communictes to vhost-user
 *             : Sets up Application callback blocks, SG Lists
 * Output      : Success or Failure
 */ 
 



/* Calculates max queues possible
 * Finds LCM of device_scaling and guest_scaling *2
 * LCM maxed by max_queues-2 if notification feature is enabled
 * Max_queues split across guest_scaling
 */
static u16 calc_num_queues(__u16 max_queues, __u8 device_scaling, 
	__u8 guest_scaling, bool b_notify_q_enabled,
	__u8 *num_queue_pairs_per_vcpu)
{
	u32 lcm;
//	u16 max = (b_notify_q_enabled == true) ? (max_queues-2) : (max_queues - 1);
	u32 max = max_queues;
	//u16 max_possible = 0;
//	u8 num_queue_pairs_per_vcpu; /* Encap+decap */


	u32 _guest_scaling= guest_scaling * 2; /* for decap + encap */

	lcm = (device_scaling > _guest_scaling) ? device_scaling : _guest_scaling;

	while (1)
	{
		if ((lcm%device_scaling == 0) && (lcm%_guest_scaling==0)) {
			break;
		}
		lcm++;
	}
	VIRTIO_IPSEC_DEBUG("%s:%s:%d:LCM=%d \n", __FILE__, __func__, __LINE__, lcm);
	max = (lcm <= max) ? lcm : max;

	VIRTIO_IPSEC_DEBUG("max = %d, guest_scaling=%d\n", max, _guest_scaling);

	*num_queue_pairs_per_vcpu =  (max/_guest_scaling); /* encap,decap pairs */

	VIRTIO_IPSEC_DEBUG("%s:%s:%d:num_queue_pairs_per_vcpu=%d\n", __FILE__, __func__, __LINE__, 
	*num_queue_pairs_per_vcpu);

	return max;

}

static void virt_ipsec_del_vqs(struct virt_ipsec_info 
	* ipsec_dev)
{
	struct virtio_device *vdev = ipsec_dev->vdev;

	virt_ipsec_clean_affinity(ipsec_dev, -1);

	vdev->config->del_vqs(vdev);

	virt_ipsec_free_queues(ipsec_dev);
}

int virt_ipsec_probe( struct virtio_device *vdev)
{
	int err;
	struct v_ipsec_device *v_ipsec_dev;
	struct virt_ipsec_info *ipsec_dev;
	u32 dev_queue_reg;

	bool b_notify_q;

	VIRTIO_IPSEC_ENTRY("vdev %p index %d\n", vdev, vdev->index);
	/* Read number of queues supported */
	virtio_cread(vdev, struct virtio_ipsec_config, dev_queue_reg, &dev_queue_reg);

	printk("dev_queue_reg = 0x%x\n", dev_queue_reg);

	if ((VIRTIO_IPSEC_MAX_QUEUES_READ(dev_queue_reg) > VIRTIO_IPSEC_MAX_VQS) ||
		(VIRTIO_IPSEC_MAX_QUEUES_READ(dev_queue_reg) < VIRTIO_IPSEC_MIN_VQS)/** || 
		(VIRTIO_IPSEC_DEVICE_SCALING_READ(dev_queue_reg)**Temp Hack   == 0) */)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d: Invalid Number of Queues: Configuration\n", 
			__FILE__, __func__, __LINE__);
		return -EINVAL;
	}

	/* Allocate a virtio ipsec device */
	v_ipsec_dev = kzalloc(sizeof(struct v_ipsec_device)+sizeof(struct virt_ipsec_info),
		GFP_KERNEL);
	
	if (!v_ipsec_dev)
	{
		printk("NO memory?\n");
		return -ENOMEM;
	}

	ipsec_dev = (struct virt_ipsec_info *)(v_ipsec_dev + 1);
	v_ipsec_dev->info = ipsec_dev;

	ipsec_dev->vdev = vdev;
	vdev->priv = ipsec_dev;
	/* intialize listhead */

	INIT_LIST_HEAD(&ipsec_dev->apps); 
	
	ipsec_dev->num_queues = VIRTIO_IPSEC_MAX_QUEUES_READ(dev_queue_reg);
	// Temp fix : ipsec_dev->device_scaling = VIRTIO_IPSEC_DEVICE_SCALING_READ(dev_queue_reg);
	//ipsec_dev->vcpu_scaling = NR_CPUS;
	// TODO: temp hardcoded
	ipsec_dev->device_scaling = 1;
	ipsec_dev->vcpu_scaling = 2; 

	printk("num_queues = %d, device_scaling = %d, vcpu_scaling=%d\n",
		ipsec_dev->num_queues, ipsec_dev->device_scaling, ipsec_dev->vcpu_scaling);

	/* Read Device features */
    if (virtio_has_feature(vdev, VIRTIO_IPSEC_F_SG_BUFFERS))
    {
		VIRTIO_IPSEC_DEBUG("Support SG Buffers\n");
		ipsec_dev->sg_buffer = 1;
    }
    if (virtio_has_feature(vdev, VIRTIO_IPSEC_F_AH))
    {
		VIRTIO_IPSEC_DEBUG("AH\n");
		ipsec_dev->ah = 1;
    }
    if (virtio_has_feature(vdev, VIRTIO_IPSEC_F_WESP))
    {
		VIRTIO_IPSEC_DEBUG("WESP\n");
		ipsec_dev->wesp = 1;
    }
    if (virtio_has_feature(vdev, VIRTIO_IPSEC_F_SA_BUNDLES))
    { 
		VIRTIO_IPSEC_DEBUG("SA_BUNDLES\n");
		ipsec_dev->sa_bundles = 1;
    }
    if (virtio_has_feature(vdev, VIRTIO_IPSEC_F_UDP_ENCAPSULATION))
    {
		VIRTIO_IPSEC_DEBUG("UDP Encap\n");
		ipsec_dev->udp_encap=1;
    }
    if (virtio_has_feature(vdev, VIRTIO_IPSEC_F_TFC))
    {
		VIRTIO_IPSEC_DEBUG("TFC \n");
		ipsec_dev->tfc = 1;
    }
    if (virtio_has_feature(vdev, VIRTIO_IPSEC_F_ESN))
    {
		VIRTIO_IPSEC_DEBUG("ESN \n");
		ipsec_dev->esn = 1;
    }
    if (virtio_has_feature(vdev, VIRTIO_IPSEC_F_ECN))
    {
		VIRTIO_IPSEC_DEBUG("ECN \n");
		ipsec_dev->ecn = 1;
    }
    if (virtio_has_feature(vdev, VIRTIO_IPSEC_F_DF))
    {
		VIRTIO_IPSEC_DEBUG("DF\n");
		ipsec_dev->df = 1;
    }
    if (virtio_has_feature(vdev, VIRTIO_IPSEC_F_ANTI_REPLAY_CHECK))
    {
		VIRTIO_IPSEC_DEBUG("ANTI_REPLAY\n");
		ipsec_dev->anti_replay = 1;
    }
    if (virtio_has_feature(vdev, VIRTIO_IPSEC_IPV6_SUPPORT))
    {
		VIRTIO_IPSEC_DEBUG("IPV6 Support\n");
		ipsec_dev->ipv6_support=1;
    }
    if (virtio_has_feature(vdev, VIRTIO_IPSEC_F_SOFT_LIFETIME_BYTES_NOTIFY))
    {
		VIRTIO_IPSEC_DEBUG("LIFETIME NOTIFY\n");
		ipsec_dev->notify_lifetime=1;
    }
    if (virtio_has_feature(vdev, VIRTIO_IPSEC_F_SEQNUM_OVERFLOW_NOTIFY))
    {
		VIRTIO_IPSEC_DEBUG("SEQNUM_NOTIFY\n");
		ipsec_dev->notify_seqnum_overflow=1;
    }
    if (virtio_has_feature(vdev, VIRTIO_IPSEC_F_SEQNUM_PERIODIC_NOTIFY))
    {
		VIRTIO_IPSEC_DEBUG("SEQNUM_PERIODIC\n");
		ipsec_dev->notify_seqnum_periodic=1;
    }

	if ((ipsec_dev->notify_lifetime==1) || (ipsec_dev->notify_seqnum_overflow==1) || 
		(ipsec_dev->notify_seqnum_periodic==1)) 
	{
		ipsec_dev->b_notify_q = true;
		VIRTIO_IPSEC_DEBUG("notify_queue\n");
	}

	ipsec_dev->num_queues = calc_num_queues(ipsec_dev->num_queues,
		ipsec_dev->device_scaling, ipsec_dev->vcpu_scaling, b_notify_q, 
		&ipsec_dev->num_q_pairs_per_vcpu);

	VIRTIO_IPSEC_DEBUG("num queues = %d\n", ipsec_dev->num_queues);

	if (ipsec_dev->num_queues < 2)
	{
		VIRTIO_IPSEC_DEBUG("%s:%s:%d Calculated number of queues < 2 \n",
			 __FILE__,__func__,__LINE__);
		goto free_resource;
	}
	

/*
	if (ipsec_dev->num_q_pairs_per_vcpu == 0)
		ipsec_dev->bLock = true;
*/

	//sprintf(ipsec_dev->name, "%s:%d\n", VIRTIO_IPSEC_NAME, virtio_ipsec_mgr_get_new_index(VIRTIO_IPSEC_MAX_DEVICES);
	
	/* Write vCPU scaling */
	// TODO: temp ignored by backend; so commented - Varun to fix
	//virtio_cwrite(vdev, struct virtio_ipsec_config, host_queue_reg, (u32*)(&ipsec_dev->vcpu_scaling));
	
	err = init_vqs(ipsec_dev);
	if (err)
		goto free_device;

	VIRTIO_IPSEC_DEBUG("init_vqs done\n");

	/* Add to available list */
	if (virt_ipsec_add_to_available_list(v_ipsec_dev)!= VIRTIO_IPSEC_SUCCESS) 
		goto free_resource;

	/* TBD
	if (ipsec_dev->b_notify)
	{
		INIT_WORK(&ipsec_dev->n_wa, _notify_jobs_done, (void *)(ipsec_dev));
	}

	ipsec_dev->nb.notifier_call = &virt_ipsec_cpu_callback;

	err = register_hotcpu_notifier(&vi->nb);
	if (err) {
		VIRTIO_IPSEC_DEBUG("virtio_ipsec: registering cpu notifier failed\n");
		goto free_resource;
	}
	*/
	INIT_WORK(&ipsec_dev->c_work, _ipsec_control_job_done);
	VIRTIO_IPSEC_DEBUG("Writing device ok\n");
	virtio_device_ready(vdev);

	VIRTIO_IPSEC_EXIT("success\n");
	//g_ipsec_dev = ipsec_dev;
	return 0;

free_resource:
	virt_ipsec_del_vqs(ipsec_dev);
free_device:
	kfree(v_ipsec_dev);
	/* TBD */
	VIRTIO_IPSEC_EXIT("failed\n");
	return -1;
}

static void virt_ipsec_remove_vq_common(struct virt_ipsec_info *vi)
{
	vi->vdev->config->reset(vi->vdev);

	/* Free unused buffers in both send and recv, if any. */
	free_unused_bufs(vi);

	virt_ipsec_del_vqs(vi);
}

static void virt_ipsec_remove(struct virtio_device *vdev)
{
	int ii;
	
	struct virt_ipsec_info *vi = vdev->priv;
	/* TBD */

	VIRTIO_IPSEC_ENTRY("vdev %p index %d\n", vdev, vdev->index);
	unregister_hotcpu_notifier(&vi->nb);

	/* Make sure no work handler is accessing the device. */
	flush_work(&vi->c_work);

	for (ii=0; ii < NR_CPUS; ii++)
	{
		tasklet_disable(&_decap_queue_cleanup[ii]);
		_decap_done(ii);
		tasklet_disable(&_encap_queue_cleanup[ii]);
		_encap_done(ii);
	}

    virt_ipsec_remove_vq_common(vi);

	/* reenable tasklets for other devices */
	for(ii=0; ii < NR_CPUS; ii++)
	{
		tasklet_enable(&_decap_queue_cleanup[ii]);
		tasklet_enable(&_encap_queue_cleanup[ii]);
	}

	kfree(vi);

	/* cleanup: TBD */
}

/*
The PCI feature bits part of Virtio Standards will be supported. 
VIRTIO_RING_F_INDIRECT_DESC	28	
VIRTIO_RING_F_EVENT_IDX		29	
VIRTIO_ID_IPSEC to be defined in virtio_ids.h
*/

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_IPSEC, VIRTIO_DEV_ANY_ID },
	{ 0 },
};


static unsigned int features[] = {
	VIRTIO_IPSEC_F_SG_BUFFERS,
	VIRTIO_IPSEC_F_AH,
	VIRTIO_IPSEC_F_WESP,
	VIRTIO_IPSEC_F_SA_BUNDLES,
	VIRTIO_IPSEC_F_UDP_ENCAPSULATION,
	VIRTIO_IPSEC_F_TFC,
	VIRTIO_IPSEC_F_ESN,
	VIRTIO_IPSEC_F_ECN,
	VIRTIO_IPSEC_F_DF,
	VIRTIO_IPSEC_F_ANTI_REPLAY_CHECK,
	VIRTIO_IPSEC_IPV6_SUPPORT,
	VIRTIO_IPSEC_F_SOFT_LIFETIME_BYTES_NOTIFY,
	VIRTIO_IPSEC_F_SEQNUM_OVERFLOW_NOTIFY,
	VIRTIO_IPSEC_F_SEQNUM_PERIODIC_NOTIFY,
};

static void virt_ipsec_config_changed(struct virtio_device *vdev)
{
	VIRTIO_IPSEC_ENTRY("===ignored vdev %p index %d\n", vdev, vdev->index);
	/* TBD */
}

/* Initialization of function pointers */
static struct virtio_driver virtio_ipsec_driver = {
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.driver.name = KBUILD_MODNAME,
	.driver.owner = THIS_MODULE,
	.id_table =id_table,
	.probe = virt_ipsec_probe,
	.remove = virt_ipsec_remove,
	.config_changed = virt_ipsec_config_changed,
};

static int _init(void)
{
	int ret;

	VIRTIO_IPSEC_ENTRY("\n");
	if (safe_ref_array_setup(&v_ipsec_devices,
		VIRTIO_IPSEC_MAX_DEVICES,
		true))
		goto err_ipsec_dev;

	if (safe_ref_array_setup(&v_ipsec_apps,
		VIRTIO_IPSEC_MAX_APPS,
		true))
		goto err_ipsec_app;

	if (safe_ref_array_setup(&v_ipsec_app_hndl_refs,
		VIRTIO_IPSEC_MAX_APPS,
		true))
		goto err_ipsec_app_hndl_refs;

	if (safe_ref_array_setup(&v_ipsec_grps,
		VIRTIO_IPSEC_MAX_GROUPS,
		true))
		goto err_ipsec_groups;

	if (safe_ref_array_setup(&v_ipsec_grp_hndl_refs,
		VIRTIO_IPSEC_MAX_GROUPS,
		true))
		goto err_ipsec_groups_hndl_refs;

	if (safe_ref_array_setup(&v_ipsec_sas,
		VIRTIO_IPSEC_MAX_SAS,
		true))
		goto err_ipsec_sas;

	if (safe_ref_array_setup(&v_ipsec_sa_hndl_refs,
		VIRTIO_IPSEC_MAX_SAS,
		true))
		goto err_ipsec_sa_hndl_refs;
	
	spin_lock_init(&device_list_lock);

	INIT_LIST_HEAD(&_device_list);

	_init_tasklet_lists();

	printk("driver->name = %s\n", virtio_ipsec_driver.driver.name);
	ret = register_virtio_driver(&virtio_ipsec_driver);
	if (ret < 0)
	{
		printk("register_virtio_driver failed\n");
		goto err_reg;
	}

	VIRTIO_IPSEC_EXIT("success\n");
	return VIRTIO_IPSEC_SUCCESS;
	
err_reg:
	safe_ref_array_cleanup(&v_ipsec_sa_hndl_refs);
err_ipsec_sa_hndl_refs:
	safe_ref_array_cleanup(&v_ipsec_sas);
err_ipsec_sas:
	safe_ref_array_cleanup(&v_ipsec_grp_hndl_refs);
err_ipsec_groups_hndl_refs:
	safe_ref_array_cleanup(&v_ipsec_grps);
err_ipsec_groups:
	safe_ref_array_cleanup(&v_ipsec_app_hndl_refs);
err_ipsec_app_hndl_refs:
	safe_ref_array_cleanup(&v_ipsec_apps);
err_ipsec_app:
	safe_ref_array_cleanup(&v_ipsec_devices);
err_ipsec_dev:
	VIRTIO_IPSEC_EXIT("failed\n");
	return -ENOMEM;
}

static void  _deinit(void)
{
	VIRTIO_IPSEC_ENTRY("\n");
	safe_ref_array_cleanup(&v_ipsec_devices);
	safe_ref_array_cleanup(&v_ipsec_apps);
	safe_ref_array_cleanup(&v_ipsec_app_hndl_refs);
	safe_ref_array_cleanup(&v_ipsec_grps);
	safe_ref_array_cleanup(&v_ipsec_grp_hndl_refs);
	safe_ref_array_cleanup(&v_ipsec_sas);
	safe_ref_array_cleanup(&v_ipsec_sa_hndl_refs);
}
module_init(_init);
module_exit(_deinit);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio IPSEC driver");
MODULE_LICENSE("GPL");

//module_virtio_driver(virtio_ipsec_driver);
