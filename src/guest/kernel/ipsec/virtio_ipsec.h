#ifndef _VIRTIO_IPSEC_H
#define _VIRTIO_IPSEC_H

#define VIRTIO_ID_IPSEC	13 /* 20 */

/* The feature bitmap for virtio ipsec */

/*
The PCI feature bits part of Virtio Standards will be supported. 
VIRTIO_RING_F_INDIRECT_DESC	28	
VIRTIO_RING_F_EVENT_IDX		29	
*/

#define VIRTIO_IPSEC_F_SG_BUFFERS 0
#define VIRTIO_IPSEC_F_AH 	1
#define VIRTIO_IPSEC_F_WESP			(2)	/* Device supports WESP */
#define VIRTIO_IPSEC_F_SA_BUNDLES		(3)	/* Device supports SA bundle */
#define VIRTIO_IPSEC_F_UDP_ENCAPSULATION	(4)	/* UDP Encapsulation for NAT Traversal */
#define VIRTIO_IPSEC_F_TFC			(5)	/* Device supports Traffic Flow Confidentiality */
#define VIRTIO_IPSEC_F_ESN			(6)	/* Device supports Extended Sequence number */
#define VIRTIO_IPSEC_F_ECN			(7)	/* Device supports Explicit Congestion Notification */
#define VIRTIO_IPSEC_F_DF			(8)	/* DF bit support */
#define VIRTIO_IPSEC_F_ANTI_REPLAY_CHECK	(9)	/* Device supports Anti replay check */
#define VIRTIO_IPSEC_IPV6_SUPPORT		(10)	/* Is Support IPv6 */	
#define VIRTIO_IPSEC_F_SOFT_LIFETIME_BYTES_NOTIFY	(11)	/* Device notifies when soft life time is about to expire, so that Guest can initiate new SA negotiation */
#define VIRTIO_IPSEC_F_SEQNUM_OVERFLOW_NOTIFY	12 	/* Device notifies when sequence number is about to overflow, so that Guest can initiate new SA negotiation */
#define VIRTIO_IPSEC_F_SEQNUM_PERIODIC_NOTIFY   13	/* Periodic update of Sequence number from device to guest */

/*
#define SAFE_REF_ARRAY_GET_DATA(table, index) (table->base[index].data)
#define SAFE_REF_ARRAY_GET_MAGIC_NUM(table, index) (table->base[index].magic_num)
*/

#undef printk
#define VIRTIO_IPSEC_DEBUG		printk
#define VIRTIO_IPSEC_ENTRY(fmt, arg...)	printk("%s ===entry: "fmt, __func__, ##arg)
#define VIRTIO_IPSEC_EXIT(fmt, arg...)	printk("%s ===exit: "fmt, __func__, ##arg)
#define VIRTIO_IPSEC_ERROR(fmt, arg...)	printk("%s/%d: "fmt, __func__, __LINE__, ##arg)
#define VIRTIO_IPSEC_DBG(fmt, arg...)	printk("%s/%d: "fmt, __func__, __LINE__, ##arg)
#define VIRTIO_IPSEC_CHECK(fmt, arg...)	printk("%s/%d: check-"fmt, __func__, __LINE__, ##arg)

#define G_IPSEC_LA_INTERNAL_HANDLE_SIZE	G_IPSEC_LA_HANDLE_SIZE

struct safe_ref_array_node {
	void *data;
	u32 magic_num;
	struct safe_ref_array_node *next;
	struct safe_ref_array_node *prev;
};

struct safe_ref_array {
	struct safe_ref_array_node *head;
	struct safe_ref_array_node *base;
	u32 num_entries;
	u32 num_cur_entries;
	u32 magic_num;
	spinlock_t  lock;
	bool b_lock;
};

static inline void *safe_ref_get_data(struct safe_ref_array *table, u32 index)
{
	return table->base[index].data;
}

static inline unsigned int safe_ref_get_magic_num (struct safe_ref_array *table, 
	u32 index)
{
	return table->base[index].magic_num;
}
struct data_q_per_cpu_vars {
		u8 data_q_pair_index_start_decap;
		u8 data_q_pair_index_cur_decap;
		u8 data_q_pair_index_start_encap;
		u8 data_q_pair_index_cur_encap;
};

struct ipsec_queue {
	struct list_head link;	
	/* Virtqueue associated with the encap queue */
	struct virtqueue *vq;

	/* Fragments + linear part + virtio header: Need to Check : AVS */
	struct scatterlist sg[MAX_SKB_FRAGS+2];

	struct scatterlist *sg_ptr[MAX_SKB_FRAGS+2];

	/* Copied from virtio-net: need to check: AVS */
	char name[40];
};

struct v_ipsec_sa_hndl {
	u8 handle[G_IPSEC_LA_SA_HANDLE_SIZE];
};

#define VIRTIO_IPSEC_MAX_CB_ARG_SIZE 64
struct virt_ipsec_data_ctx
{
	struct list_head link;
	struct virtio_ipsec_hdr hdr;
	g_ipsec_la_resp_cbfn	cb_fn;
	struct v_ipsec_sa_hndl sa_hndl;
	u8 cb_arg[VIRTIO_IPSEC_MAX_CB_ARG_SIZE];
	u32 cb_arg_len;
};
	
struct ipsec_data_q_pair
{
	struct ipsec_queue decap_q;
	struct ipsec_queue encap_q;
	struct virt_ipsec_data_ctx *decap_ctx;
	u32 decap_q_index_max;
	u32 decap_q_index_cur;
	struct virt_ipsec_data_ctx *encap_ctx;
	u32 encap_q_index_max;
	u32 encap_q_index_cur;
};	

/* Virtio Accelerator Block */
struct virt_ipsec_info {
	struct list_head node; /* prev/next entries */
	struct virtio_device *vdev; /* Pointer to virtio device */
	char name[IPSEC_IFNAMESIZ];
	struct list_head apps; /* List of application contexts */
	struct ipsec_queue *cvq; /* Pointer to control virt queue */
	struct ipsec_queue *nvq; /* Pointer to notification virt queue */
	/* Following Out+Inq will be percpu variables */
	struct ipsec_data_q_pair *data_q_pair; /* decap-q, encap-q, decap-hdrs, encap-hdrs */
	struct virtio_ipsec_ctrl_hdr *ctrl_hdr; /* Array of allocated control headers */
	struct data_q_per_cpu_vars *dq_per_cpu_vars;
	struct work_struct c_work;
	u8 vcpu_scaling; /* Number of queues required to achieve vcpu scaling */
	u8 device_scaling; /* Number of queues required to achieve device scaling */
	u8 num_q_pairs_per_vcpu; /* Number of queues per vcpu */
	u8 num_queues; /* Number of queues (Encap + decap) across vpcus */
	bool b_notify_q;
	spinlock_t	      lock;
	u32 
	    sg_buffer:1,
	    ah:1,
	    wesp:1,
	    sa_bundles:1,
	    udp_encap:1,
	    tfc:1,
	    esn:1,
	    ecn:1,
            df:1,
            anti_replay:1,
	    ipv6_support:1,
	    notify_lifetime:1,
	    notify_seqnum_overflow:1,
	    notify_seqnum_periodic:1;
	/* affinity hint */
	bool affinity_hint_set;
	/* CPU hot plug notifier */
	struct notifier_block nb;
};

#endif
