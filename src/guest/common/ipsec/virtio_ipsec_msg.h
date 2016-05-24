/* Virtio Messages for IPsec Protocol header acceleration.
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
/*
 * @file virtio_ipsec_msg.h
 * 
 * @brief Contains  virtio_ipsec_msg declarations & definitions
 *
 * @addtogroup VIRTIO_IPSEC
 * @{
*/
#ifndef _VIRTIO_IPSEC_MSG_H
#define _VIRTIO_IPSEC_MSG_H


/*! Success and Failure macros */
#define VIRTIO_IPSEC_FAILURE -1
#define VIRTIO_IPSEC_SUCCESS 0


/*! Macros */
/*! Nounce Length */
#define VIRTIO_IPSEC_NOUNCE_LEN		16
/*! Cipher Key size */
#define VIRTIO_IPSEC_MAX_CIPHER_KEY_SIZE	64

#define VIRTIO_IPSEC_MAX_KEY_IV_LEN 64

/*! SA Handle size */
#define VIRTIO_IPSEC_SA_HANDLE_SIZE	8	

/*! GROUP Handle Size */
#define VIRTIO_IPSEC_GROUP_HANDLE_SIZE 8 

/*! V4 Tunnel */
#define VIRTIO_IPSEC_TUNNEL_HDR_IS_IPV4	0
/*! V6 Tunnel */
#define VIRTIO_IPSEC_TUNNEL_HDR_IS_IPV6	1

/*! Tunnel/Transport Mode */
#define VIRTIO_IPSEC_SA_SAFLAGS_TUNNEL_MODE		0
#define VIRTIO_IPSEC_SA_SAFLAGS_TRANSPORT_MODE	1

/*! ESP/AH Protocol */
#define VIRTIO_IPSEC_SA_PARAMS_PROTO_ESP	50
#define VIRTIO_IPSEC_SA_PARAMS_PROTO_AH		51	

/*! Propogate ECN or not */
#define VIRTIO_IPSEC_PROPOGATE_ECN_ON	0
#define VIRTIO_IPSEC_PROPOGATE_ECN_OFF	1

/*! Extended Sequence number on or off */
#define VIRTIO_IPSEC_EXTENDED_SEQ_NUM_ON	0
#define VIRTIO_IPSEC_EXTENDED_SEQ_NUM_OFF 	1

/*! Anti-replay on or off */
#define VIRTIO_IPSEC_REPLAY_CHECK_ON	0
#define VIRTIO_IPSEC_REPLAY_CHECK_OFF	1

/*! UDP encapsulation on or off */
#define VIRTIO_IPSEC_UDP_ENCAPSULATION_ON 	0
#define VIRTIO_IPSEC_UDP_ENCAPSULATION_OFF	1

/*! NAT Traversal v1 or v2 */
#define VIRTIO_IPSEC_UDP_NAT_TRAVERSAL_V1	0
#define VIRTIO_IPSEC_UDP_NAT_TRAVERSAL_V2	1

/*! SA Notify upon lifetime expiry on or off */
#define VIRTIO_IPSEC_SA_NOTIFY_LIFETIME_KB_EXPIRY_ON 1
#define VIRTIO_IPSEC_SA_NOTIFY_LIFETIME_KB_EXPIRY_OFF 0

/*! SA Notify upon sequence number overflow on or off */
#define VIRTIO_IPSEC_SA_NOTIFY_SEQNUM_OVERFLOW_ON 1
#define VIRTIO_IPSEC_SA_NOTIFY_SEQNUM_OVERFLOW_OFF 1

/*! SA Notify sequence number periodically on or off */
#define VIRTIO_IPSEC_SA_NOTIFY_SEQNUM_PERIODIC_ON	1
#define VIRTIO_IPSEC_SA_NOTIFY_SEQNUM_PERIODIC_OFF	0


/*!
 *  IPSec Control virtqueue data structures
 *
 * The control virtqueue expects a header in the first sg entry
 * and an result/status response in the last entry.  Data for the
 * command goes in between.
 * Note: The ctrl_hdr, ctrl_result and the actual command 
 * can be sent as a single buffer as well
 */
struct virtio_ipsec_ctrl_hdr {
	u8 class;  /*! class of command */
	u8 cmd;   /*! actual command */
}__attribute__((packed)); 

/*! Data structure for control queue result */
struct virtio_ipsec_ctrl_result {
	u8 result;	/*! VIRTIO_IPSEC_OK or VIRTIO_IPSEC_ERR */
	u8 result_data; /*! error information if any */
}__attribute__((packed));

/*! Enumerations */
/*! Defines for the result field */
enum virtio_ipsec_result_value 
{
	VIRTIO_IPSEC_OK = 0,	/*! Result is Ok */
	VIRTIO_IPSEC_ERR	/*! iResult is an error */
};

/*! Following messages will be sent on the Command Queue */
enum virtio_ipsec_ctrl_command_class
{
	VIRTIO_IPSEC_CTRL_GENERIC= 1,	
	/*! Generic Commands such as Get/Set Capabilities, Set Endianness etc. */
	VIRTIO_IPSEC_CTRL_SA,		
	/*! Class of commands to add/modify/delete SA */
	VIRTIO_IPSEC_CTRL_GET_RAND_DATA,	
	/*! Class of commands to get random data */
	VIRTIO_IPSEC_CTRL_ADVANCED	
	/*! Any vendor specific or advanced commands */
};

/*! Generic commands */
enum virtio_ipsec_ctrl_command_class_generic
{
	VIRTIO_IPSEC_CTRL_GET_CAPABILITIES=1,	
	/*! Underlying algorithm support */
	VIRTIO_IPSEC_CTRL_SET_CAPABILITIES=2,	
	/*! Nothing defined here as of now */
	VIRTIO_IPSEC_CTRL_SET_GUEST_ENDIAN=3	
	/*! Set the Guest endian mode to device */
};

/*! SA Commands */
enum virtio_ipsec_ctrl_command_class_sa
{
	VIRTIO_IPSEC_CTRL_ADD_GROUP=1,  
	/*! Add a group */
	VIRTIO_IPSEC_CTRL_DELETE_GROUP, 
	/*! Delete a group */
	VIRTIO_IPSEC_CTRL_ADD_OUT_SA,	
	/*! Add an outbound SA - Encapsulation */ 
	VIRTIO_IPSEC_CTRL_DEL_OUT_SA,	
	/*! Delete Outbound SA */
	VIRTIO_IPSEC_CTRL_UPDATE_OUT_SA,	
	/*! Update Outbound SA */
	VIRTIO_IPSEC_CTRL_READ_OUT_SA,	
	/*! Read Outbound SA */
	VIRTIO_IPSEC_CTRL_READ_FIRST_N_OUT_SAs, 
	/*! Read first N outbound SAs */
	VIRTIO_IPSEC_CTRL_READ_NEXT_N_OUT_SAs,	
	/*! Read next N Out SAs */
	VIRTIO_IPSEC_CTRL_ADD_IN_SA,	
	/*! Add an inbound SA - Decapsulation */
	VIRTIO_IPSEC_CTRL_DEL_IN_SA,	
	/*! Delete Inbound SA */
	VIRTIO_IPSEC_CTRL_UPDATE_IN_SA,	
	/*! Update Inbound SA */
	VIRTIO_IPSEC_CTRL_READ_IN_SA,	
	/*! Read Inbound SA */
	VIRTIO_IPSEC_CTRL_READ_FIRST_N_IN_SAs,	
	/*! Read first N SAs */
	VIRTIO_IPSEC_CTRL_READ_NEXT_N_IN_SAs,	
	/*! Read Next N SAs */
	VIRTIO_IPSEC_CTRL_FLUSH_SA,	
	/*! Flush SAs within a group */
	VIRTIO_IPSEC_CTRL_FLUSH_SA_ALL 
	/*! Flush all SAs */
};

/*! Random Number */
enum virtio_ipsec_ctrl_command_class_rand
{
	VIRTIO_IPSEC_GET_RAND_NUM=1 /*! Get Random number */
};

/*! HMAC Algorithms */
enum virtio_ipsec_hmac_algorithms {
	VIRTIO_IPSEC_HMAC_NULL=0,	 /*! NULL */
	VIRTIO_IPSEC_HMAC_MD5, /*! MD5 */
	VIRTIO_IPSEC_HMAC_SHA1, /*! SHA1 */
	VIRTIO_IPSEC_HMAC_AES_XCBC_MAC, /*! XCBC_MAC */
	VIRTIO_IPSEC_HMAC_SHA256, /*! SHA256 */
	VIRTIO_IPSEC_HMAC_SHA384, /*! SHA384 */
	VIRTIO_IPSEC_HMAC_SHA512, /*! SHA512 */
	VIRTIO_IPSEC_HMAC_SHA1_160 /*! SHA1_160 */
};

/*! Cipher Algorithms */
enum virtio_ipsec_cipher_alogithms {
	VIRTIO_IPSEC_CIPHER_NONE=0, /*! NONE */	
	VIRTIO_IPSEC_DES_CBC, /*! DES */
	VIRTIO_IPSEC_3DES_CBC, /*! 3DES */
	VIRTIO_IPSEC_ESP_NULL, /*! NULL */
	VIRTIO_IPSEC_AES_CBC, /*! AES */
	VIRTIO_IPSEC_AESCTR, /*! AESCTR */
	VIRTIO_IPSEC_AES_CCM_ICV8, /*! AES_CCM_ICV8 */
	VIRTIO_IPSEC_AES_CCM_ICV12, /*! AES_CCM_ICV12 */
	VIRTIO_IPSEC_AES_CCM_ICV16, /*! AES_CCM_ICV16 */
	VIRTIO_IPSEC_AES_GCM_ICV8, /*! AES_GCM_ICV8 */
	VIRTIO_IPSEC_AES_GCM_ICV12, /*! AES_GCM_ICV12 */
	VIRTIO_IPSEC_AES_GCM_ICV16, /*! AES_GCM_ICV16 */
	VIRTIO_IPSEC_AES_GMAC /*! AES_GMAC */
};

/*! Endian */
enum virtio_ipsec_endian
{
 	VIRTIO_IPSEC_GUEST_LITTLE_ENDIAN=1, /*! Little */
	VIRTIO_IPSEC_GUEST_BIG_ENDIAN /*! Big endian */
};

/*! DSCP Setting */
enum virtio_ipsec_qos_dscp_setting
{
	VIRTIO_IPSEC_DSCP_COPY=0, /*! Copy */
	VIRTIO_IPSEC_DSCP_CLEAR, /*! Clear */
	VIRTIO_IPSEC_DSCP_SET /*! Set */
}; 

/*! DF Setting */
enum virtio_ipsec_df_setting
{
	VIRTIO_IPSEC_DF_COPY=0, /*! Copy */
	VIRTIO_IPSEC_DF_CLEAR, /*! Clear */
	VIRTIO_IPSEC_DF_SET /* Set */
};

/*! IPsec Transforms */
enum virtio_ipsec_transforms
{
	VIRTIO_IPSEC_ESP=0, /*! ESP */
	VIRTIO_IPSEC_AH, /*! AH */
	VIRTIO_IPSEC_ESP_WITH_AUTH /*! ESP with AUTH */
};

/*! 
 @internal AVS: Confirm data structure 
struct virtio_ipsec_config {
	__u16 max_queue_pairs_r;
	__u8  device_scaling_r;
	__u8  guest_scaling_r;
	__u16 reserved;
	__u8  reserved_1;
	__u8  guest_scaling_w;
}__attribute__((packed));
*/

/*! Version information */
struct virtio_ipsec_version_info {
	__u32 version_len; /*! Length of all versions supported */
}__attribute__((packed));

/*! Value of version */
struct virtio_ipsec_version {
	__u32 version;  /*! Version value */
}__attribute__((packed));

/*! Device queue registers */
struct virtio_ipsec_config {
	__u32 dev_queue_reg; /*! Device queue information */
	__u32 host_queue_reg; /*! Guest queue information */
}__attribute__((packed));

/*! Macros for queue information */
#define MAX_Q_PAIR_MASK	0xffff
#define DEVICE_SCALING_MASK 0xff0000
#define GUEST_SCALING_MASK 0xff000000

#define VIRTIO_IPSEC_MAX_QUEUES_READ(p)	\
	((p & MAX_Q_PAIR_MASK) *2)

#define VIRTIO_IPSEC_DEVICE_SCALING_READ(p)	\
	((p & DEVICE_SCALING_MASK) >> 16)


/*! Max and minimum queues */
#define VIRTIO_IPSEC_MAX_VQS (4096 -2)
#define VIRTIO_IPSEC_MIN_VQS 2

/*! Get capabilities */
struct virtio_ipsec_ctrl_capabilities {	
	/* Algorithm capabilities */
	u32	hmac_algorithms; /*! HMAC capabilities */
	u32 	cipher_algorithms;  /*! Cipher capabilities */
}__attribute__((packed));


/*! Guest Endian */
struct virtio_ipsec_set_guest_endian {
	u8 endian; /*! GUEST_LITTLE_ENDIAN or GUEST_BIT_ENDIAN */
}__attribute__((packed));


/*! Group Add data structure */
struct virtio_ipsec_group_add{
	u8	group_handle[VIRTIO_IPSEC_GROUP_HANDLE_SIZE]; 
}__attribute__((packed));

/*! Group delete data structure */
struct virtio_ipsec_group_delete{
	u8	group_handle[VIRTIO_IPSEC_GROUP_HANDLE_SIZE]; 
}__attribute__((packed));


/*! Structures used in SA add, get messages */
struct virtio_ipsec_sa_params {
	u32 ulSPI;	/*! Security Parameter Index */
	uint8_t proto; /*! ESP, or AH*/
	u16 		/*! Flags */
		
		bEncapsulationMode:1, /*! tunnel or transport */ 
		bIPv4OrIPv6, /*! IPv4 or IPv6 */
		bUseExtendedSeqNum:1, /*! To use extended sequence number or not */
		bDoAntiReplayCheck:1, /*! Do antireplay sequence number or not */
		bDoUDPEncapsulation:1, /*! Do UDP encapsulation or not */
		bNotifySoftLifeKBExpiry:1, 
		/*! Notify when soft life time expires */
		bNotifyBeforeSeqNumOverflow:1,		
		/*! Notify 'n' packets before Seq number expires */
		bNotifySeqNumPeriodic:1;		
		/*! Notify Periodically every 'n' packets */
	u32	antiReplayWin; /*! Anti replay window */
}__attribute__((packed));

/*! The following structures may be used following the virtio_ipsec_sa_params, 
	based on the bit field settings for add sa , get sa */

/*! Tunnel Header IPv4 */
struct virtio_ipsec_tunnel_hdr_ipv4
{
	u32 saddr;	/*! Source Address */
	u32 daddr;	/*! Destination Address */
	u8 b_handle_dscp:2, /*! Handle DSCP */
	   b_handle_df:2, /*! Handle DF */
	   b_propogate_ECN:1; /*! handle ECN */
	u8 Dscp;	/*! Value to be used for creating DSCP field in Outer IP header */
}__attribute__((packed));

/*! Tunnel header IPv6 */
struct virtio_ipsec_tunnel_hdr_ipv6
{
	u32 s_addr[4];	/*! Source Address */
	u32 d_addr[4];	/*! Destination Address */
	u8 b_handle_dscp:2, /*! Handle DSCP */
	   b_handle_df:2, /*!  Handle DF */
	   b_propogate_ECN:1; /*! Handle ECN */
	u8 dscp;	/*! Value to be used for creating DSCP field in Outer IP header */
}__attribute__((packed));	

/*! Structure to hold NAT Traversal information */
struct virtio_ipsec_udp_encapsulation_info
{
	u8 ulNatTraversalMode;	/*! v1 or v2 */
	u16 d_port;	/*! Destination Port Value */
	u16 s_port;	/*! Source Port Value */
}__attribute__((packed));

/*! Structure to hold variable length data; Can be used for sending keys etc. */
struct virtio_ipsec_lv
{
	u32 len;	/*! Length of following data */
	u8 data[VIRTIO_IPSEC_MAX_KEY_IV_LEN];	/*! actual data */
}__attribute__((packed));

/*! ESP information */
struct virtio_ipsec_esp_info
{
	u8  reserved:4, /*! reserved for future use */
		bAuth:1, /*! set when auth is enabled */
		bEncrypt:1; /*! indicates when cipher is enabled */	
	u8 cipher_algo;	/*! Encryption algorithm */
	u8   IV_Size; /*! IV size */
	u8 block_size; /*! block size */
	u32 counter_initial; /*! Initial counter for counter mode algorithms */
	u8 auth_algo;	/*! Authentication Algorithm as defined in Get Features */
	u8   AHPaddingLen;  /*! AH padding length */
	u8 ICVSize; /*! ICV size */
}__attribute__((packed));


/*! Cipher key */
struct cipher_key {
	struct virtio_ipsec_lv lv; /*! Cipher key information */
}__attribute__((packed));

/*! authentication key */
struct auth_key {
	struct virtio_ipsec_lv lv; /*! Authentication key */
}__attribute__((packed));;

/*! nounce iv */
struct nounce_iv {
	struct virtio_ipsec_lv lv; /*! Nounce IV */
}__attribute__((packed));


/*! virtio ipsec ah information */
struct virtio_ipsec_ah_info
{
	u8 authAlgo; /*! Authentication algorithm */
	 u8   AHPaddingLen;  /*! Padding length */
	u8 ICVSize; /*! ICV size */
}__attribute__((packed));

/*! Notify lifetime kb */
struct virtio_ipsec_notify_lifetime_kb {
	u32 soft_lifetime_in_kb; /*! Soft lifetime in kb */
	u32 hard_lifetime_in_kb; /*! hard lifteime in kb */
}__attribute__((packed));

/*! Periodic sequence number notification */
struct virtio_ipsec_notify_seqnum_periodic {
	u32 seqnum_interval; /*! Notification interval */
}__attribute__((packed));

/*! Structure to create SA */
struct virtio_ipsec_create_sa{
	u8	group_handle[VIRTIO_IPSEC_GROUP_HANDLE_SIZE];	  
	/*! Input: Optional Group Handle when a group was 
	   previously created; All 0s indicate an invalid group handle */
	u8	sa_handle[VIRTIO_IPSEC_SA_HANDLE_SIZE]; /*! Output */
	u32 num_sas; /*! number of SAs in the SA bundle */
	u32 sa_len; /*! length of following SA information */
	struct virtio_ipsec_sa_params sa_params; /*! Input */
	/*! Followed by structures based on the flag bits in sa_params */
	/*! followed by more virtio_sec_sa_params and other structures if num_sas >  1 */
}__attribute__((packed));

/*! The structures that follow struct virtio_ipsec_sa_params depend on the 
   flags member of the structure. 
1. If bEncaspulationMode is set to 
	a. VIRTIO_IPSEC_SA_SAFLAGS_TUNNEL_MODE, the next structure would be 
           either struct virtio_ipsec_tunnel_hdr_ipv4 or 
           struct virtio_ipsec_tunnel_hdr_ipv6 based on the bIPv4OrIPv6 flag setting. 
2. If bTransforms is set to
	a. VIRTIO_IPSEC_ESP, the next structure would be 
	   struct virtio_ipsec_esp_info
	b. VIRTIO_IPSEC_AH, the next structure would be struct virtio_ipsec_ah_info
	c. VIRTIO_IPSEC_ESP_WITH_AH, the next structure would be 
           struct virtio_ipsec_esp_info followed by struct virtio_ipsec_ah_info

3. If bDoUDPEncapsulation is set to VIRTIO_IPSEC_UDP_ENCAPSULATION_ON
	a.The next structure to follow would be 
          struct virtio_ipsec_udp_encapsulation_info
4. If bNotifySoftLifeKBExpiry is set			
	a. The next structure to follow would be 
           struct virtio_ipsec_notify_lifetime_kb
5. If bNotifyBeforeSeqNumOverflow is set
	a.The next structure to follow would be 
           struct virtio_ipsec_notify_before_seqnum_overflow
6. If bNotifySeqNumPeriodic is set
	a. The next structure to follow would be 
           struct virtio_ipsec_notify_seqnum_periodic
*/

/*! Capability - update */
/*! Update v4 Address */
struct virtio_ipsec_update_sa_ipaddr_v4 {
	u16 port;
	u32 addr;
}__attribute__((packed));

/*! Update v6 Address */
struct virtio_ipsec_update_sa_ipaddr_v6{
	u16 port;
	u32 addr[4];
}__attribute__((packed));

/*! Update sequence number */
struct virtio_ipsec_update_sa_seqnum{
	u32 seq_num; /* Sequence Number is being updated */
	u32 hi_seq_num;
}__attribute__((packed));

/*! Update antireplay */
struct virtio_ipsec_update_sa_antireplay {
 	u32 anti_replay_window_size;
	u32 anti_replay_window_bit_map;
}__attribute__((packed));

/*! Macros for updating SA */
#define VIRTIO_IPSEC_UPDATE_SA_LOCAL_GW	0
#define VIRTIO_IPSEC_UPDATE_SA_PEER_GW	1
#define VIRTIO_IPSEC_UPDATE_SA_SEQ_NUM 2
#define VIRTIO_IPSEC_UPDATE_SA_ANTI_REPLAY_WINDOW  3


/*! Update SA */
struct virtio_ipsec_update_sa {
	u8	group_handle[VIRTIO_IPSEC_GROUP_HANDLE_SIZE];	  
        /*! Input: Optional Group Handle when a group was previously created; 
           All 0s indicate an invalid group handle */
	u8 changeType;  /*! LOCAL_GW, REMOTE_GW etc. */
	u8	sa_handle[VIRTIO_IPSEC_SA_HANDLE_SIZE]; /*! SA Handle */
	/*! The structure that follows would be either 
        struct virtio_ipsec_update_sa_ipaddr_v4 or 
        struct virtio_ipsec_update_sa_ipaddr_v6 based on whether the 
        updated SA is an ipv4 or ipv6 SA. */
}__attribute__((packed));;

/*! Delete SA */
struct virtio_ipsec_delete_sa{
	u8	group_handle[VIRTIO_IPSEC_GROUP_HANDLE_SIZE];	  
        /*! Input: Optional Group Handle when a group was previously created; 
           All 0s indicate an invalid group handle */
	u8	sa_handle[VIRTIO_IPSEC_SA_HANDLE_SIZE]; /*! SA Handle */
}__attribute__((packed));

/*! Seq number information */
struct virtio_ipsec_out_sa_info {
	u32 low_seq_number;
	u32 hi_seq_number;
}__attribute__((packed));

/*! Get SA message */
struct virtio_ipsec_read_out_sa_exact {
	u8	group_handle[VIRTIO_IPSEC_GROUP_HANDLE_SIZE];	  
        /*! Input: Optional Group Handle when a group was previously created; 
          All 0s indicate an invalid group handle */

	u8	sa_handle[VIRTIO_IPSEC_SA_HANDLE_SIZE];
	/*! SA Handle */
	struct virtio_ipsec_out_sa_info info;
	/*! Seq number information */
	struct virtio_ipsec_sa_params sa_params;
	/*! SA Params */
	/*! Followed by structures based on the flag bits in sa_params */
}__attribute__((packed));


/*! Read N SAs */
struct virtio_ipsec_read_out_n_first_sa {
	u8	group_handle[VIRTIO_IPSEC_GROUP_HANDLE_SIZE];	  
        /*! Input: Optional Group Handle when a group was previously created; 
           All 0s indicate an invalid group handle */
	u32 num_sas; /*!Number of SAs to read */ 
	u8	opaque_handle[VIRTIO_IPSEC_SA_HANDLE_SIZE]; 
        /*! Output by Accelerator; Input for next n calls */
	/*! Array of the following */
	u8	sa_handle[VIRTIO_IPSEC_SA_HANDLE_SIZE];
	/*! SA handle */
	struct virtio_ipsec_out_sa_info info;
	/*! SA Sequence number */
 	struct virtio_ipsec_sa_params sa_params; 
	/*! SA Params */
	/*! Followed by structures based on the flag bits in sa_params */
}__attribute__((packed));


/*! Read Next N SAs */
struct virtio_ipsec_read_out_n_next_sa {
	u8	group_handle[VIRTIO_IPSEC_GROUP_HANDLE_SIZE];	  
        /*! Input: Optional Group Handle when a group was previously created; 
           All 0s indicate an invalid group handle */
	u32 num_sas; /*! Number of SAs */
	u8	opaque_handle[VIRTIO_IPSEC_SA_HANDLE_SIZE]; 
        /*! Output by Accelerator; Input for next n calls */
	/*! Array of sa_handle, seq number information, sa params*/ 
	u8	sa_handle[VIRTIO_IPSEC_SA_HANDLE_SIZE];
	struct virtio_ipsec_out_sa_info info;
    	struct virtio_ipsec_sa_params sa_params; 
	/*! Followed by structures based on the flag bits in sa_params */
}__attribute__((packed));;

/*! In SA information */
struct virtio_ipsec_in_sa_info {
	u32 low_seq_number;
	u32 hi_seq_number; 
}__attribute__((packed));;

/*! Read In SA */
struct virtio_ipsec_read_in_sa_exact {
	u8	group_handle[VIRTIO_IPSEC_GROUP_HANDLE_SIZE];	  
        /*! Input: Optional Group Handle when a group was previously created; 
           All 0s indicate an invalid group handle */
	u8	sa_handle[VIRTIO_IPSEC_SA_HANDLE_SIZE];
	/*! SA handle */
	struct virtio_ipsec_in_sa_info info;
	/*! Sequence number information */
	struct virtio_ipsec_sa_params sa_params;
	/*! Sa Parameters information */
	/* Followed by structures based on the flag bits in sa_params */
}__attribute__((packed));


/*! Read First N SA */
struct virtio_ipsec_read_in_n_first_sa {
	u8	group_handle[VIRTIO_IPSEC_GROUP_HANDLE_SIZE];	  
        /*! Input: Optional Group Handle when a group was previously created; 
           All 0s indicate an invalid group handle */
	u32 num_sas;
	/*! Number of SAs to read */
	u8	opaque_handle[VIRTIO_IPSEC_SA_HANDLE_SIZE]; 
        /*! Output by Accelerator; Input for next n calls */
	/*! Array of sa_handle, info, sa_params etc */
	u8	sa_handle[VIRTIO_IPSEC_SA_HANDLE_SIZE];
	struct virtio_ipsec_in_sa_info info;
	struct virtio_ipsec_sa_params sa_params;
	/*! Followed by structures based on the flag bits in sa_params */
}__attribute__((packed));


/*! Read Next N SA */
struct virtio_ipsec_read_in_n_next_sa {
	u8	group_handle[VIRTIO_IPSEC_GROUP_HANDLE_SIZE];	  
        /* Input: Optional Group Handle when a group was previously created; 
           All 0s indicate an invalid group handle */
	u32 num_sas; 
	/*! Number of SAs to read */
	u8	opaque_handle[VIRTIO_IPSEC_SA_HANDLE_SIZE]; 
        /*! Output by Accelerator; Input for next n calls */
	/*! Array of the following */
	u8	sa_handle[VIRTIO_IPSEC_SA_HANDLE_SIZE];
	struct virtio_ipsec_in_sa_info info;
	struct virtio_ipsec_sa_params sa_params;
	/* Followed by structures based on the flag bits in sa_params */
}__attribute__((packed));;

/*! Flush SA */
struct virtio_ipsec_flush_sa {
	u8	group_handle[VIRTIO_IPSEC_GROUP_HANDLE_SIZE];	  
        /*! Input: Valid Group Handle */
}__attribute__((packed));

/*! Event notification */
enum virtio_ipsec_notify_event
{
	VIRTIO_IPSEC_NOTIFY_LIFETIME_KB_EXPIRY=1, /*! Lifetime expiry notification */
	VIRTIO_IPSEC_NOTIFY_BEFORE_SEQNUM_OVERFLOW, /* Sequence number overflow notification */
	VIRTIO_IPSEC_NOTIFY_SEQNUM_PERIODIC /* Sequence number periodic notification */
};


/*! Structure for Lifetime Notification */
struct virtio_ipsec_notify_lifetime_kb_expiry
{
	enum virtio_ipsec_notify_event notify_event; 
        /*! Value = VIRTIO_IPSEC_NOTIFY_LIFETIME_KB_EXPIRY */
	u8	group_handle[VIRTIO_IPSEC_GROUP_HANDLE_SIZE];	  
        /*! Optional Group Handle */
	u8	sa_context_handle[VIRTIO_IPSEC_SA_HANDLE_SIZE];
	/*! SA Handle */
	u32	lifetime_in_kb;	/* Current Lifetime in Kb */
	/*! lifetime information */
}__attribute__((packed));


/*! Structure for Sequence number overflow notification */
struct virtio_ipsec_notify_before_seqnum_overflow
{
	enum virtio_ipsec_notify_event notify_event; 
        /*! Value = VIRTIO_IPSEC_NOTIFY_BEFORE_SEQNUM_OVERFLOW  */
	u8	group_handle[VIRTIO_IPSEC_GROUP_HANDLE_SIZE];	  
        /*! Optional Group Handle */
	u8	sa_context_handle[VIRTIO_IPSEC_SA_HANDLE_SIZE];
	/*! sa handle */
	u32	seqnum;	/* Current Sequence Number */
	/*! sequence number */
}__attribute__((packed));

/*! Structure for Periodic seqnumber notification */
struct virtio_ipsec_notify_periodic_seqnum
{
	enum virtio_ipsec_notify_event notify_event; 
        /*! Value = VIRTIO_IPSEC_NOTIFY_SEQNUM_PERIODIC */
	u8 group_handle[VIRTIO_IPSEC_GROUP_HANDLE_SIZE];	  
        /*! Optional Group Handle */
	u8 sa_context_handle[VIRTIO_IPSEC_SA_HANDLE_SIZE];
	/*! SA handle */
	u32 seqnum;	/* Current sequence number */
	/*! Sequence number */
}__attribute__((packed));


/*! @internal
Packets are IPSec-encrypted by placing them in the EncryptQ1..EncryptQn and 
decrypted by placing them in the DecryptQ1..DecryptQn.  
In each case, the data is preceded by a header. When data is spread 
across a SG list, only the first buffer shall have the virtio_ipsec_hdr. 
The rest of the buffers will have only data.
*/
/*! Data structure for data processing */
struct virtio_ipsec_hdr {
	u8 group_handle[VIRTIO_IPSEC_GROUP_HANDLE_SIZE];	  
        /*! Input: Optional Group Handle when a group was previously created; 
           All 0s indicate an invalid group handle */
	u8 sa_context_handle[VIRTIO_IPSEC_SA_HANDLE_SIZE]; /*! IPsec SA  Context */
	u32 num_input_buffers; /*! Number of input buffers  */
	u32 input_data_length;  /*! Length of input data */
	u32 num_output_buffers; /*! Number of output buffers */
	u32 output_buffer_length; /*! Size of output buffers */
	u32 flags;  /* for future use */
	u32 output_data_length;	/*! Output data length */
	u32 result; /*! result */
	u32 error_code; /*! error code */
}__attribute__((packed));;

/*!
 * @brief Releases previously allocated message after any internal cleanup
 *
 * @param[in] msg - pointer to message
 * 
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t virt_ipsec_msg_release(u8 *);


/*!
 * @brief Frames a message for SA flush 
 *
 * @param[in] g_hw_handle - group  handle
 *
 * @param[in] len - pointer to length
 * 
 * @param[in] msg - address of pointer to message
 * 
 * param[in/out] result_ptr - offset where the result data is
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t virt_ipsec_msg_sa_flush(
	u32 *g_hw_handle, u32 *len,
	u8 **msg, u8 **result_ptr);

/*!
 * @brief Frames a message for SA Modify
 *
 * @param[in] g_hw_handle - group handle 
 *
 * @param[in] sa_handle - sa_handle
 * 
 * @param[in] in - input arguments to modify SA 
 *
 * @param[in] len - pointer to length
 * 
 * @param[in] msg - address of pointer to message
 * 
 * param[in/out] result_ptr - offset where the result data is
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t virt_ipsec_msg_sa_mod
		(u32 *g_hw_handle, u32 *sa_handle, 
		const struct g_ipsec_la_sa_mod_inargs *in,
		 u32 *len, u8 **msg, u8 **result_ptr);

/*!
 * @brief Frames a message for SA Modify
 *
 * @param[in] g_hw_handle - group handle 
 *
 * @param[in] sa_handle - sa_handle
 * 
 * @param[in] in - input arguments to delete SA 
 *
 * @param[in] len - pointer to length
 * 
 * @param[in] msg - address of pointer to message
 * 
 * param[in/out] result_ptr - offset where the result data is
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t virt_ipsec_msg_sa_del(
		u32 *g_hw_handle, u32 *sa_handle, 
		const struct g_ipsec_la_sa_del_inargs *in, 
		u32 *len,
		u8 **msg, u8 **result_ptr);

/*!
 * @brief Frames a message for SA Add
 *
 * @param[in] handle - group handle 
 *
 * @param[in] in - input arguments to create SA 
 *
 * @param[in] len - pointer to length
 * 
 * @param[in] msg - address of pointer to message
 * 
 * param[in/out] result_ptr - offset where the result data is
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t virt_ipsec_msg_sa_add(u32 *handle, 
	 const struct g_ipsec_la_sa_add_inargs *in, u32 *len, u8 **msg,
	 u8 **result_ptr);

/*!
 * @brief Frames a message for Group Add
 *
 * @param[in] len - pointer to length
 * 
 * @param[in] msg - address of pointer to message
 * 
 * param[in/out] result_ptr - offset where the result data is
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t  virt_ipsec_msg_group_add(
	u32 *len, u8 **msg, u8 **result_ptr);
/*!
 * @brief Frames a message for Group Delete
 *
 * @param[in] group_handle - group handle 
 *
 * @param[in] len - pointer to length
 * 
 * @param[in] msg - address of pointer to message
 * 
 * param[in/out] result_ptr - offset where the result data is
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t virt_ipsec_msg_group_delete(
	u32 *group_handle,
	u32 *len, u8 **msg,
	u8 **result_ptr);

/*!
 * @brief Frames a message for Get capabilities 
 *
 * @param[in] len - pointer to length
 * 
 * @param[in] msg - address of pointer to message
 * 
 * param[in/out] result_ptr - offset where the result data is
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t virt_ipsec_msg_get_capabilities(
	u32 *len, u8 **msg, u8 **result_ptr);

/*!
 * @brief Utility function to parse the sa flush result
 *
 * @param[in] msg - pointer to msg
 * 
 * @param[in] len - length of message
 * 
 * param[in/out] result_ptr - pointer in the buffer that holds the result information 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t virt_ipsec_msg_sa_flush_parse_result(
		u8 *msg, u32 len,
		struct virtio_ipsec_ctrl_result **result,
		u8 *result_ptr);

/*!
 * @brief Utility function to parse sa add result
 *
 * @param[in] msg - pointer to msg
 * 
 * @param[in] len - length of message
 * 
 * param[in/out] result_ptr - pointer in the buffer that holds the result information 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t virt_ipsec_msg_sa_add_parse_result(
        u8 *msg, u32 len,
        struct virtio_ipsec_ctrl_result **result,
        struct virtio_ipsec_create_sa **v_ipsec_create_sa,
        u8 *result_ptr);


/*!
 * @brief Utility function to parse the sa delete result
 *
 * @param[in] msg - pointer to msg
 * 
 * @param[in] len - length of message
 * 
 * param[in/out] result_ptr - pointer in the buffer that holds the result information 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t virt_ipsec_msg_sa_del_parse_result(
	u8 *msg, u32 len,
	struct virtio_ipsec_ctrl_result **result,
	u8 *result_ptr); 

/*!
 * @brief Utility function to parse the sa modify result
 *
 * @param[in] msg - pointer to msg
 * 
 * @param[in] len - length of message
 * 
 * param[in/out] result_ptr - pointer in the buffer that holds the result information 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t virt_ipsec_msg_sa_mod_parse_result(
		u8 *msg, u32 len,
		struct virtio_ipsec_ctrl_result **result,
		u8 *result_ptr);

/*!
 * @brief Utility function to parse the capabilities get result
 *
 * @param[in] msg - pointer to msg
 * 
 * @param[in] len - length of message
 * 
 * param[in/out] result_ptr - pointer in the buffer that holds the result information 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t virt_ipsec_msg_capabilities_get_parse_result(
	u8 *msg, u32 len,
	struct virtio_ipsec_ctrl_result **result,
	struct virtio_ipsec_ctrl_capabilities **caps, 
	u8 *result_ptr);

/*!
 * @brief Utility function to parse the group add result
 *
 * @param[in] msg - pointer to msg
 * 
 * @param[in] len - length of message
 * 
 * param[in/out] result_ptr - pointer in the buffer that holds the result information 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t virt_ipsec_msg_group_add_parse_result(
	u8 *msg, u32 len, 
	struct virtio_ipsec_ctrl_result **result,
	struct virtio_ipsec_group_add **group,
	u8 *result_ptr);

/*!
 * @brief Utility function to parse the group delete result
 *
 * @param[in] msg - pointer to msg
 * 
 * @param[in] len - length of message
 * 
 * param[in/out] result_ptr - pointer in the buffer that holds the result information 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t virt_ipsec_msg_delete_group_parse_result(
	u8 *msg, u32 len,
	struct virtio_ipsec_ctrl_result **result, u8 *result_ptr);

#endif
