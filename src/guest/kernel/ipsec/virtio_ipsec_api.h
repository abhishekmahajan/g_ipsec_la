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
/*
 * @file virtio_ipsec_api.h
 * 
 * @brief Contains  g_ipsec_api function declarations & definitions
 *
 * @addtogroup VIRTIO_IPSEC
 * @{
*/

#ifndef _VIRTIO_IPSEC_API_H
#define _VIRTIO_IPSEC_API_H

/* To be added into virtio header file */
/*! Macros */
/*! Virtio IPsec Vendor ID and Device ID */
#define VIRTIO_IPSEC_VENDOR_ID 0x1AF4
#define VIRTIO_IPSEC_DEVICE_ID  0x1054


/*! Defintion for invalid group id*/
#define G_IPSEC_LA_GROUP_INVALID	0xffffffff

/*! Maximum version length */
#define G_IPSEC_LA_MAX_VERSION_LENGTH	32


/*! Success and Failure macros */
#define G_IPSEC_LA_FAILURE -1
#define G_IPSEC_LA_SUCCESS 0


/*! Device name maximum size */
#define IPSEC_IFNAMESIZ	16	

/*! Device handle size */
#define G_IPSEC_LA_HANDLE_SIZE	8

/*! Group handle size */
#define G_IPSEC_LA_GROUP_HANDLE_SIZE	8

/*! SA Handle Size */
#define G_IPSEC_LA_SA_HANDLE_SIZE	8


/*! Protocol values for ESP and AH */
#define G_IPSEC_LA_PROTOCOL_ESP	50
#define G_IPSEC_LA_PROTOCOL_AH 51


/*! Enumerations */

/*! Accelerator Modes */
enum g_ipsec_la_mode {
	G_IPSEC_LA_INSTANCE_AVAILABLE=0, /**< Available for use*/
	G_IPSEC_LA_INSTANCE_EXCLUSIVE=1, /**< Exclusive Mode */
	G_IPSEC_LA_INSTANCE_SHARED	/**< Shared Mode */
};

/*! Control Flags */
enum g_ipsec_la_control_flags
{
	G_IPSEC_LA_CTRL_FLAG_ASYNC = BIT(0), /**< If Set, API call be asynchronous. Otherwise, API call will be synchronous */
	G_IPSEC_LA_CTRL_FLAG_NO_RESP_EXPECTED = BIT(1), /**< If set, no response is expected for this API call */
}; 


/*! Authentication Algorithms */
enum g_ipsec_la_auth_alg {
	G_IPSEC_LA_AUTH_ALGO_NONE=1,	/**< No Authentication */
	G_IPSEC_LA_AUTH_ALGO_MD5_HMAC,   /**< MD5 HMAC Authentication Algo. */
	G_IPSEC_LA_AUTH_ALGO_SHA1_HMAC,  /**< SHA1 HMAC Authentication Algo. */
	G_IPSEC_LA_AUTH_AESXCBC,	/**< AES-XCBC Authentication Algo. */
	G_IPSEC_LA_AUTH_ALGO_SHA2_256_HMAC, /**< SHA2 HMAC Authentication Algorithm; 256 bit key length */
	G_IPSEC_LA_AUTH_ALGO_SHA2_384_HMAC, /**< SHA2 HMAC Authentication Algorithm with 384 bit key length */
	G_IPSEC_LA_AUTH_ALGO_SHA2_512_HMAC, /**< SHA2 HMAC Authentication Algorithm with 512 bit key length */
	G_IPSEC_LA_AUTH_ALGO_HMAC_SHA1_160 /**< SHA1 160 HMAC Algorithm */
};

/*! Cipher Algorithms */
enum g_ipsec_la_cipher_alg {
	G_IPSEC_LA_CIPHER_ALGO_NULL=1, /**< NULL Encryption algorithm */
	G_IPSEC_LA_ALGO_DES_CBC,	/**< DES-CBC Encryption Algorithm */
	G_IPSEC_LA_ALGO_3DES_CBC, /**< 3DES_CBC Encryption Algorithm */
	G_IPSEC_LA_ALGO_AES_CBC, /**< AES_CBC  Algorithm */
	G_IPSEC_LA_ALGO_AES_CTR, /**< AES_CTR Algorithm */
	G_IPSEC_LA_ALGO_COMB_AES_CCM, /**< AES-CCM */
	G_IPSEC_LA_ALGO_COMB_AES_GCM,	/**< AES-GCM */
	G_IPSEC_LA_ALGO_COMB_AES_GMAC	/**< AES-GMAC */
};

/*! Compression Algorithms */
enum g_ipsec_la_ipcomp_alg {
	G_IPSEC_LA_IPCOMP_DEFLATE=1, /**< Deflate IP Compression Algorithm */
	G_IPSEC_LA_IPCOMP_LZS /**< LZS IP Compression Algorithm */
};

/*! DSCP Handle flags */
enum g_ipsec_la_dscp_handle {
	G_IPSEC_LA_DSCP_COPY=1, /**< copy from inner header to tunnel outer header */
	G_IPSEC_LA_DSCP_CLEAR,	/**< Clear the DSCP value in outer header */
	G_IPSEC_LA_DSCP_SET,	/**< Set the DSCP value in outer header to specific value */
};

/*! DF Handle flags */
enum g_ipsec_la_df_handle {
	G_IPSEC_LA_DF_COPY=1, /**< Copy DF bit from inner to outer */
	G_IPSEC_LA_DF_CLEAR, /**< Clear the DF bit in outer header */
	G_IPSEC_LA_DF_SET	/**< Set the bit in the outer header */
};

/*! SA direction */
enum g_ipsec_la_sa_direction {
	G_IPSEC_LA_SA_INBOUND, /**< Inbound SA */
	G_IPSEC_LA_SA_OUTBOUND /**< Outbound SA */
};

/*! SA Flags */
enum g_ipsec_la_sa_flags
{
	G_IPSEC_LA_SA_DO_UDP_ENCAP_FOR_NAT_TRAVERSAL = BIT(1), /**< UDP Encapsulation for Nat Traversal */
	G_IPSEC_LA_SA_USE_ECN = BIT(2), /**< Extended Congestion Notification */
	G_IPSEC_LA_SA_LIFETIME_IN_KB = BIT(3), /**< Lifetime in Kilobytes */
	G_IPSEC_LA_SA_DO_ANTI_REPLAY_CHECK = BIT(4), /**< Anti replay check */
	G_IPSEC_LA_SA_ENCAP_TRANSPORT_MODE = BIT(5), /**< transport mode */
	G_IPSEC_LA_SA_USE_ESN=BIT(6), /**< Extended Sequence Number support */
	G_IPSEC_LA_SA_USE_IPv6=BIT(7), /**< IPv6 Support */
	G_IPSEC_LA_NOTIFY_LIFETIME_KB_EXPIRY=BIT(8), /**< Lifetime kilobyte expiry notification */
	G_IPSEC_LA_NOTIFY_SEQNUM_OVERFLOW=BIT(9), /**< Sequence Number Overflow notification */
	G_IPSEC_LA_NOTIFY_SEQNUM_PERIODIC=BIT(10) /**< Sequence Number periodic notification */
};

/*! Inbound SA flags */
enum g_ipsec_la_inb_sa_flags {
	G_IPSEC_INB_SA_PROPOGATE_ECN =1
	/**< When set, ENC from outer tunnel packet will be propagated to the decrypted packet */
};

/*! SA Modification: Replay */
enum g_ipsec_la_sa_modify_replay_info_flags {
	G_IPSEC_LA_SA_MODIFY_SEQ_NUM= BIT(1), /**< Sequence number is being updated */
	G_IPSEC_LA_SA_MODIFY_ANTI_REPLAY_WINDOW = BIT(2) /**< Anti-replay window is being updated */
};


/*! SA Get Operations */
enum g_ipsec_la_sa_get_op {
	G_IPSEC_LA_SA_GET_FIRST_N = 0, /**< Get First n SAs */
	G_IPSEC_LA_SET_GET_NEXT_N, /**< Get Next N SAs */
	G_IPSEC_LA_SA_GET_EXACT /**< Get Exact SA */
};

/*! IP Version */
enum g_ipsec_la_ip_version {
        G_IPSEC_LA_IPV4 = 4, /**< IPv4 Version */
        G_IPSEC_LA_IPV6 = 6 /**< IPv6 Version */
};

/*! Group Create Inargs */
struct g_ipsec_la_group_create_inargs {
	char *group_identity;	/**< Group identity */
};


/*! Group Create Outargs */
struct g_ipsec_la_group_create_outargs {
	int32_t result; /**< result of the operation */
	u8 group_handle[G_IPSEC_LA_GROUP_HANDLE_SIZE]; /**< Group handle holder */
};


/*! Group Delete Outargs */
struct g_ipsec_la_group_delete_outargs {
	int32_t result; /**< result of the operation */
};

/*! Handles */
struct g_ipsec_la_handle {
	u8 handle[G_IPSEC_LA_HANDLE_SIZE]; /**< Accelerator handle */
	u8 group_handle[G_IPSEC_LA_GROUP_HANDLE_SIZE]; /**< Group handle */
};

/*! Callback Notification Prototype when connection to accelerator is broken */
typedef void (*g_ipsec_la_instance_broken_cbk_fn)(struct g_ipsec_la_handle *handle,  void *cb_arg);

/*! Accelerator Open inArgs */
struct g_ipsec_la_open_inargs {
	uint16_t pci_vendor_id; /**< PCI Vendor ID 0x1AF4 */
	uint16_t device_id;   /**< Device Id for IPsec */
	char *accl_name; /**< Accelerator name */
	char *app_identity;	/**< Application identity */
	g_ipsec_la_instance_broken_cbk_fn cb_fn;	/**< Callback function to be called when the connection to the underlying accelerator is broken */
	void *cb_arg;	/**< Callback argument */
	int32_t cb_arg_len;	/**< Callback argument length */
};

/*! Accelerator Open OutArgs */
struct g_ipsec_la_open_outargs{
	 struct g_ipsec_la_handle *handle; /**< handle */
};

/*! Asynchronous response callback function prototype */
typedef void(*g_ipsec_la_resp_cbfn) (void *cb_arg, int32_t cb_arg_len, void *outargs);

/*! Asynchronous response callback function, callback argument */
struct g_ipsec_la_resp_args {
	g_ipsec_la_resp_cbfn cb_fn; 
	/**< Callback function if  ASYNC flag is chosen */
	void *cb_arg; /**< Callback Argument */
	int32_t cb_arg_len; /**< Callback argument length */
};  


/*! Get Available devices inArgs */
struct g_ipsec_la_avail_devices_get_inargs 
{
	uint32_t num_devices; /**< Number of devices to get */
	char *last_device_read; 
	/**< NULL if this is the first time this call is invoked;
          Subsequent calls will have a valid value here */											  
};

/*! Device information */ 
struct g_ipsec_la_device_info
{
	char device_name[IPSEC_IFNAMESIZ]; /**< Device name */
	u8 mode; /* Shared or Available */ /**< Device mode */
	u32 num_apps; /**< If shared, number of apps sharing the accelerator */
};

/*! Avaialble devices get outArgs */
struct g_ipsec_la_avail_devices_get_outargs
{
	uint32_t num_devices; /**< number of devices to get */
	struct g_ipsec_la_device_info *dev_info; 						
	/**< Array of pointers, where each points to
	    device specific information */
	char *last_device_read; 
	/**< Send a value that the application can use and
	  * invoke for the next set of devices */
	bool b_more_devices;
	/**< Set if more devices are available */
};


/*! SA Handle */
struct g_ipsec_la_sa_handle {
	u8 ipsec_sa_handle[G_IPSEC_LA_SA_HANDLE_SIZE]; /**< SA Handle */
};


/*! Authentication Algorithm capabilities */
struct g_ipsec_la_auth_algo_cap {
	uint32_t		md5:1, /**< MD5 */
			sha1:1, /**< SHA1 */
			sha2:1, /**< SHA2 */
			aes_xcbc:1, /**< AES_XCBC */
			none:1; /**< No authentication */
};			 


/*! Cipher Algorithm Capabilities */
struct g_ipsec_la_cipher_algo_cap {
	uint32_t		des:1, /**< DES */
			des_3:1, /**< Triple DES */
			aes:1, /**< AES */
			aes_ctr:1, /**< AES_CTR */
			null:1; /**< Null Encryption */
};

/*! Combined mode algorithm capabilities */
struct g_ipsec_la_comb_algo_cap {
	uint32_t		aes_ccm:1, /**< AES_CCM */
			aes_gcm:1, /**< AES_GCM */
			aes_gmac:1; /**< AES_GMAC */
};

/*! Accelerator capabilities */
struct g_ipsec_la_capabilities {
	uint32_t sg_features:1, /**< Scatter-Gather Support for I/O */
		ah_protocol:1,	/**< AH Protocol */
		esp_protocol:1,	/**< ESP protocol */
		wesp_protocol:1,	/**< WESP Protocol */
		ipcomp_protocol:1,	/**< IP	Compression */
		multi_sec_protocol:1,	/**< SA Bundle support */
		udp_encap:1,	/**< UDP Encapsulation */
		esn:1,	/**< Extended Sequence Number support */
		tfc:1,	/**< Traffic Flow Confidentiality */
            ecn:1,	/**< Extended Congestion Notification */
		df:1,		/**< Fragment bit handling */
		anti_replay_check:1,	/**< Anti Replay check */
		ipv6_support:1,	/**< IPv6 Support */
		soft_lifetime_bytes_notify:1,	/**< Soft Lifetime Notify Support */
		seqnum_overflow_notify:1,	/**< Seq Num Overflow notify */
		seqnum_periodic_notify:1;	/**< Seq Num Periodic Notify */
	struct g_ipsec_la_auth_algo_cap auth_algo_caps; /**< Authentication algo capabilites */
	struct g_ipsec_la_cipher_algo_cap cipher_algo_caps; /**< Cipher Algo capabilities */
	struct g_ipsec_la_comb_algo_cap comb_algo_caps; /**< Combined Algo capabilities */
};

/*! Accelerator Capabilities Get OutArgs */
struct g_ipsec_la_cap_get_outargs
{
	int32_t result; /**< Non zero value: Success, Otherwise failure */
	struct g_ipsec_la_capabilities caps; /**< Capabilities */
};

/*! data structure to accompany for sequence number notification */
struct g_ipsec_seq_number_notification { 
	struct g_ipsec_la_handle *handle; /**< Accelerator Handle */
	struct g_ipsec_la_sa_handle *sa_handle; /**< SA Handle */
	uint32_t seq_num;	/**< Low Sequence Number */
	uint32_t hi_seq_num; /**< High Sequence Number */
};


/*! Callback function prototype that application can provide to receive sequence number overflow notifications from underlying accelerator */
typedef void (*g_ipsec_la_cbk_sa_seq_number_overflow_fn) (
	struct g_ipsec_la_handle handle,  
	struct g_ipsec_seq_number_notification *in);


/*! Callback function prototype that application can provide to receive sequence number periodic notifications from underlying accelerator */
typedef void (*g_ipsec_la_cbk_sa_seq_number_periodic_update_fn) (
	struct g_ipsec_la_handle handle,
	struct g_ipsec_seq_number_notification *in);


/*! Data structure to accompany for liftime expiry notification */
struct g_ipsec_la_lifetime_in_bytes_notification {
	struct g_ipsec_la_sa_handle sa_handle;	/**< SA Handle */
	uint32_t ipsec_lifetime_in_kbytes;	/**< Lifetime in Kilobytes */
};

/*! Callback function prototype that application can provide to receive soft lifetime out expiry from underlying accelerator */
typedef void (*g_ipsec_la_cbk_sa_soft_lifetimeout_expiry_fn) (
	struct g_ipsec_la_handle handle,
	struct g_ipsec_la_lifetime_in_bytes_notification *in);


/*! Structure to hold notification callback functions */
struct g_ipsec_la_notification_hooks
{
	/**< Sequence Number Overflow callback function */
	struct g_ipsec_la_cbk_sa_seq_number_overflow_fn *seq_num_overflow_fn;
	/**< Sequence Number periodic Update Callback function */
	struct g_ipsec_la_cbk_sa_seq_number_periodic_update_fn *seq_num_periodic_update_fn;
	/**< Soft lifetime in Kilobytes expiry function */
	struct g_ipsec_la_cbk_sa_soft_lifetimeout_expiry_fn *soft_lifetimeout_expirty_fn;
	
	/**< Sequence number Overflow callback function argument and length */
	void *seq_num_overflow_cbarg;
	u32 seq_num_overflow_cbarg_len;
	
	/**< Periodic sequence number notification callback function argument and length */
	void *seq_num_periodic_cbarg;
	u32 seq_num_periodic_cbarg_len;
	
	/**< Soft lifetimeout callback notification function argument and length */
	void *soft_lifetimeout_cbarg;
	u32 soft_lifetimeout_cbarg_len;
};
	

/*! Structure to hold SA crypto parameters */
struct g_ipsec_la_sa_crypto_params
{
	u8  reserved:4, /**< reserved, for future use */
		bAuth:1, /**< Authentication */
		bEncrypt:1; /**< Encryption */	
	enum g_ipsec_la_auth_alg auth_algo; /**< Authentication Algorithm */
	uint8_t *auth_key; /**< Authentication Key */
	uint32_t auth_key_len_bits; /**< Key Length in bits */
	enum g_ipsec_la_cipher_alg cipher_algo;	/**< Cipher Algorithm */
	uint8_t *cipher_key;	/**< Cipher Key */
	u32 block_size; /**< block size */
	uint32_t cipher_key_len_bits;	/**< Cipher Key Length in bits */
	uint8_t *iv;	/**< IV Length */
	uint8_t iv_len_bits; 	/**< IV length in bits */
	uint8_t icv_len_bits;	/**< ICV  Integrity check value size in bits */
};

/*! IP Compression information */
struct g_ipsec_la_ipcomp_info
{
	enum g_ipsec_la_ipcomp_alg	algo; /**< Algorithm */
	uint32_t cpi; /**< compression index */
};

/*! IPv6 Address */
struct g_ipsec_la_ipv6_addr{        
#define G_IPSEC_LA_IPV6_ADDRU8_LEN 16  /**< address as bytes */      
#define G_IPSEC_LA_IPV6_ADDRU32_LEN 4 /**< address as integers */
	union {
		uint8_t b_addr[G_IPSEC_LA_IPV6_ADDRU8_LEN]; /**< byte stream */
        	uint32_t w_addr[G_IPSEC_LA_IPV6_ADDRU32_LEN]; /**< array of integers */
     };
};

/*! IP Address */
struct g_ipsec_la_ip_addr {
	enum g_ipsec_la_ip_version version; /**< Version v4/v6 */
	union {
		uint32_t ipv4; /**< IPv4 address */
 		struct g_ipsec_la_ipv6_addr ipv6; /**< IPv6 Address */
    };
};

/*! Tunnel address */
struct g_ipsec_la_tunnel_end_addr {
	struct g_ipsec_la_ip_addr		src_ip;	/**< Source Address */
	struct g_ipsec_la_ip_addr		dest_ip; /**< Destination Address */
};

/*! NAT Traversal information */
struct g_ipsec_la_nat_traversal_info {
	uint16_t dest_port; /**< Destination Port */
	uint16_t src_port; /**< Source Port */
	struct g_ipsec_la_ip_addr nat_oa_peer_addr; /**< Original Peer Address; valid if encapsulation Mode is transport */
};

/*! SA */
struct g_ipsec_la_sa
{
	uint32_t spi; /**< Security Parameter Index */
	uint8_t proto; /**< ESP, AH or IPCOMP */
	enum g_ipsec_la_sa_flags cmn_flags;	/**< Flags such as Anti-replay check, ECN etc */
	uint32_t anti_replay_window_size; /**< anti replay window size */
	union {
		struct  {
			uint8_t dscp; /**< DSCP value  valid when dscp_handle is set to copy */
			enum g_ipsec_la_df_handle df_bit_handle; /**< DF set, clear or propogate */
			enum g_ipsec_la_dscp_handle dscp_handle;   /**< DSCP handle set, clear etc. */
			
		}outb;
		struct {
			enum g_ipsec_la_inb_sa_flags flags;	/**< Flags specific to inbound SA */
	   }inb;
	};
	struct g_ipsec_la_sa_crypto_params crypto_params;  /**< Crypto Parameters */
	struct g_ipsec_la_ipcomp_info ipcomp_info;	/**< IP Compression Information */
	uint32_t soft_kilobytes_limit; /**< Soft Kilobytes limit */
	uint32_t hard_kilobytes_limit; /**< Hard Kilobytes limit */
	uint32_t seqnum_interval; /**< Sequence number notification interval */
	struct g_ipsec_la_nat_traversal_info nat_info; /**< NAT Traversal information */
	struct g_ipsec_la_tunnel_end_addr te_addr; /** < Tunnel address */	
};

/*! Add SA Inargs */
struct g_ipsec_la_sa_add_inargs
{
	enum g_ipsec_la_sa_direction dir; /**< SA Direction */
	uint8_t num_sas; /**< Number of SAs */
	struct g_ipsec_la_sa *sa_params; /**< Array of SA Parameters */
};

/*! Add SA outArgs */
struct g_ipsec_la_sa_add_outargs {
	int32_t result; /**< Non zero value: Success, Otherwise failure */
	struct g_ipsec_la_sa_handle handle; /**< SA Handle if SA creation is successful */
};

/*! Enumeration for possible modify options */
enum g_ipsec_la_sa_modify_flags {
	G_IPSEC_LA_SA_MODIFY_LOCAL_GW_INFO= 1, /**< Modify the Local Gateway Information */
	G_IPSEC_LA_SA_MODIFY_PEER_GW_INFO, /**< Modify the Remote Gateway Information */
	G_IPSEC_LA_SA_MODIFY_REPLAY_INFO, /**< SA will be updated with Sequence number, window bit map etc. */
};


/*! SA Modify inArgs */
struct g_ipsec_la_sa_mod_inargs
{
	enum g_ipsec_la_sa_direction dir; /**< Inbound or Outbound */
	struct g_ipsec_la_sa_handle *handle; /**< SA Handle */
	enum g_ipsec_la_sa_modify_flags flags; /**< Flags that indicate what needs to  be updated */
	union {
		struct {
			uint16_t port; /**< New Port */
			struct g_ipsec_la_ip_addr addr;  /**< New IP Address */
		}addr_info; /**< Valid when Local or Remote Gateway Information is modified */
		struct  {
			enum g_ipsec_la_sa_modify_replay_info_flags flags; /**< Flag indicates which parameters are being modified */
			uint8_t anti_replay_window_size; /**< Anti replay window size is being modified */
			uint32_t anti_replay_window_bit_map; /**< Window bit map array is being updated */
			uint32_t seq_num; /**< Sequence Number is being updated */
			uint32_t hi_seq_num; /**< Higher order Sequence number, when Extended Sequence number is used */
		}replay; /**< Valid when SA_MODIFY_REPLAY_INFO is set */
	};
};

/*! SA Modify outArgs */
struct g_ipsec_la_sa_mod_outargs
{
	int32_t result; /**< 0 Success; Non zero value: Error code indicating failure */
};

/*! SA Delete inArgs */
struct g_ipsec_la_sa_del_inargs
{
	enum g_ipsec_la_sa_direction  dir; /**< Input or Output */
	struct g_ipsec_la_sa_handle *handle; /**< SA Handle */
};

/*! SA Delete outArgs */
struct g_ipsec_la_sa_del_outargs
{
	int32_t result; /**< 0 success, Non-zero value: Error code indicating failure */
};

/*! SA flush outArgs */
struct g_ipsec_la_sa_flush_outargs {
	int32_t result; /**< 0 for success */
};


/*! SA Statistics */
struct g_ipsec_la_sa_stats {
	uint64_t packets_processed;	/**< Number of packets processed */
	uint64_t bytes_processed; 	/**< Number of bytes processed */
	struct {
		uint32_t invalid_ipsec_pkt; /**< Number of invalid IPSec Packets */
		uint32_t invalid_pad_length; /**< Number of packets with invalid padding length */
		uint32_t invalid_seq_num; /**< Number of packets with invalid sequence number */
		uint32_t anti_replay_late_pkt; /**< Number of packets that failed anti-replay check through late arrival */
		uint32_t anti_replay_replay_pkt; /**< Number of replayed packets */
		uint32_t invalid_icv;	/**< Number of packets with invalid ICV */
		uint32_t seq_num_over_flow; /**< Number of packets with sequence number overflow */
		uint32_t crypto_op_failed; /**< Number of packets where crypto operation failed */
	}protocol_violation_errors;

	struct {
		uint32_t no_tail_room; /**< Number of packets with no tail room required for padding */
		uint32_t submit_to_accl_failed; /**< Number of packets where submission to underlying hardware accelerator failed */
	}process_errors;  
};


/*! SA Get outArgs*/
struct g_ipsec_la_sa_get_outargs {
	int32_t result; /**< 0: Success: Non zero value: Error code indicating failure */
	struct g_ipsec_la_sa *sa_params; /**< An array of sa_params[] to hold num_sas information */
	struct g_ipsec_la_sa_stats *stats; /**< An array of stats[] to hold the statistics */
	struct g_ipsec_la_sa_handle ** handle; /**< handle returned to be used for subsequent Get Next N call */
};


/*! SA Get inArgs */
struct g_ipsec_la_sa_get_inargs {
	enum g_ipsec_la_sa_direction dir; /**< Direction: Inbound or Outbound */
	/**< Following field is not applicable for get_first */
	struct g_ipsec_la_sa_handle *handle;
	enum g_ipsec_la_sa_get_op operation; /**< Get First, Next or Exact */
	uint32_t num_sas; /**< Number of SAs to read */
	uint32_t flags; /**< flags indicate to get complete SA information or only Statistics */
};

/*! Data buffer */
struct g_ipsec_la_data {
	uint8_t *buffer;	/**< Buffer pointer */
	uint32_t length;	/**< Buffer length */
};


/*! Function prototypes */
/*! 
 * @brief This API returns the API version.
 *
 * @param[in/out] version - Version string
 * 
 * @returns SUCCESS upon SUCCESS or FAILURE 
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t g_ipsec_la_get_api_version(char *version);

/*! 
 * @brief Get the number of available devices 
 *
 * @param[in/out] nr_devices - Number of devices 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t g_ipsec_la_avail_devices_get_num(uint32_t *nr_devices); 

/*!
 * @brief  Get the avaialble device info  
 *
 * @param[in] in -  Pointer to input structure
 *
 * @param[out] out - Pointer to output structure containing device information
 *
 * @returns SUCCESS upon SUCCESS or failure 
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t g_ipsec_la_avail_devices_get_info(
	struct g_ipsec_la_avail_devices_get_inargs *in,
	struct g_ipsec_la_avail_devices_get_outargs *out);


/*! 
 * @brief Open an accelerator instance in either exclusive or shared mode 
 *
 * @param[in] mode - Mode exclusive or mode shared
 * 
 * @param[in] in - Pointer to input structure
 *
 * @param[out] out -Pointer to output structure with accelerator handle 
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t g_ipsec_la_open(
	enum g_ipsec_la_mode mode, /* Mode = EXCLUSIVE OR SHARED */
	struct g_ipsec_la_open_inargs *in,
	struct g_ipsec_la_open_outargs *out);


/*!
 * @brief Create a logical group
 *
 * @param[in] handle- Accelerator handle 
 *
 * @param[in]  in - Pointer to input structure
 *
 * @param[in] flags - API Behavior flags
 *
 * @param[out] out -Pointer to output structure with group handle 
 *  
 * @param[in] resp - Response arguments for asynchronous call 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t g_ipsec_la_group_create(
	struct g_ipsec_la_handle *handle, 
	/* handle should be valid one */
	struct g_ipsec_la_group_create_inargs *in,
	enum g_ipsec_la_control_flags flags,
	struct g_ipsec_la_group_create_outargs *out,
	struct g_ipsec_la_resp_args *resp);

 
/*!
 * @brief Delete a logical group
 *
 * @param[in] handle- Accelerator handle, group handle 
 *
 * @param[in] flags - API Behavior flags
 *
 * @param[out] out -Pointer to output structure 
 *  
 * @param[in] resp - Response arguments for asynchronous call 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t g_ipsec_la_delete_group(
	struct g_ipsec_la_handle *handle,
	enum g_ipsec_la_control_flags flags,
	struct g_ipsec_la_group_delete_outargs *out,
	struct g_ipsec_la_resp_args *resp
	);

/*!
 * @brief Close a previously opened accelerator  
 *
 * @param[in] handle- Accelerator handle 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t g_ipsec_la_close(struct g_ipsec_la_handle *handle);

/*!
 * @brief Get the capabilities of accelerator
 *
 * @param[in] handle- Accelerator handle 
 *
 * @param[in] flags - API Behavior flags
 *
 * @param[out] out -Pointer to output structure with accelerator capabilities 
 *  
 * @param[in] resp - Response arguments for asynchronous call 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t g_ipsec_la_capabilities_get(
	struct g_ipsec_la_handle *handle,
	enum g_ipsec_la_control_flags flags, 
	struct g_ipsec_la_cap_get_outargs *out, 
	struct g_ipsec_la_resp_args *resp);

/*!
 * @brief Register for notifications
 *
 * @param[in] handle- Accelerator handle, group handle 
 *
 * @param[in]  in - Pointer to input structure containing notitication callback function and arguments
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t g_ipsec_la_notification_hooks_register(
	struct g_ipsec_la_handle *handle, 
	const struct g_ipsec_la_notification_hooks *in
);

/*!
 * @brief De-register for notifications
 *
 * @param[in] handle- Accelerator handle , group handle
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t g_ipsec_la_notifications_hook_deregister( 
	struct g_ipsec_la_handle  *handle/* Accelerator Handle */ );

/*!
 * @brief Add a SA
 *
 * @param[in] handle- Accelerator handle , group handle
 *
 * @param[in]  in - Pointer to input structure
 *
 * @param[in] flags - API Behavior flags
 *
 * @param[out] out -Pointer to output structure with SA handle 
 *  
 * @param[in] resp - Response arguments for asynchronous call 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t g_ipsec_la_sa_add(
	 	struct g_ipsec_la_handle *handle,
        const struct g_ipsec_la_sa_add_inargs *in,
        enum g_ipsec_la_control_flags flags,
        struct g_ipsec_la_sa_add_outargs *out,
        struct g_ipsec_la_resp_args *resp);

/*!
 * @brief Modify SA
 *
 * @param[in] handle- Accelerator handle, group handle 
 *
 * @param[in]  in - Pointer to input structure
 *
 * @param[in] flags - API Behavior flags
 *
 * @param[out] out -Pointer to output structure 
 *  
 * @param[in] resp - Response arguments for asynchronous call 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t g_ipsec_la_sa_mod(
	 struct g_ipsec_la_handle *handle, 
	 const struct g_ipsec_la_sa_mod_inargs *in, 
     	 enum g_ipsec_la_control_flags flags, 
     	 struct g_ipsec_la_sa_mod_outargs *out, 
         struct g_ipsec_la_resp_args *resp 
        );

/*!
 * @brief Delete a SA
 *
 * @param[in] handle- Accelerator handle, group handle 
 *
 * @param[in]  in - Pointer to input structure
 *
 * @param[in] flags - API Behavior flags
 *
 * @param[out] out -Pointer to output structure with group handle 
 *  
 * @param[in] resp - Response arguments for asynchronous call 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t g_ipsec_la_sa_del(
	struct g_ipsec_la_handle *handle,
       const struct g_ipsec_la_sa_del_inargs *in,
       enum g_ipsec_la_control_flags flags,
       struct g_ipsec_la_sa_del_outargs *out,
       struct g_ipsec_la_resp_args *resp);


/*!
 * @brief Flush all SAs
 *
 * @param[in] handle- Accelerator handle, group handle 
 *
 * @param[in] flags - API Behavior flags
 *
 * @param[out] out -Pointer to output structure  
 *  
 * @param[in] resp - Response arguments for asynchronous call 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t g_ipsec_la_sa_flush(
	struct g_ipsec_la_handle *handle,
	enum g_ipsec_la_control_flags flags,
	struct g_ipsec_la_sa_flush_outargs *out,
	struct g_ipsec_la_resp_args *resp);


/*!
 * @brief Read or Get SA(s)
 *
 * @param[in] handle- Accelerator handle, group handle
 *
 * @param[in]  in - Pointer to input structure
 *
 * @param[in] flags - API Behavior flags
 *
 * @param[out] out -Pointer to output structure with SA(s) information
 *  
 * @param[in] resp - Response arguments for asynchronous call 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t g_ipsec_la_sa_get(
	struct g_ipsec_la_handle *handle,
	const struct g_ipsec_la_sa_get_inargs *in,
	enum g_ipsec_la_control_flags flags,
	struct g_ipsec_la_sa_get_outargs *out,
	struct g_ipsec_la_resp_args *resp);



/*!
 * @brief Packet Encapsulation 
 *
 * @param[in] handle - accelerator handle, group handle 
 * 
 * @param[in] flags - API flags
 * 
 * param[in] sa_handle - SA handle 
 *
 * param[in] num_sg_elem - number of scatter gather elements 
 * 
 * param[in] in_data - input data
 *
 * param[out] out_data - modified data (encrypted)
 *
 * @param[in] resp - Response arguments for asynchronous call 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t g_ipsec_la_packet_encap(
	struct g_ipsec_la_handle *handle, 
	enum g_ipsec_la_control_flags flags,
	struct g_ipsec_la_sa_handle *sa_handle, 
	uint32_t num_sg_elem, 
	struct g_ipsec_la_data in_data[],
	struct g_ipsec_la_data out_data[], 
	struct g_ipsec_la_resp_args *resp
	);

/*!
 * @brief Packet Decapsulation 
 *
 * @param[in] handle - accelerator handle, group handle 
 * 
 * @param[in] flags - API flags
 * 
 * param[in] sa_handle - SA handle 
 *
 * param[in] num_sg_elem - number of scatter gather elements 
 * 
 * param[in] in_data - input data
 *
 * param[out] out_data - modified data (encrypted)
 *
 * @param[in] resp - Response arguments for asynchronous call 
 *
 * @returns SUCCESS upon SUCCESS or FAILURE
 *
 * @ingroup VIRTIO_IPSEC
 */
int32_t	g_ipsec_la_packet_decap(
	struct g_ipsec_la_handle *handle, 
	enum g_ipsec_la_control_flags flags,
	struct g_ipsec_la_sa_handle *sa_handle,
	uint32_t num_sg_elem,
	struct g_ipsec_la_data in_data[],
	struct g_ipsec_la_data out_data[], 
	struct g_ipsec_la_resp_args *resp
	);

/* Todo: 
 1.  Map APIs to Virtio calls 
 2.  Version implementation
 3.  SA handle and group handle to be 8 bit in virtio messages
*/

#endif
	

