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
//#include "../../kernel/ipsec/virtio_ipsec_api.h"
#include "virtio_ipsec_api.h"
#include "virtio_ipsec_msg.h"
//#include "../../kernel/ipsec/virtio_ipsec.h"
#include "virtio_ipsec.h"

#define VIRTIO_IPSEC_MSG_DEBUG	printk
#if 0
struct virtio_ipsec_ctrl_hdr {
	u8 class;  /* class of command */
	u8 cmd;   /* actual command */
}; 

struct virtio_ipsec_ctrl_result {
	u8 result;	/* VIRTIO_IPSEC_OK or VIRTIO_IPSEC_ERR */
	u8 result_data; /* error information if any */
};

enum virtio_ipsec_ctrl_command_class
{
	VIRTIO_IPSEC_CTRL_GENERIC= 1,	
	/* Generic Commands such as Get/Set Capabilities, Set Endianness etc. */
	VIRTIO_IPSEC_CTRL_SA,		
	/* Class of commands to add/modify/delete SA */
	VIRTIO_IPSEC_CTRL_GET_RAND_DATA,	
	/* Class of commands to get random data */
	VIRTIO_IPSEC_CTRL_ADVANCED	
	/* Any vendor specific or advanced commands */
};

/* SA Commands */
enum virtio_ipsec_ctrl_command_class_sa
{
	VIRTIO_IPSEC_CTRL_ADD_GROUP=1,  
	/* Add a group */
	VIRTIO_IPSEC_CTRL_DELETE_GROUP, 
	/* Delete a group */
	VIRTIO_IPSEC_CTRL_ADD_OUT_SA,	
	/* Add an outbound SA - Encapsulation */ 
	VIRTIO_IPSEC_CTRL_DEL_OUT_SA,	
	/* Delete Outbound SA */
	VIRTIO_IPSEC_CTRL_UPDATE_OUT_SA,	
	/* Update Outbound SA */
	VIRTIO_IPSEC_CTRL_READ_OUT_SA,	
	/* Read Outbound SA */
	VIRTIO_IPSEC_CTRL_READ_FIRST_N_OUT_SAs, 
	/* Read first N outbound SAs */
	VIRTIO_IPSEC_CTRL_READ_NEXT_N_OUT_SAs,	
	/* Read next N Out SAs */
	VIRTIO_IPSEC_CTRL_ADD_IN_SA,	
	/* Add an inbound SA - Decapsulation */
	VIRTIO_IPSEC_CTRL_DEL_IN_SA,	
	/* Delete Inbound SA */
	VIRTIO_IPSEC_CTRL_UPDATE_IN_SA,	
	/* Update Inbound SA */
	VIRTIO_IPSEC_CTRL_READ_IN_SA,	
	/* Read Inbound SA */
	VIRTIO_IPSEC_CTRL_READ_FIRST_N_IN_SAs,	
	/* Read first N SAs */
	VIRTIO_IPSEC_CTRL_READ_NEXT_N_IN_SAs,	
	/* Read Next N SAs */
	VIRTIO_IPSEC_CTRL_FLUSH_SA,	
	/* Flush SAs within a group */
	VIRTIO_IPSEC_CTRL_FLUSH_SA_ALL 
	/* Flush all SAs */
};

	

struct virtio_ipsec_create_group{
	u32	group_handle[VIRTIO_IPSEC_GROUP_HANDLE_SIZE]; /* Output */
}__attribute__((packed));

#endif

#define VIRT_MSG_GET_HDR(msg, hdr)	\
	hdr = ((virtio_ipsec_ctrl_hdr *)msg



/* allocate and populate the message */
int32_t  virt_ipsec_msg_group_add(
	u32 *len, u8 **msg, u8 **result_ptr)
{
	struct virtio_ipsec_ctrl_hdr *hdr;
	//struct virtio_ipsec_ctrl_result *result;
	//struct virtio_ipsec_group_add *group;

	u8 *buf; 
	*len = sizeof(struct virtio_ipsec_ctrl_hdr) +
		sizeof(struct virtio_ipsec_group_add) +
		sizeof(struct virtio_ipsec_ctrl_result);
	
	buf = kzalloc(*len, GFP_KERNEL);
	if (!buf) {
		return -ENOMEM;
	}
	
	hdr = (struct virtio_ipsec_ctrl_hdr *)buf;
	//group = (virtio_ipsec_group_add *)((u8 *)(buf + sizeof(struct virtio_ipsec_ctrl_hdr));
	//result = (virtio_ipsec_ctrl_result *)((u8 *)(group + sizeof(struct virtio_ipsec_group_add));

	hdr->class = VIRTIO_IPSEC_CTRL_SA;
	hdr->cmd = VIRTIO_IPSEC_CTRL_ADD_GROUP;

	*result_ptr = (u8 *)hdr+ 
		sizeof(struct virtio_ipsec_group_add)+
		sizeof(struct virtio_ipsec_ctrl_hdr);

	*msg = buf;

	return VIRTIO_IPSEC_SUCCESS;
		
}

int32_t virt_ipsec_msg_delete_group_parse_result(
	u8 *msg, u32 len,
	struct virtio_ipsec_ctrl_result **result, u8 *result_ptr)
{
	*result = (struct virtio_ipsec_ctrl_result *)result_ptr;

	return VIRTIO_IPSEC_SUCCESS;
}


int32_t virt_ipsec_msg_group_add_parse_result(
	u8 *msg, u32 len, 
	struct virtio_ipsec_ctrl_result **result,
	struct virtio_ipsec_group_add **group,
	u8 *result_ptr)
{
	if (len < (sizeof(struct virtio_ipsec_ctrl_hdr)+sizeof(struct virtio_ipsec_ctrl_result)
			+ sizeof(struct virtio_ipsec_group_add)))
	{
		VIRTIO_IPSEC_MSG_DEBUG("%s:%s:%d Parse result length is invalid: %d\n", 
			__FILE__, __func__, __LINE__, len);
		return VIRTIO_IPSEC_FAILURE;
	}

	*group = (struct virtio_ipsec_group_add *)(
		(u8 *)(msg) + sizeof(struct virtio_ipsec_ctrl_hdr));

	*result = (struct virtio_ipsec_ctrl_result *)result_ptr;

	return VIRTIO_IPSEC_SUCCESS;
}

int32_t virt_ipsec_msg_sa_add_parse_result(
	u8 *msg, u32 len,
	struct virtio_ipsec_ctrl_result **result,
	struct virtio_ipsec_create_sa **v_ipsec_create_sa,
	u8 *result_ptr)
{
	

	*v_ipsec_create_sa = (struct virtio_ipsec_create_sa *)(
		(u8 *)(msg)+sizeof(struct virtio_ipsec_ctrl_hdr));
	*result = (struct virtio_ipsec_ctrl_result *)(result_ptr);
	
	return VIRTIO_IPSEC_SUCCESS;
}

int32_t virt_ipsec_msg_capabilities_get_parse_result(
	u8 *msg, u32 len,
	struct virtio_ipsec_ctrl_result **result,
	struct virtio_ipsec_ctrl_capabilities **caps, 
	u8 *result_ptr)
{
	*result = (struct virtio_ipsec_ctrl_result *)result_ptr;

	*caps = (struct virtio_ipsec_ctrl_capabilities *)
		(msg + sizeof(struct virtio_ipsec_ctrl_hdr));

	return VIRTIO_IPSEC_SUCCESS;
}


int32_t virt_ipsec_msg_sa_mod_parse_result(
		u8 *msg, u32 len,
		struct virtio_ipsec_ctrl_result **result,
		u8 *result_ptr)
{
	*result = (struct virtio_ipsec_ctrl_result *)result_ptr;

	return VIRTIO_IPSEC_SUCCESS;
}

int32_t virt_ipsec_msg_sa_del_parse_result(
	u8 *msg, u32 len,
	struct virtio_ipsec_ctrl_result **result,
	u8 *result_ptr) 
{
	*result = (struct virtio_ipsec_ctrl_result *)result_ptr;
	return VIRTIO_IPSEC_SUCCESS;
}

int32_t virt_ipsec_msg_sa_flush_parse_result(
	u8 *msg, u32 len,
	struct virtio_ipsec_ctrl_result **result,
	u8 *result_ptr) {
		
	*result = (struct virtio_ipsec_ctrl_result *)result_ptr;
	return VIRTIO_IPSEC_SUCCESS;
}	
	


int32_t virt_ipsec_msg_get_capabilities(
	u32 *len, u8 **msg, u8 **result_ptr)
{
	
	struct virtio_ipsec_ctrl_hdr *hdr;
	
	u8 *buf;
	*len = sizeof(struct virtio_ipsec_ctrl_hdr) +
		sizeof(struct virtio_ipsec_ctrl_capabilities) +
		sizeof(struct virtio_ipsec_ctrl_result);

	buf = kzalloc(*len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	hdr = (struct virtio_ipsec_ctrl_hdr *)buf;

	hdr->class = VIRTIO_IPSEC_CTRL_GENERIC;
	hdr->cmd = VIRTIO_IPSEC_CTRL_GET_CAPABILITIES;

	*result_ptr = buf + sizeof(struct virtio_ipsec_ctrl_hdr)+
		sizeof(struct virtio_ipsec_ctrl_capabilities);

	*msg = buf;

	return VIRTIO_IPSEC_SUCCESS;
	
}


#define VIRT_IPSEC_MSG_GROUP_DELETE_SIZE \
	(sizeof(struct virtio_ipsec_ctrl_hdr)+	\
	sizeof(struct virtio_ipsec_group_delete) + \
	sizeof(struct virtio_ipsec_ctrl_result))
	
int32_t virt_ipsec_msg_group_delete(
	u32 *group_handle,
	u32 *len, uint8_t **msg,
	uint8_t **result_ptr)
{
	struct virtio_ipsec_ctrl_hdr *hdr;
	struct virtio_ipsec_group_delete *grp_del;

	u8 *buf;
	*len = VIRT_IPSEC_MSG_GROUP_DELETE_SIZE;
	buf = kzalloc(*len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	hdr = (struct virtio_ipsec_ctrl_hdr *)buf;
	hdr->class = VIRTIO_IPSEC_CTRL_SA;
	hdr->cmd = VIRTIO_IPSEC_CTRL_DELETE_GROUP;

	grp_del = (struct virtio_ipsec_group_delete *)(buf + sizeof(struct virtio_ipsec_ctrl_hdr));
	memcpy(grp_del->group_handle, group_handle,
		VIRTIO_IPSEC_GROUP_HANDLE_SIZE);

	*result_ptr = buf + sizeof(struct virtio_ipsec_ctrl_hdr) +
		sizeof(struct virtio_ipsec_group_delete);
	
	*msg = buf;

	return VIRTIO_IPSEC_SUCCESS;
}

#define VIRTIO_IPSEC_ADD_SA_MSG_SIZE \
	(sizeof(struct virtio_ipsec_ctrl_hdr) +	\
	 sizeof(struct virtio_ipsec_ctrl_result) +	\
	 sizeof(struct virtio_ipsec_create_sa) + \
	 sizeof(struct virtio_ipsec_tunnel_hdr_ipv4)+ \
	 sizeof(struct virtio_ipsec_tunnel_hdr_ipv6) + \
	 sizeof(struct virtio_ipsec_esp_info)+	\
	 sizeof(struct virtio_ipsec_ah_info)+	\
	 sizeof(struct cipher_key)+	\
	 sizeof(struct nounce_iv)+	\
	 sizeof(struct auth_key)+	\
	 sizeof(struct virtio_ipsec_udp_encapsulation_info) + \
	 sizeof(struct virtio_ipsec_notify_lifetime_kb_expiry) +\
	 sizeof(struct virtio_ipsec_notify_seqnum_periodic)+	\
	 VIRTIO_IPSEC_MAX_KEY_IV_LEN +	\
	 VIRTIO_IPSEC_MAX_KEY_IV_LEN +	\
	 VIRTIO_IPSEC_MAX_KEY_IV_LEN)

int32_t virt_ipsec_msg_sa_add(u32 *handle, 
	 const struct g_ipsec_la_sa_add_inargs *in, u32 *len, u8 **msg,
	 u8 **result_ptr)
{
	struct virtio_ipsec_ctrl_hdr *hdr;
	struct virtio_ipsec_esp_info *esp;
	struct virtio_ipsec_ah_info *ah;
	struct virtio_ipsec_udp_encapsulation_info *udp_encap;
	struct virtio_ipsec_tunnel_hdr_ipv6 *ipv6;
	struct virtio_ipsec_tunnel_hdr_ipv4 *ipv4;
	struct virtio_ipsec_create_sa *v_create_sa;
	struct virtio_ipsec_sa_params *v_sa_params;
	struct virtio_ipsec_notify_lifetime_kb *notify_kb;
	struct virtio_ipsec_notify_seqnum_periodic *seqnum_periodic;
	struct cipher_key *cipher_key_info;
	struct auth_key *auth_key_info;
	struct nounce_iv *nounce_iv_info;

	struct g_ipsec_la_sa *sa_params = in->sa_params;
	u8 *buf, *buf_start;
	
	/* Check num_sas  to see if we support SA Bundle */
	/* Check feature bits for compatibility */

	buf_start = buf = kzalloc(VIRTIO_IPSEC_ADD_SA_MSG_SIZE, GFP_KERNEL);
	if (buf == NULL) {
		VIRTIO_IPSEC_MSG_DEBUG("%s:%s:%d:Add SA Out of memory  \n",
			__FILE__, __func__, __LINE__);
		return -ENOMEM;
	}

	hdr = (struct virtio_ipsec_ctrl_hdr *)buf;
	hdr->class = VIRTIO_IPSEC_CTRL_SA;
	if (in->dir == G_IPSEC_LA_SA_OUTBOUND)
		hdr->cmd = VIRTIO_IPSEC_CTRL_ADD_OUT_SA;
	else
		hdr->cmd = VIRTIO_IPSEC_CTRL_ADD_IN_SA;
	*len = sizeof(struct virtio_ipsec_ctrl_hdr);
	buf += sizeof(struct virtio_ipsec_ctrl_hdr);

	v_create_sa = (struct virtio_ipsec_create_sa *)buf;
	if (handle != NULL)
		memcpy(v_create_sa->group_handle, handle, VIRTIO_IPSEC_GROUP_HANDLE_SIZE);
	else
		memset(v_create_sa->group_handle, 0, VIRTIO_IPSEC_GROUP_HANDLE_SIZE);

	v_create_sa->num_sas = in->num_sas;
	v_sa_params = &v_create_sa->sa_params;
	v_sa_params->ulSPI = sa_params->spi;

	if (sa_params->proto == G_IPSEC_LA_PROTOCOL_ESP)
		v_sa_params->proto = VIRTIO_IPSEC_SA_PARAMS_PROTO_ESP;

	if (sa_params->proto == G_IPSEC_LA_PROTOCOL_AH)
		v_sa_params->proto = VIRTIO_IPSEC_SA_PARAMS_PROTO_AH;

	/* Check ECN, ESN etc. */
	if (sa_params->cmn_flags & G_IPSEC_LA_SA_USE_ESN)
		v_sa_params->bUseExtendedSeqNum = VIRTIO_IPSEC_EXTENDED_SEQ_NUM_ON;
	else
		v_sa_params->bUseExtendedSeqNum = VIRTIO_IPSEC_EXTENDED_SEQ_NUM_OFF;

	if (sa_params->cmn_flags & G_IPSEC_LA_SA_DO_ANTI_REPLAY_CHECK)
		v_sa_params->bDoAntiReplayCheck = VIRTIO_IPSEC_REPLAY_CHECK_ON;
	else
		v_sa_params->bDoAntiReplayCheck = VIRTIO_IPSEC_REPLAY_CHECK_OFF;

	if (sa_params->cmn_flags & G_IPSEC_LA_SA_DO_UDP_ENCAP_FOR_NAT_TRAVERSAL)
		v_sa_params->bDoUDPEncapsulation = VIRTIO_IPSEC_UDP_ENCAPSULATION_ON;
	else
		v_sa_params->bDoAntiReplayCheck = VIRTIO_IPSEC_UDP_ENCAPSULATION_OFF;

	if (sa_params->cmn_flags & G_IPSEC_LA_NOTIFY_LIFETIME_KB_EXPIRY)
		v_sa_params->bNotifySoftLifeKBExpiry = VIRTIO_IPSEC_SA_NOTIFY_LIFETIME_KB_EXPIRY_ON;
	else
		v_sa_params->bNotifySoftLifeKBExpiry = VIRTIO_IPSEC_SA_NOTIFY_LIFETIME_KB_EXPIRY_OFF;

	if (sa_params->cmn_flags & G_IPSEC_LA_NOTIFY_SEQNUM_OVERFLOW)
		v_sa_params->bNotifyBeforeSeqNumOverflow = VIRTIO_IPSEC_SA_NOTIFY_SEQNUM_OVERFLOW_ON;
	else
		v_sa_params->bNotifyBeforeSeqNumOverflow = VIRTIO_IPSEC_SA_NOTIFY_SEQNUM_OVERFLOW_OFF;

	if (sa_params->cmn_flags & G_IPSEC_LA_NOTIFY_SEQNUM_PERIODIC)
		v_sa_params->bNotifySeqNumPeriodic = VIRTIO_IPSEC_SA_NOTIFY_SEQNUM_PERIODIC_ON;
	else
		v_sa_params->bNotifySeqNumPeriodic = VIRTIO_IPSEC_SA_NOTIFY_SEQNUM_PERIODIC_OFF;

	v_sa_params->antiReplayWin = sa_params->anti_replay_window_size;
	*len += sizeof(struct virtio_ipsec_create_sa);
	buf += sizeof(struct virtio_ipsec_create_sa);

	/* Set the encapsulation mode */
	/* Encapsulation mode: tunnel or transport */
	if (!(sa_params->cmn_flags & G_IPSEC_LA_SA_ENCAP_TRANSPORT_MODE)) {/* Tunnel Mode */ 
		v_sa_params->bEncapsulationMode = VIRTIO_IPSEC_SA_SAFLAGS_TUNNEL_MODE;
		if (!(sa_params->cmn_flags & G_IPSEC_LA_SA_USE_IPv6)) { /* Use IPv4 */
			v_sa_params->bIPv4OrIPv6 = VIRTIO_IPSEC_TUNNEL_HDR_IS_IPV4;

			ipv4 = (struct virtio_ipsec_tunnel_hdr_ipv4 *)buf;
			/* Populate the tunnel data structure */
			ipv4->saddr = sa_params->te_addr.src_ip.ipv4;
			ipv4->daddr = sa_params->te_addr.dest_ip.ipv4;

			if (in->dir == G_IPSEC_LA_SA_OUTBOUND) {
				if (sa_params->outb.dscp_handle == G_IPSEC_LA_DSCP_CLEAR)
					ipv4->b_handle_dscp = VIRTIO_IPSEC_DSCP_CLEAR;
				else if (sa_params->outb.dscp_handle == G_IPSEC_LA_DSCP_COPY)	
					ipv4->b_handle_dscp = VIRTIO_IPSEC_DSCP_COPY;
				else {
				 	ipv4->b_handle_dscp = VIRTIO_IPSEC_DSCP_SET;
					ipv4->Dscp = sa_params->outb.dscp;
				}
				switch(sa_params->outb.df_bit_handle) {
					case G_IPSEC_LA_DF_CLEAR:
						ipv4->b_handle_df = VIRTIO_IPSEC_DF_CLEAR;
						break;
					case G_IPSEC_LA_DF_SET:
						ipv4->b_handle_df = VIRTIO_IPSEC_DF_SET;
						break;
					case G_IPSEC_LA_DF_COPY:
						ipv4->b_handle_df = VIRTIO_IPSEC_DF_COPY;
						break;
					default:
						break;
				}
			}
			if (sa_params->cmn_flags & G_IPSEC_LA_SA_USE_ECN)
				ipv4->b_propogate_ECN = VIRTIO_IPSEC_PROPOGATE_ECN_ON;
			else
				ipv4->b_propogate_ECN = VIRTIO_IPSEC_PROPOGATE_ECN_OFF;
			*len += sizeof(struct virtio_ipsec_tunnel_hdr_ipv4);
			buf += sizeof(struct virtio_ipsec_tunnel_hdr_ipv4);
		} else { /* use ipv6 */
			v_sa_params->bIPv4OrIPv6 = VIRTIO_IPSEC_TUNNEL_HDR_IS_IPV6;

			ipv6 = (struct virtio_ipsec_tunnel_hdr_ipv6 *)buf;
			memcpy(ipv6->s_addr, sa_params->te_addr.src_ip.ipv6.w_addr, 16);
			memcpy(ipv6->d_addr, sa_params->te_addr.dest_ip.ipv6.w_addr, 16);

			if (in->dir == G_IPSEC_LA_SA_OUTBOUND) {
				if (sa_params->outb.dscp_handle == G_IPSEC_LA_DSCP_CLEAR)
					ipv6->b_handle_dscp = VIRTIO_IPSEC_DSCP_CLEAR;
				else if (sa_params->outb.dscp_handle == G_IPSEC_LA_DSCP_COPY)	
					ipv6->b_handle_dscp = VIRTIO_IPSEC_DSCP_COPY;
				else {
				 	ipv6->b_handle_dscp = VIRTIO_IPSEC_DSCP_SET;
					ipv6->dscp = sa_params->outb.dscp;
				}
				switch(sa_params->outb.df_bit_handle) {
					case G_IPSEC_LA_DF_CLEAR:
						ipv6->b_handle_df = VIRTIO_IPSEC_DF_CLEAR;
						break;
					case G_IPSEC_LA_DF_SET:
						ipv6->b_handle_df = VIRTIO_IPSEC_DF_SET;
						break;
					case G_IPSEC_LA_DF_COPY:
						ipv6->b_handle_df = VIRTIO_IPSEC_DF_COPY;
						break;
					default:
						break;
				}
			}
			if (sa_params->cmn_flags & G_IPSEC_LA_SA_USE_ECN)
				ipv6->b_propogate_ECN = VIRTIO_IPSEC_PROPOGATE_ECN_ON;
			else
				ipv6->b_propogate_ECN = VIRTIO_IPSEC_PROPOGATE_ECN_OFF;
			*len += sizeof(struct virtio_ipsec_tunnel_hdr_ipv6);
			buf += sizeof(struct virtio_ipsec_tunnel_hdr_ipv6);
		}
	} else {
		v_sa_params->bEncapsulationMode = VIRTIO_IPSEC_SA_SAFLAGS_TRANSPORT_MODE;
	}

	/* Copy the crypto parameters */
	if (v_sa_params->proto == VIRTIO_IPSEC_SA_PARAMS_PROTO_ESP) {
		esp = (struct virtio_ipsec_esp_info *)buf;
		esp->bEncrypt = true;
		switch (sa_params->crypto_params.cipher_algo) {
			case G_IPSEC_LA_CIPHER_ALGO_NULL:
				esp->cipher_algo = VIRTIO_IPSEC_ESP_NULL;
				break;
			case G_IPSEC_LA_ALGO_DES_CBC:
				esp->cipher_algo = VIRTIO_IPSEC_DES_CBC;
				break;
			case G_IPSEC_LA_ALGO_3DES_CBC:
				esp->cipher_algo = VIRTIO_IPSEC_3DES_CBC;
				break;
			case G_IPSEC_LA_ALGO_AES_CBC:
				esp->cipher_algo = VIRTIO_IPSEC_AES_CBC;
				break;
			case G_IPSEC_LA_ALGO_AES_CTR:
				esp->cipher_algo = VIRTIO_IPSEC_AESCTR;
				break;
			case G_IPSEC_LA_ALGO_COMB_AES_CCM:
				switch (sa_params->crypto_params.icv_len_bits/8) {
					case 8:
						esp->cipher_algo = VIRTIO_IPSEC_AES_CCM_ICV8;
						break;
					case 12:
						esp->cipher_algo = VIRTIO_IPSEC_AES_CCM_ICV12;
						break;
					case 16:
						esp->cipher_algo = VIRTIO_IPSEC_AES_CCM_ICV16;
						break;
					default:
						break;
					}
				break;
			case G_IPSEC_LA_ALGO_COMB_AES_GCM:
				switch (sa_params->crypto_params.icv_len_bits/8) {
					case 8:
						esp->cipher_algo = VIRTIO_IPSEC_AES_GCM_ICV8;
						break;
					case 12:
						esp->cipher_algo = VIRTIO_IPSEC_AES_GCM_ICV12;
						break;
					case 16:
						esp->cipher_algo = VIRTIO_IPSEC_AES_CCM_ICV16;
						break;
					default:
						break;
				}
				break;
			case G_IPSEC_LA_ALGO_COMB_AES_GMAC:
				esp->cipher_algo = VIRTIO_IPSEC_AES_GMAC;
				break;
		}
		*len += sizeof(struct virtio_ipsec_esp_info);
		buf += sizeof(struct virtio_ipsec_esp_info);

		cipher_key_info = (struct cipher_key *)buf; 
		cipher_key_info->lv.len = sa_params->crypto_params.cipher_key_len_bits/8;
		memcpy(cipher_key_info->lv.data, sa_params->crypto_params.cipher_key, 
			cipher_key_info->lv.len);
		*len += sizeof(struct cipher_key);
		buf += sizeof(struct cipher_key);

		if (sa_params->crypto_params.auth_algo != G_IPSEC_LA_AUTH_ALGO_NONE) {
			esp->bAuth = true;
			esp->auth_algo = sa_params->crypto_params.auth_algo;

			auth_key_info = (struct auth_key *)buf;
			auth_key_info->lv.len = sa_params->crypto_params.auth_key_len_bits/8;
			memcpy(auth_key_info->lv.data, sa_params->crypto_params.auth_key,
				auth_key_info->lv.len);
			esp->ICVSize = sa_params->crypto_params.icv_len_bits/8;
			*len += sizeof(struct auth_key);
			buf += sizeof(struct auth_key);
		}
	
		nounce_iv_info = (struct nounce_iv *)buf; 
		nounce_iv_info->lv.len = sa_params->crypto_params.iv_len_bits/8;
		memcpy(nounce_iv_info->lv.data, sa_params->crypto_params.iv,
			nounce_iv_info->lv.len);
		*len += sizeof(struct nounce_iv);
		buf += sizeof(struct nounce_iv);
	}

	if (v_sa_params->proto == VIRTIO_IPSEC_AH) {
		ah = (struct virtio_ipsec_ah_info *)buf;
		switch(sa_params->crypto_params.auth_algo) {
			case G_IPSEC_LA_AUTH_ALGO_NONE:	/* No Authentication */
				ah->authAlgo = VIRTIO_IPSEC_HMAC_NULL;	
				break;
			case G_IPSEC_LA_AUTH_ALGO_MD5_HMAC:   /* MD5 HMAC Authentication Algo. */
				ah->authAlgo = VIRTIO_IPSEC_HMAC_MD5;
				break;
			case G_IPSEC_LA_AUTH_ALGO_SHA1_HMAC:  /* SHA1 HMAC Authentication Algo. */
				ah->authAlgo = VIRTIO_IPSEC_HMAC_SHA1;
				break;
			case G_IPSEC_LA_AUTH_AESXCBC:	/* AES-XCBC Authentication Algo. */
				ah->authAlgo = VIRTIO_IPSEC_HMAC_AES_XCBC_MAC;
				break;
			case G_IPSEC_LA_AUTH_ALGO_SHA2_256_HMAC: /* SHA2 HMAC Authentication Algorithm; 256 bit key length */
				ah->authAlgo = VIRTIO_IPSEC_HMAC_SHA256;
				break;
			case G_IPSEC_LA_AUTH_ALGO_SHA2_384_HMAC: /* SHA2 HMAC Authentication Algorithm with 384 bit key length */
				ah->authAlgo = VIRTIO_IPSEC_HMAC_SHA384;
				break;
			case G_IPSEC_LA_AUTH_ALGO_SHA2_512_HMAC: 
				ah->authAlgo = VIRTIO_IPSEC_HMAC_SHA512;
				break;
			case G_IPSEC_LA_AUTH_ALGO_HMAC_SHA1_160:
				ah->authAlgo = VIRTIO_IPSEC_HMAC_SHA1_160;
				break;
		}			
		*len += sizeof(struct virtio_ipsec_ah_info);
		buf += sizeof(struct virtio_ipsec_ah_info);

		auth_key_info = (struct auth_key *)buf;
		auth_key_info->lv.len = sa_params->crypto_params.auth_key_len_bits/8;
		memcpy(auth_key_info->lv.data, sa_params->crypto_params.auth_key,
			auth_key_info->lv.len);
		ah->ICVSize = sa_params->crypto_params.icv_len_bits/8;
		*len += sizeof(struct auth_key);
		buf += sizeof(struct auth_key);
	}

	if (v_sa_params->bDoUDPEncapsulation) {
		udp_encap = (struct virtio_ipsec_udp_encapsulation_info *)(buf);
		// TBD : udp_encap->ulNatTraversalMode = sa_params->nat_info.;
		udp_encap->d_port = sa_params->nat_info.dest_port;
		udp_encap->s_port = sa_params->nat_info.src_port;
		*len += sizeof(struct virtio_ipsec_udp_encapsulation_info);
		buf += sizeof(struct virtio_ipsec_udp_encapsulation_info);
	}
	if (v_sa_params->bNotifySoftLifeKBExpiry) {
		notify_kb = (struct virtio_ipsec_notify_lifetime_kb *)(buf);
		notify_kb->hard_lifetime_in_kb = sa_params->hard_kilobytes_limit;
		notify_kb->soft_lifetime_in_kb = sa_params->soft_kilobytes_limit;
		*len += sizeof(struct virtio_ipsec_notify_lifetime_kb);
		buf += sizeof(struct virtio_ipsec_notify_lifetime_kb);
	}
	if (v_sa_params->bNotifySeqNumPeriodic) {
		seqnum_periodic = (struct virtio_ipsec_notify_seqnum_periodic*)(buf);
		seqnum_periodic->seqnum_interval = sa_params->seqnum_interval;
		*len += sizeof(struct virtio_ipsec_notify_seqnum_periodic);
		buf += sizeof(struct virtio_ipsec_notify_seqnum_periodic);
	}

	/* Account for the result */
	*result_ptr = buf_start + (*len);
	v_create_sa->sa_len = *len;
	*msg = buf_start;
	*len += sizeof(struct virtio_ipsec_ctrl_result);

	return VIRTIO_IPSEC_SUCCESS;
}


#define VIRT_IPSEC_MSG_SA_DEL_SIZE \
	(sizeof(struct virtio_ipsec_ctrl_hdr) +	\
	 sizeof(struct virtio_ipsec_ctrl_result)+ \
	 sizeof(struct virtio_ipsec_delete_sa))
	

int32_t virt_ipsec_msg_sa_del(
		u32 *g_hw_handle, u32 *sa_handle, 
		const struct g_ipsec_la_sa_del_inargs *in, 
		u32 *len,
		u8 **msg, u8 **result_ptr)
{
	u8 *buf, *buf_start;
	struct virtio_ipsec_ctrl_hdr *hdr;
	struct virtio_ipsec_delete_sa *del_sa;

	buf_start = buf = kzalloc(
		VIRT_IPSEC_MSG_SA_DEL_SIZE, GFP_KERNEL);
	if (buf == NULL) {
		VIRTIO_IPSEC_MSG_DEBUG("%s:%s:%d:Add SA Out of memory \n",
			__FILE__, __func__, __LINE__);
		return -ENOMEM;
		}

	hdr = (struct virtio_ipsec_ctrl_hdr *)buf;
	hdr->class = VIRTIO_IPSEC_CTRL_SA;

	if (in->dir == G_IPSEC_LA_SA_OUTBOUND)
		hdr->cmd = VIRTIO_IPSEC_CTRL_DEL_OUT_SA;
	else
		hdr->cmd = VIRTIO_IPSEC_CTRL_DEL_IN_SA;

	buf += sizeof(struct virtio_ipsec_ctrl_hdr);
	*len = sizeof(struct virtio_ipsec_ctrl_hdr);

	del_sa = (struct virtio_ipsec_delete_sa *)(buf);
	if (g_hw_handle != NULL)
		memcpy(del_sa->group_handle, g_hw_handle, VIRTIO_IPSEC_GROUP_HANDLE_SIZE);
	else
		memset(del_sa->group_handle, 0, VIRTIO_IPSEC_GROUP_HANDLE_SIZE);
	memcpy(del_sa->sa_handle, sa_handle, VIRTIO_IPSEC_SA_HANDLE_SIZE);

	buf += sizeof(struct virtio_ipsec_delete_sa);
	*len += sizeof(struct virtio_ipsec_delete_sa);

	*result_ptr = buf;
	*len+= sizeof(struct virtio_ipsec_ctrl_result);

	return VIRTIO_IPSEC_SUCCESS;	
}


#define VIRT_IPSEC_MSG_SA_MOD_SIZE \
	(sizeof(struct virtio_ipsec_ctrl_hdr)+	\
	sizeof(struct virtio_ipsec_ctrl_result)+	\
	sizeof(struct virtio_ipsec_update_sa)+	\
	sizeof(struct virtio_ipsec_update_sa_ipaddr_v4)+ \
	sizeof(struct virtio_ipsec_update_sa_ipaddr_v6) + \
	sizeof(struct virtio_ipsec_update_sa_seqnum) + \
	sizeof(struct virtio_ipsec_update_sa_antireplay))
	
int32_t virt_ipsec_msg_sa_mod
		(u32 *g_hw_handle, u32 *sa_handle, 
		const struct g_ipsec_la_sa_mod_inargs *in,
		 u32 *len ,u8 **msg, u8 **result_ptr)
{
	u8 *buf, *buf_start;
	struct virtio_ipsec_ctrl_hdr *hdr;
	struct virtio_ipsec_update_sa *update_sa;
	struct virtio_ipsec_update_sa_ipaddr_v4 *ipv4;
	struct virtio_ipsec_update_sa_ipaddr_v6 *ipv6;
	struct virtio_ipsec_update_sa_seqnum *seq_num;
	struct virtio_ipsec_update_sa_antireplay *anti_replay;
	
	buf_start = buf = kzalloc(VIRT_IPSEC_MSG_SA_MOD_SIZE, GFP_KERNEL);
	if (buf == NULL) {
		VIRTIO_IPSEC_MSG_DEBUG("%s:%s:%d:Add SA Out of memory \n",
			__FILE__, __func__, __LINE__);
		return -ENOMEM;
	}

	hdr = (struct virtio_ipsec_ctrl_hdr *)buf;
	hdr->class = VIRTIO_IPSEC_CTRL_SA;
	
	if (in->dir == G_IPSEC_LA_SA_OUTBOUND)
		hdr->cmd = VIRTIO_IPSEC_CTRL_UPDATE_OUT_SA;
	else
		hdr->cmd = VIRTIO_IPSEC_CTRL_UPDATE_IN_SA;

	*len = sizeof(struct virtio_ipsec_ctrl_hdr);
	buf += sizeof(struct virtio_ipsec_ctrl_hdr);

	update_sa =(struct virtio_ipsec_update_sa *)buf;
	buf += sizeof(struct virtio_ipsec_update_sa);

	if (g_hw_handle != NULL)
		memcpy(update_sa->group_handle, 
			g_hw_handle, VIRTIO_IPSEC_GROUP_HANDLE_SIZE);
	else
		memset(update_sa->group_handle, 0, 
			VIRTIO_IPSEC_GROUP_HANDLE_SIZE);
	
	memcpy(update_sa->sa_handle,
		sa_handle, VIRTIO_IPSEC_SA_HANDLE_SIZE);
	
	if (in->flags & G_IPSEC_LA_SA_MODIFY_LOCAL_GW_INFO) {
		
		update_sa->changeType = VIRTIO_IPSEC_UPDATE_SA_LOCAL_GW;

		if (in->addr_info.addr.version == G_IPSEC_LA_IPV4) {
			ipv4 = (struct virtio_ipsec_update_sa_ipaddr_v4 *)buf;
			memcpy(&ipv4->addr, &in->addr_info.addr.ipv4, 4);
			buf += sizeof(struct virtio_ipsec_update_sa_ipaddr_v4);
			*len += sizeof(struct virtio_ipsec_update_sa_ipaddr_v4);
		}
		else {
			ipv6 = (struct virtio_ipsec_update_sa_ipaddr_v6 *)(buf);
			memcpy(ipv6->addr, in->addr_info.addr.ipv6.b_addr, 4*4 );
			buf += sizeof(struct virtio_ipsec_update_sa_ipaddr_v6);
			*len += sizeof(struct virtio_ipsec_update_sa_ipaddr_v6);
		}
	}
	
	if(in->flags & G_IPSEC_LA_SA_MODIFY_PEER_GW_INFO)	{
		update_sa->changeType = VIRTIO_IPSEC_UPDATE_SA_PEER_GW;
		if (in->addr_info.addr.version == G_IPSEC_LA_IPV4) {
			ipv4 = (struct virtio_ipsec_update_sa_ipaddr_v4 *)buf;
			memcpy(&ipv4->addr, &in->addr_info.addr.ipv4, 4);
			buf += sizeof(struct virtio_ipsec_update_sa_ipaddr_v4);
			*len += sizeof(struct virtio_ipsec_update_sa_ipaddr_v4);
		}
		else {
			ipv6 = (struct virtio_ipsec_update_sa_ipaddr_v6 *)(buf);
			memcpy(ipv6->addr, in->addr_info.addr.ipv6.b_addr, 4*4 );
			buf += sizeof(struct virtio_ipsec_update_sa_ipaddr_v6);
			*len += sizeof(struct virtio_ipsec_update_sa_ipaddr_v6);
		}
	}
	
	if ((in->flags & G_IPSEC_LA_SA_MODIFY_REPLAY_INFO) &&
		(in->replay.flags == G_IPSEC_LA_SA_MODIFY_SEQ_NUM)) {
		update_sa->changeType = VIRTIO_IPSEC_UPDATE_SA_SEQ_NUM;
		seq_num = (struct virtio_ipsec_update_sa_seqnum *)(buf);
		seq_num->seq_num = in->replay.seq_num;
		seq_num->hi_seq_num = in->replay.hi_seq_num;
		buf += sizeof(struct virtio_ipsec_update_sa_seqnum);
		*len += sizeof(struct virtio_ipsec_update_sa_seqnum);
	}
	if ((in->flags & G_IPSEC_LA_SA_MODIFY_REPLAY_INFO) && 
		(in->replay.flags == G_IPSEC_LA_SA_MODIFY_ANTI_REPLAY_WINDOW)) {
		update_sa->changeType = VIRTIO_IPSEC_UPDATE_SA_ANTI_REPLAY_WINDOW;
		anti_replay = (struct virtio_ipsec_update_sa_antireplay*)buf;
		anti_replay->anti_replay_window_bit_map = in->replay.anti_replay_window_bit_map;
		anti_replay->anti_replay_window_size = in->replay.anti_replay_window_size;

		buf += sizeof(struct virtio_ipsec_update_sa_antireplay);
		*len += sizeof(struct virtio_ipsec_update_sa_antireplay);
	}

	*result_ptr = buf + (*len);
	*msg = buf_start;
	*len += sizeof(struct virtio_ipsec_ctrl_result);
	
	return VIRTIO_IPSEC_SUCCESS;
	
}

#define VIRT_IPSEC_MSG_SA_FLUSH_SIZE \
	(sizeof(struct virtio_ipsec_ctrl_hdr) +	\
	sizeof(struct virtio_ipsec_ctrl_result) +	\
	sizeof(struct virtio_ipsec_flush_sa))
	
int32_t virt_ipsec_msg_sa_flush(
	u32 *g_hw_handle, u32 *len,
	u8 **msg, u8 **result_ptr)
{
	u8 *buf, *buf_start;
	struct virtio_ipsec_ctrl_hdr *hdr;
	struct virtio_ipsec_flush_sa *flush_sa;

	buf_start = buf = kzalloc(VIRT_IPSEC_MSG_SA_FLUSH_SIZE,
		GFP_KERNEL);

	if (buf == NULL)
		return -ENOMEM;

	hdr = (struct virtio_ipsec_ctrl_hdr *)buf;
	buf += sizeof(struct virtio_ipsec_ctrl_hdr);
	*len = sizeof(struct virtio_ipsec_ctrl_hdr);
	
	hdr->class = VIRTIO_IPSEC_CTRL_SA;
	if (g_hw_handle == NULL){
		hdr->cmd = VIRTIO_IPSEC_CTRL_FLUSH_SA_ALL;
	}
	else {
 		hdr->cmd = VIRTIO_IPSEC_CTRL_FLUSH_SA;
		flush_sa = (struct virtio_ipsec_flush_sa *)buf;
		memcpy(flush_sa->group_handle, g_hw_handle, 
			VIRTIO_IPSEC_GROUP_HANDLE_SIZE);
		buf += sizeof(struct virtio_ipsec_flush_sa);
		*len += sizeof(struct virtio_ipsec_flush_sa);
	}

	*result_ptr = buf;
	*msg = buf_start;
	*len += sizeof(struct virtio_ipsec_ctrl_result);

	return VIRTIO_IPSEC_SUCCESS;
}


int32_t virt_ipsec_msg_release(u8 *buf)
{
 	kfree(buf);
	return 0;
}
	











	



	
	


