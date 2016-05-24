/* An asf-virtio integration file.
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
#include <linux/stddef.h>
#include <linux/skbuff.h>
#include "../../asfffp/driver/asftmr.h"
#include "../../asfffp/driver/asf.h"
#include "../../asfffp/driver/asfcmn.h"
#include "../../asfffp/driver/asfipsec.h"
#include "ipsfpapi.h"
#include "ipsecfp.h"
#include "virtio_ipsec_api.h"
#include "ipsecvio.h"


#define ASF_VIO_DEBUG	printk

struct asf_vdev_info {
	char name[IPSEC_IFNAMESIZ];
	struct g_ipsec_la_handle handle;
};

static struct asf_vdev_info *_asf_device = NULL;
#if 0
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
#endif
void dbg_prt_sa_parms(char *msg, struct g_ipsec_la_sa_add_inargs *in)
{
#if 1
	printk("===%s: dir %d numSA %d spi 0x%x proto %d flags 0x%x ARwinsize %d\n", msg,
		in->dir, in->num_sas, in->sa_params->spi, in->sa_params->proto,
		in->sa_params->cmn_flags, in->sa_params->anti_replay_window_size);
	printk("    dscp %d dfcmd %d dscpcmd %d reserved %d bAuth %d bEncr %d\n",
		in->sa_params->outb.dscp, in->sa_params->outb.df_bit_handle,
		in->sa_params->outb.dscp_handle, in->sa_params->crypto_params.reserved,
		in->sa_params->crypto_params.bAuth, in->sa_params->crypto_params.bEncrypt);
	printk("    auth_algo %d cipher_algo %d blksize %d\n", in->sa_params->crypto_params.auth_algo,
		in->sa_params->crypto_params.cipher_algo, in->sa_params->crypto_params.block_size);
	printk("    icv_len_bits %d soft_KB %d hard_KB %d seq_intv %d\n",
		in->sa_params->crypto_params.icv_len_bits, in->sa_params->soft_kilobytes_limit,
		in->sa_params->hard_kilobytes_limit, in->sa_params->seqnum_interval);
	if (in->sa_params->crypto_params.auth_key)
		dbg_prt_blk("   auth_key:", in->sa_params->crypto_params.auth_key, in->sa_params->crypto_params.auth_key_len_bits/8);
	else
		printk("    auth_key null len %d bits\n", in->sa_params->crypto_params.auth_key_len_bits);
	if (in->sa_params->crypto_params.cipher_key)
		dbg_prt_blk("   cipher_key:", in->sa_params->crypto_params.cipher_key, in->sa_params->crypto_params.cipher_key_len_bits/8);
	else printk("    cipher_key null len %d bits\n", in->sa_params->crypto_params.cipher_key_len_bits);
	if (in->sa_params->crypto_params.iv)
	 	dbg_prt_blk("   iv:", in->sa_params->crypto_params.iv, in->sa_params->crypto_params.iv_len_bits/8);
	else printk("    iv null len %d bits\n", in->sa_params->crypto_params.iv_len_bits);
#else
	printk("########## Dump Parameters STARTING ################## \r\n");
	printk(" in->dir %d \n in->num_sas %d \n in->sa_params->spi 0x%x \n in->sa_params->proto %d \n in->sa_params->cmn_flags %d \n in->sa_params->anti_replay_window_size %d \n in->sa_params->outb.dscp %d \n in->sa_params->outb.df_bit_handle %d \n in->sa_params->outb.dscp_handle %d \n in->sa_params->crypto_params.reserved %d \n in->sa_params->crypto_params.bAuth %d \n in->sa_params->crypto_params.bEncrypt %d \n in->sa_params->crypto_params.auth_algo %d \n in->sa_params->crypto_params.auth_key %p \n in->sa_params->crypto_params.auth_key_len_bits %d \n in->sa_params->crypto_params.cipher_algo %d \n  in->sa_params->crypto_params.cipher_key %p \n in->sa_params->crypto_params.block_size %d \n in->sa_params->crypto_params.cipher_key_len_bits %d \n in->sa_params->crypto_params.iv %p \n in->sa_params->crypto_params.iv_len_bits %d \n in->sa_params->crypto_params.icv_len_bits %d \n in->sa_params->soft_kilobytes_limit %d \n in->sa_params->hard_kilobytes_limit %d \n in->sa_params->seqnum_interval %d \n \r\n", in->dir, in->num_sas, in->sa_params->spi,in->sa_params->proto, in->sa_params->cmn_flags, in->sa_params->anti_replay_window_size, in->sa_params->outb.dscp, in->sa_params->outb.df_bit_handle, in->sa_params->outb.dscp_handle, in->sa_params->crypto_params.reserved, in->sa_params->crypto_params.bAuth, in->sa_params->crypto_params.bEncrypt, in->sa_params->crypto_params.auth_algo, in->sa_params->crypto_params.auth_key, in->sa_params->crypto_params.auth_key_len_bits, in->sa_params->crypto_params.cipher_algo, in->sa_params->crypto_params.cipher_key, in->sa_params->crypto_params.block_size, in->sa_params->crypto_params.cipher_key_len_bits, in->sa_params->crypto_params.iv, in->sa_params->crypto_params.iv_len_bits, in->sa_params->crypto_params.icv_len_bits, in->sa_params->soft_kilobytes_limit, in->sa_params->hard_kilobytes_limit, in->sa_params->seqnum_interval);
	printk("########## Dump Parameters ENDING ################## \r\n");
#endif
}
void asf_vio_device_unplugged(struct g_ipsec_la_handle *handle,  void *cb_arg)
{
	ASF_VIO_DEBUG("Device unplugged\n");
}

void asf_virtio_interface_init()
{
	struct g_ipsec_la_open_inargs in_open;
	struct g_ipsec_la_open_outargs out_open;
	int ret;
	char acc_name[20] = "ipsec-0";
	char app_iden[20] = "ASF";

	/*struct g_ipsec_la_avail_devices_get_outargs out;
	char last_name[IPSEC_IFNAMESIZ];
	out.last_device_read = last_name;*/
#if 0
	char version[G_IPSEC_LA_MAX_VERSION_LENGTH];
	uint32_t nr_devices;
	u32 ii;
	struct g_ipsec_la_avail_devices_get_inargs in;
	struct g_ipsec_la_device_info *info;

	/* check on the API version */
	g_ipsec_la_get_api_version(version);

	/* Get the number of devices */
	g_ipsec_la_avail_devices_get_num(&nr_devices);

	/* get available devices */
	in.last_device_read = NULL;
	in.num_devices = nr_devices;

	out.dev_info = (struct g_ipsec_la_device_info *)kzalloc(
		(sizeof(struct g_ipsec_la_device_info*)*nr_devices)+
		(sizeof(struct g_ipsec_la_device_info)*nr_devices)+
		(IPSEC_IFNAMESIZ*nr_devices), GFP_KERNEL);

	if (out.dev_info == NULL) {
		/* error */
		ASF_VIO_DEBUG("Memory allocation error %s:%s:%d\n", 
			__FILE__, __func__, __LINE__);
		return; 
		/* handle error */
	}
	
	ret = g_ipsec_la_avail_devices_get_info(&in, &out);

	info = out.dev_info;
	if (ret == G_IPSEC_LA_SUCCESS) {
		for (ii=0; ii < nr_devices; ii++, info++) {
			if (info->mode == G_IPSEC_LA_INSTANCE_AVAILABLE) {
				break;
			}
		}
	}

	if (ii < nr_devices) {
		_asf_device = kzalloc(sizeof(struct g_ipsec_la_device_info)+IPSEC_IFNAMESIZ, GFP_KERNEL);
		if (_asf_device == NULL) {
			/* handle error */
			kfree(out.dev_info);
			ASF_VIO_DEBUG("Memory allocation error %s:%s:%d\n", 
				__FILE__, __func__, __LINE__);
			return;
		}
		info->device_name[15] = 0;
		strncpy(_asf_device->name, info->device_name, 16);
	}
#endif
	in_open.cb_arg = NULL;
	in_open.cb_arg_len = 0;
	in_open.pci_vendor_id = VIRTIO_IPSEC_VENDOR_ID;
	in_open.device_id = VIRTIO_IPSEC_DEVICE_ID;
	in_open.accl_name = acc_name;
	in_open.app_identity = app_iden;
	in_open.cb_fn = asf_vio_device_unplugged;

	_asf_device = kzalloc(sizeof(struct g_ipsec_la_device_info)+IPSEC_IFNAMESIZ, GFP_KERNEL);
	out_open.handle = &(_asf_device->handle);
	
	/* Open the device */
	ret = g_ipsec_la_open(G_IPSEC_LA_INSTANCE_EXCLUSIVE,&in_open, &out_open);
	if (ret != G_IPSEC_LA_SUCCESS) {
		ASF_VIO_DEBUG("Unable to get an IPsec handle%s:%s:%d \n",
			__FILE__, __func__, __LINE__);
		kfree(_asf_device);
		_asf_device = NULL;
		return;
	}
	/* Now we have got the handle: good to go */
	dbg_prt_blk("asf_ipsec device:\n", _asf_device, sizeof(struct asf_vdev_info));
}

#if 0
typedef  struct {
	ASF_uint32_t ulNATt;
	ASF_uint16_t usDstPort;
	ASF_uint16_t usSrcPort;
} ASF_IPSec_Nat_Info_t;

#endif

void vioips_sa_add_cbfn(void *arg, int arg_len, struct g_ipsec_la_sa_add_outargs *out)
{
	printk("===callback received\n");
}

int32_t secfp_createInSAVIpsec(inSA_t *pSA)
{
	struct g_ipsec_la_sa_add_inargs in;
	struct g_ipsec_la_sa_add_outargs out;
	struct g_ipsec_la_sa sa_params; 
	struct g_ipsec_la_resp_args resp_a;
	enum g_ipsec_la_control_flags flags_a;
	int ret = ASF_FAILURE;

	in.dir = G_IPSEC_LA_SA_INBOUND;
	in.num_sas = 1;
	in.sa_params = &sa_params;

	sa_params.crypto_params.iv = NULL;
	sa_params.crypto_params.cipher_key= NULL;
	sa_params.crypto_params.auth_key= NULL;
	sa_params.spi = pSA->SAParams.ulSPI;
	sa_params.proto = pSA->SAParams.ucProtocol;
	sa_params.cmn_flags = 0;

	if (pSA->SAParams.bDoUDPEncapsulationForNATTraversal) {
		sa_params.cmn_flags |= G_IPSEC_LA_SA_DO_UDP_ENCAP_FOR_NAT_TRAVERSAL;
		sa_params.nat_info.dest_port = pSA->SAParams.IPsecNatInfo.usDstPort;
		sa_params.nat_info.src_port = pSA->SAParams.IPsecNatInfo.usSrcPort;
		sa_params.nat_info.nat_oa_peer_addr.version = G_IPSEC_LA_IPV4;
		sa_params.nat_info.nat_oa_peer_addr.ipv4 = pSA->SAParams.IPsecNatInfo.ulNATt;
	}

	if (pSA->SAParams.bPropogateECN)
		sa_params.cmn_flags |= G_IPSEC_LA_SA_USE_ECN;

	if (pSA->SAParams.bDoAntiReplayCheck)
		sa_params.cmn_flags |= G_IPSEC_LA_SA_DO_ANTI_REPLAY_CHECK;

	if (pSA->SAParams.bEncapsulationMode == ASF_IPSEC_SA_SAFLAGS_TRANSPORTMODE)
		sa_params.cmn_flags |= G_IPSEC_LA_SA_ENCAP_TRANSPORT_MODE;
	else {
		if(pSA->SAParams.tunnelInfo.bIPv4OrIPv6) { /* IPv6 */

		sa_params.te_addr.src_ip.version = G_IPSEC_LA_IPV6;
			
		memcpy(sa_params.te_addr.dest_ip.ipv6.w_addr,
			pSA->SAParams.tunnelInfo.addr.iphv6.daddr, 4);
		memcpy(sa_params.te_addr.src_ip.ipv6.w_addr,
			pSA->SAParams.tunnelInfo.addr.iphv6.saddr, 4);
			
		}
		else {
			sa_params.te_addr.dest_ip.version = G_IPSEC_LA_IPV4;
			sa_params.te_addr.dest_ip.ipv4 = pSA->SAParams.tunnelInfo.addr.iphv4.daddr;

			sa_params.te_addr.src_ip.version = G_IPSEC_LA_IPV4;
			sa_params.te_addr.dest_ip.ipv4 = pSA->SAParams.tunnelInfo.addr.iphv4.saddr;
		}
	}

	if (pSA->SAParams.bUseExtendedSequenceNumber)
		sa_params.cmn_flags |= G_IPSEC_LA_SA_USE_ESN;

	if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6 == 1)
		sa_params.cmn_flags |= G_IPSEC_LA_SA_USE_IPv6;

	sa_params.anti_replay_window_size= pSA->SAParams.AntiReplayWin; /* Need to check this */

	sa_params.crypto_params.bAuth = pSA->SAParams.bAuth;
	sa_params.crypto_params.bEncrypt = pSA->SAParams.bEncrypt; /* Need to check virtio message framing */
		
	if (pSA->SAParams.bAuth) {

		sa_params.crypto_params.auth_key = kzalloc((pSA->SAParams.AuthKeyLen),GFP_KERNEL);
		memcpy(sa_params.crypto_params.auth_key, pSA->SAParams.ucAuthKey, pSA->SAParams.AuthKeyLen);
		sa_params.crypto_params.auth_key_len_bits = pSA->SAParams.AuthKeyLen*8;

		sa_params.crypto_params.icv_len_bits = pSA->SAParams.uICVSize;
		switch (pSA->SAParams.ucAuthAlgo) {
		case SECFP_HMAC_MD5:
			sa_params.crypto_params.auth_algo = G_IPSEC_LA_AUTH_ALGO_MD5_HMAC;
			break;
		case SECFP_HMAC_SHA1:
			sa_params.crypto_params.auth_algo = G_IPSEC_LA_AUTH_ALGO_SHA1_HMAC;
			break;
		case SECFP_HMAC_AES_XCBC_MAC:
			sa_params.crypto_params.auth_algo = G_IPSEC_LA_AUTH_AESXCBC;
			break;
		case SECFP_HMAC_SHA256:
			sa_params.crypto_params.auth_algo = G_IPSEC_LA_AUTH_ALGO_SHA2_256_HMAC;
			break;
		case SECFP_HMAC_SHA384:
			sa_params.crypto_params.auth_algo= G_IPSEC_LA_AUTH_ALGO_SHA2_384_HMAC;
			break;
		case SECFP_HMAC_SHA512:
			sa_params.crypto_params.auth_algo = G_IPSEC_LA_AUTH_ALGO_SHA2_512_HMAC;
			break;
		default:
			ASF_VIO_DEBUG("Invalid ucAuthAlgo");
			return -1;
			}
	}

					
	if (pSA->SAParams.bEncrypt) {
			
		sa_params.crypto_params.cipher_key= kzalloc((pSA->SAParams.EncKeyLen),GFP_KERNEL);
		memcpy(sa_params.crypto_params.cipher_key, pSA->SAParams.ucEncKey, pSA->SAParams.EncKeyLen);
		sa_params.crypto_params.cipher_key_len_bits= pSA->SAParams.EncKeyLen*8;

		sa_params.crypto_params.block_size = pSA->SAParams.ulBlockSize;
		sa_params.crypto_params.iv_len_bits = 0;
			
		switch (pSA->SAParams.ucCipherAlgo) {
			case SECFP_DES:
				sa_params.crypto_params.cipher_algo = G_IPSEC_LA_ALGO_DES_CBC;
				break;
			case SECFP_3DES:
				sa_params.crypto_params.cipher_algo = G_IPSEC_LA_ALGO_3DES_CBC;
				break;
			case SECFP_AES:
				sa_params.crypto_params.cipher_algo = G_IPSEC_LA_ALGO_AES_CBC;
				break;
			case SECFP_AESCTR:
				sa_params.crypto_params.cipher_algo = G_IPSEC_LA_ALGO_AES_CTR;
				sa_params.crypto_params.iv = kzalloc(sizeof(pSA->SAParams.ucNounceIVCounter), GFP_KERNEL);
				if (sa_params.crypto_params.iv)
					memcpy(sa_params.crypto_params.iv, pSA->SAParams.ucNounceIVCounter,
						AES_CTR_SALT_LEN);
				else
					goto api_err;
				sa_params.crypto_params.iv_len_bits = AES_CTR_SALT_LEN*8;
				break;
			case SECFP_AES_CCM_ICV8:
			case SECFP_AES_CCM_ICV12:
			case SECFP_AES_CCM_ICV16:
				sa_params.crypto_params.cipher_algo = G_IPSEC_LA_ALGO_COMB_AES_CCM;
				sa_params.crypto_params.icv_len_bits = pSA->SAParams.uICVSize*8;
				sa_params.crypto_params.block_size = AES_CCM_BLOCK_SIZE;
				sa_params.crypto_params.iv = kzalloc(sizeof(pSA->SAParams.ucNounceIVCounter), GFP_KERNEL);
				if (sa_params.crypto_params.iv)
					memcpy(sa_params.crypto_params.iv, pSA->SAParams.ucNounceIVCounter,
						AES_CCM_SALT_LEN);
				else
					goto api_err;
				sa_params.crypto_params.iv_len_bits = AES_CCM_SALT_LEN*8;
				break;
			case SECFP_AES_GCM_ICV8:
			case SECFP_AES_GCM_ICV12:
			case SECFP_AES_GCM_ICV16:
				sa_params.crypto_params.cipher_algo = G_IPSEC_LA_ALGO_COMB_AES_GCM;
				sa_params.crypto_params.icv_len_bits = pSA->SAParams.uICVSize*8;
				sa_params.crypto_params.block_size = AES_GCM_BLOCK_SIZE;
				sa_params.crypto_params.iv = kzalloc(sizeof(pSA->SAParams.ucNounceIVCounter), GFP_KERNEL);
				if (sa_params.crypto_params.iv)
					memcpy(sa_params.crypto_params.iv, pSA->SAParams.ucNounceIVCounter,
						AES_GCM_SALT_LEN);
				else
					goto api_err;
				sa_params.crypto_params.iv_len_bits = AES_GCM_SALT_LEN*8;				
				break;
			case SECFP_NULL_AES_GMAC:
				sa_params.crypto_params.cipher_algo= G_IPSEC_LA_ALGO_COMB_AES_GMAC;
				sa_params.crypto_params.block_size = AES_GMAC_BLOCK_SIZE;
				sa_params.crypto_params.icv_len_bits= pSA->SAParams.uICVSize;
				sa_params.crypto_params.iv = kzalloc(sizeof(pSA->SAParams.ucNounceIVCounter), GFP_KERNEL);
				if (sa_params.crypto_params.iv)
					memcpy(sa_params.crypto_params.iv, pSA->SAParams.ucNounceIVCounter,
						AES_GMAC_SALT_LEN);
				else
					goto api_err;
				sa_params.crypto_params.iv_len_bits = AES_GMAC_SALT_LEN*8;	
				break;
				
			case SECFP_ESP_NULL:
				sa_params.crypto_params.cipher_algo = G_IPSEC_LA_CIPHER_ALGO_NULL;
				sa_params.crypto_params.block_size = 4;
				break;
			default:
				ASF_VIO_DEBUG("Invalid ucEncryptAlgo");
				goto api_err;
		}
	}


	if (pSA->SAParams.bEncapsulationMode == ASF_IPSEC_SA_SAFLAGS_TRANSPORTMODE)
			sa_params.cmn_flags |= G_IPSEC_LA_SA_ENCAP_TRANSPORT_MODE;

	resp_a.cb_fn = vioips_sa_add_cbfn;
	resp_a.cb_arg = NULL;
	resp_a.cb_arg_len = 0;		
	flags_a =  0 /* for a-sync mode */;
	//flags_a = G_IPSEC_LA_CTRL_FLAG_ASYNC /* for sync mode */;

	dbg_prt_blk("===asf device:\n", _asf_device, sizeof(struct asf_vdev_info));
	dbg_prt_sa_parms(__func__, &in);
	if (_asf_device == NULL) {
		printk("##### _asf_device is NULL\n");
		goto api_err;
	}

	out.result = 0xFFFFFFFF;
	ret = g_ipsec_la_sa_add(&_asf_device->handle, &in, flags_a, &out, &resp_a);
	//ret = virt_ipsec_sa_add(&_asf_device->handle, &in, flags_a, &out, &resp_a);
	if (ret != 0) {
		printk("##### virt_ipsec_sa_add returned error %d in %s %d \r\n", ret, __FUNCTION__, __LINE__);
		goto api_err;
	}
#if 0
	for (ret = 500; ret > 0; --ret) {
		msleep_interruptible(10);
		if (out.result != 0xFFFFFFFF) break;
	}
	if (ret == 0) {
		printk("##### g_ipsec_la_sa_add response timeout\n");
		ret = ASF_FAILURE;
		goto api_err;
	}
	ret = ASF_SUCCESS;
#endif
	memcpy(pSA->sa_handle, (void *)&out.handle, G_IPSEC_LA_SA_HANDLE_SIZE);
	printk("##### virt_ipsec_sa_add returned %d handle 0x%x:0x%x\n", out.result,
		*(u32 *)pSA->sa_handle, *(u32 *)(pSA->sa_handle + 4));

api_err:
	if (sa_params.crypto_params.iv != NULL)
		kfree(sa_params.crypto_params.iv);
	if (sa_params.crypto_params.cipher_key != NULL)
		kfree(sa_params.crypto_params.cipher_key);
	if (sa_params.crypto_params.auth_key != NULL)
		kfree(sa_params.crypto_params.auth_key);
	if (ret) printk("%s failed\n", __func__);
	return ret;
}

int32_t secfp_createOutSAVIpsec(outSA_t *pSA)
{
	struct g_ipsec_la_sa_add_inargs in;
	struct g_ipsec_la_sa_add_outargs out;
	struct g_ipsec_la_sa sa_params; 
	struct g_ipsec_la_resp_args resp_a;
	enum g_ipsec_la_control_flags flags_a;
	int ret = ASF_FAILURE;

	in.dir = G_IPSEC_LA_SA_OUTBOUND;
	in.num_sas = 1;
	in.sa_params = &sa_params;

	sa_params.crypto_params.iv = NULL;
	sa_params.crypto_params.cipher_key= NULL;
	sa_params.crypto_params.auth_key= NULL;
	sa_params.spi = pSA->SAParams.ulSPI;
	sa_params.proto = pSA->SAParams.ucProtocol;
	sa_params.cmn_flags = 0;

	if (pSA->SAParams.bDoUDPEncapsulationForNATTraversal) {
		sa_params.cmn_flags |= G_IPSEC_LA_SA_DO_UDP_ENCAP_FOR_NAT_TRAVERSAL;
		sa_params.nat_info.dest_port = pSA->SAParams.IPsecNatInfo.usDstPort;
		sa_params.nat_info.src_port = pSA->SAParams.IPsecNatInfo.usSrcPort;
		sa_params.nat_info.nat_oa_peer_addr.version = G_IPSEC_LA_IPV4;
		sa_params.nat_info.nat_oa_peer_addr.ipv4 = pSA->SAParams.IPsecNatInfo.ulNATt;
	}

	if (pSA->SAParams.bPropogateECN)
		sa_params.cmn_flags |= G_IPSEC_LA_SA_USE_ECN;

	if (pSA->SAParams.bDoAntiReplayCheck)
		sa_params.cmn_flags |= G_IPSEC_LA_SA_DO_ANTI_REPLAY_CHECK;

	if (pSA->SAParams.bEncapsulationMode == ASF_IPSEC_SA_SAFLAGS_TRANSPORTMODE)
		sa_params.cmn_flags |= G_IPSEC_LA_SA_ENCAP_TRANSPORT_MODE;
	else {
		if(pSA->SAParams.tunnelInfo.bIPv4OrIPv6) { /* IPv6 */

		sa_params.te_addr.src_ip.version = G_IPSEC_LA_IPV6;
			
		memcpy(sa_params.te_addr.dest_ip.ipv6.w_addr,
			pSA->SAParams.tunnelInfo.addr.iphv6.daddr, 4);
		memcpy(sa_params.te_addr.src_ip.ipv6.w_addr,
			pSA->SAParams.tunnelInfo.addr.iphv6.saddr, 4);
			
		}
		else {
			sa_params.te_addr.dest_ip.version = G_IPSEC_LA_IPV4;
			sa_params.te_addr.dest_ip.ipv4 = pSA->SAParams.tunnelInfo.addr.iphv4.daddr;

			sa_params.te_addr.src_ip.version = G_IPSEC_LA_IPV4;
			sa_params.te_addr.dest_ip.ipv4 = pSA->SAParams.tunnelInfo.addr.iphv4.saddr;
		}
	}

	if (pSA->SAParams.bUseExtendedSequenceNumber)
		sa_params.cmn_flags |= G_IPSEC_LA_SA_USE_ESN;

	if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6 == 1)
		sa_params.cmn_flags |= G_IPSEC_LA_SA_USE_IPv6;

	sa_params.anti_replay_window_size= pSA->SAParams.AntiReplayWin; /* Need to check this */

	sa_params.crypto_params.bAuth = pSA->SAParams.bAuth;
	sa_params.crypto_params.bEncrypt = pSA->SAParams.bEncrypt; /* Need to check virtio message framing */
		
	if (pSA->SAParams.bAuth) {

		sa_params.crypto_params.auth_key = kzalloc((pSA->SAParams.AuthKeyLen),GFP_KERNEL);
		memcpy(sa_params.crypto_params.auth_key, pSA->SAParams.ucAuthKey, pSA->SAParams.AuthKeyLen);
		sa_params.crypto_params.auth_key_len_bits = pSA->SAParams.AuthKeyLen*8;

		sa_params.crypto_params.icv_len_bits = pSA->SAParams.uICVSize;
		switch (pSA->SAParams.ucAuthAlgo) {
		case SECFP_HMAC_MD5:
			sa_params.crypto_params.auth_algo = G_IPSEC_LA_AUTH_ALGO_MD5_HMAC;
			break;
		case SECFP_HMAC_SHA1:
			sa_params.crypto_params.auth_algo = G_IPSEC_LA_AUTH_ALGO_SHA1_HMAC;
			break;
		case SECFP_HMAC_AES_XCBC_MAC:
			sa_params.crypto_params.auth_algo = G_IPSEC_LA_AUTH_AESXCBC;
			break;
		case SECFP_HMAC_SHA256:
			sa_params.crypto_params.auth_algo = G_IPSEC_LA_AUTH_ALGO_SHA2_256_HMAC;
			break;
		case SECFP_HMAC_SHA384:
			sa_params.crypto_params.auth_algo = G_IPSEC_LA_AUTH_ALGO_SHA2_384_HMAC;
			break;
		case SECFP_HMAC_SHA512:
			sa_params.crypto_params.auth_algo = G_IPSEC_LA_AUTH_ALGO_SHA2_512_HMAC;
			break;
		default:
			ASF_VIO_DEBUG("Invalid ucAuthAlgo");
			return -1;
			}
	}

					
	if (pSA->SAParams.bEncrypt) {
			
		sa_params.crypto_params.cipher_key= kzalloc((pSA->SAParams.EncKeyLen),GFP_KERNEL);
		memcpy(sa_params.crypto_params.cipher_key, pSA->SAParams.ucEncKey, pSA->SAParams.EncKeyLen);
		sa_params.crypto_params.cipher_key_len_bits= pSA->SAParams.EncKeyLen*8;

		sa_params.crypto_params.block_size = pSA->SAParams.ulBlockSize;
		sa_params.crypto_params.iv_len_bits = 0;
			
		switch (pSA->SAParams.ucCipherAlgo) {
			case SECFP_DES:
				sa_params.crypto_params.cipher_algo = G_IPSEC_LA_ALGO_DES_CBC;
				break;
			case SECFP_3DES:
				sa_params.crypto_params.cipher_algo = G_IPSEC_LA_ALGO_3DES_CBC;
				break;
			case SECFP_AES:
				sa_params.crypto_params.cipher_algo = G_IPSEC_LA_ALGO_AES_CBC;
				break;
			case SECFP_AESCTR:
				sa_params.crypto_params.cipher_algo = G_IPSEC_LA_ALGO_AES_CTR;
				sa_params.crypto_params.iv = kzalloc(sizeof(pSA->SAParams.ucNounceIVCounter), GFP_KERNEL);
				if (sa_params.crypto_params.iv)
					memcpy(sa_params.crypto_params.iv, pSA->SAParams.ucNounceIVCounter,
						AES_CTR_SALT_LEN);
				else
					goto api_error;
				sa_params.crypto_params.iv_len_bits = AES_CTR_SALT_LEN*8;
				break;
			case SECFP_AES_CCM_ICV8:
			case SECFP_AES_CCM_ICV12:
			case SECFP_AES_CCM_ICV16:
				sa_params.crypto_params.cipher_algo = G_IPSEC_LA_ALGO_COMB_AES_CCM;
				sa_params.crypto_params.icv_len_bits = pSA->SAParams.uICVSize*8;
				sa_params.crypto_params.block_size = AES_CCM_BLOCK_SIZE;
				sa_params.crypto_params.iv = kzalloc(sizeof(pSA->SAParams.ucNounceIVCounter), GFP_KERNEL);
				if (sa_params.crypto_params.iv)
					memcpy(sa_params.crypto_params.iv, pSA->SAParams.ucNounceIVCounter,
						AES_CCM_SALT_LEN);
				else
					goto api_error;
				sa_params.crypto_params.iv_len_bits = AES_CCM_SALT_LEN*8;
				break;
			case SECFP_AES_GCM_ICV8:
			case SECFP_AES_GCM_ICV12:
			case SECFP_AES_GCM_ICV16:
				sa_params.crypto_params.cipher_algo = G_IPSEC_LA_ALGO_COMB_AES_GCM;
				sa_params.crypto_params.icv_len_bits = pSA->SAParams.uICVSize*8;
				sa_params.crypto_params.block_size = AES_GCM_BLOCK_SIZE;
				sa_params.crypto_params.iv = kzalloc(sizeof(pSA->SAParams.ucNounceIVCounter), GFP_KERNEL);
				if (sa_params.crypto_params.iv)
					memcpy(sa_params.crypto_params.iv, pSA->SAParams.ucNounceIVCounter,
						AES_GCM_SALT_LEN);
				else
					goto api_error;
				sa_params.crypto_params.iv_len_bits = AES_GCM_SALT_LEN*8;				
				break;
			case SECFP_NULL_AES_GMAC:
				sa_params.crypto_params.cipher_algo= G_IPSEC_LA_ALGO_COMB_AES_GMAC;
				sa_params.crypto_params.block_size = AES_GMAC_BLOCK_SIZE;
				sa_params.crypto_params.icv_len_bits= pSA->SAParams.uICVSize;
				sa_params.crypto_params.iv = kzalloc(sizeof(pSA->SAParams.ucNounceIVCounter), GFP_KERNEL);
				if (sa_params.crypto_params.iv)
					memcpy(sa_params.crypto_params.iv, pSA->SAParams.ucNounceIVCounter,
						AES_GMAC_SALT_LEN);
				else
					goto api_error;
				sa_params.crypto_params.iv_len_bits = AES_GMAC_SALT_LEN*8;	
				break;
				
			case SECFP_ESP_NULL:
				sa_params.crypto_params.cipher_algo = G_IPSEC_LA_CIPHER_ALGO_NULL;
				sa_params.crypto_params.block_size = 4;
				break;
			default:
				ASF_VIO_DEBUG("Invalid ucEncryptAlgo");
				goto api_error;
		}
	}

	if (pSA->SAParams.bCopyDscp == 1){
		sa_params.outb.dscp_handle = G_IPSEC_LA_DSCP_COPY;
		} else {
		sa_params.outb.dscp_handle = G_IPSEC_LA_DSCP_SET;
		sa_params.outb.dscp = pSA->SAParams.ucDscp;
	}
		
	switch (pSA->SAParams.handleDf) {
		case  SECFP_DF_COPY:
			sa_params.outb.df_bit_handle = G_IPSEC_LA_DF_COPY;
			break;
		case SECFP_DF_CLEAR:
			sa_params.outb.df_bit_handle = G_IPSEC_LA_DF_CLEAR;
			break;
		case SECFP_DF_SET:
			sa_params.outb.df_bit_handle = G_IPSEC_LA_DF_SET;
			break;
		default:
			goto api_error;
		}
	
	switch (pSA->SAParams.handleDf) {
		case SECFP_DF_CLEAR:
			sa_params.outb.df_bit_handle = G_IPSEC_LA_DF_CLEAR;
			break;
		case SECFP_DF_SET:
			sa_params.outb.df_bit_handle = G_IPSEC_LA_DF_SET;
			break;
		case SECFP_DF_COPY: /* Revisit AVS 09/02 */
			sa_params.outb.df_bit_handle = G_IPSEC_LA_DF_COPY;
			ASF_VIO_DEBUG("DF Option not handled\n");
			break;
		default:
			goto api_error;
		}

	resp_a.cb_fn = vioips_sa_add_cbfn;
	resp_a.cb_arg = NULL;
	resp_a.cb_arg_len = 0;		
	flags_a =  0 /* for a-sync mode */;
	//flags_a = G_IPSEC_LA_CTRL_FLAG_ASYNC /* for sync mode */;
	dbg_prt_sa_parms(__func__, &in);

	out.result = 0xFFFFFFFF;
	ret = g_ipsec_la_sa_add(&_asf_device->handle, &in, flags_a, &out, &resp_a);
	if (ret != 0) {
		printk("##### virt_ipsec_sa_add returned error %d in %s %d \r\n", ret, __FUNCTION__, __LINE__);
		goto api_error;
	}
#if 0
	for (ret = 500; ret > 0; --ret) {
		msleep_interruptible(10);
		if (out.result != 0xFFFFFFFF) break;
	}
	if (ret == 0) {
		printk("##### g_ipsec_la_sa_add response timeout\n");
		ret = ASF_FAILURE;
		goto api_err;
	}
	ret = ASF_SUCCESS;
#endif
	memcpy(pSA->sa_handle, &out.handle, G_IPSEC_LA_SA_HANDLE_SIZE);
	printk("##### virt_ipsec_sa_add returned %d handle %d:%d\n", out.result,
		*(u32 *)pSA->sa_handle, *(u32 *)(pSA->sa_handle + 4));

api_error:
	if (sa_params.crypto_params.iv != NULL)
		kfree(sa_params.crypto_params.iv);
	if (sa_params.crypto_params.cipher_key != NULL)
		kfree(sa_params.crypto_params.cipher_key);
	if (sa_params.crypto_params.auth_key != NULL)
		kfree(sa_params.crypto_params.auth_key);
	if (ret) printk("%s failed\n", __func__);
	return ret;
}

int32_t secfp_deleteOutSAVIpsec(outSA_t *pSA)
{
	struct g_ipsec_la_sa_del_inargs in;
	struct g_ipsec_la_sa_del_outargs out;
	int ret;
	
	in.dir = G_IPSEC_LA_SA_OUTBOUND;
	memcpy(in.handle, &pSA->sa_handle, G_IPSEC_LA_SA_HANDLE_SIZE);

	ret = g_ipsec_la_sa_del(&_asf_device->handle,&in,0,&out,NULL);

	return ret;
}

int32_t secfp_deleteInSAVIpsec(inSA_t *pSA)
{
	struct g_ipsec_la_sa_del_inargs in;
	struct g_ipsec_la_sa_del_outargs out;
	int ret;
	
	in.dir = G_IPSEC_LA_SA_INBOUND;
	memcpy(in.handle, &pSA->sa_handle, G_IPSEC_LA_SA_HANDLE_SIZE);

	ret = g_ipsec_la_sa_del(&_asf_device->handle,&in,0,&out,NULL);

	return ret;
}

/* TBD */
/* handle callback function */
void secfp_encap_complete_cbk(void *cb_arg, int32_t cb_arg_len, void *outargs)
{
	secfp_outComplete(NULL,NULL, cb_arg,(int)(outargs));
}


int32_t secfp_vio_encap(outSA_t *pSA,
	 struct sk_buff *skb, 
	 void (*cbk)(struct device *dev, u32 *desc,
				u32 status, void *areq),
		    void *areq)
{
	int ret;
	struct g_ipsec_la_data in_data, out_data;
	struct g_ipsec_la_resp_args resp;
	/* Need to handle resp callback function */

	/* to check this out */
	in_data.buffer = skb->data;
	in_data.length = skb->len;

	out_data.buffer = skb->data;
	out_data.length = skb->len;

	resp.cb_fn = secfp_encap_complete_cbk;
	resp.cb_arg = areq;
	resp.cb_arg_len = sizeof(areq);

		
	ret = g_ipsec_la_packet_encap(&_asf_device->handle, G_IPSEC_LA_CTRL_FLAG_ASYNC,
		pSA->sa_handle, 1, &in_data, &out_data, &resp);

	return ret;
}


void secfp_decap_complete_cbk(void *cb_arg, int32_t cb_arg_len, void *outargs)
{
	secfp_inComplete(NULL, NULL, cb_arg,(int)(outargs));
}

int32_t secfp_vio_decap(inSA_t *pSA,
		struct sk_buff *skb,
		void (*cbk)(struct device *dev, u32 *desc,
			u32 status, void *areq),
			void *areq)
{
	struct g_ipsec_la_data in_data, out_data;
	struct g_ipsec_la_resp_args resp;
	int ret;
	/* Need to handle resp callback function */

	/* to check this out */
	in_data.buffer = skb->data;
	in_data.length = skb->len;

	out_data.buffer = skb->data;
	out_data.length = skb->len;


	resp.cb_fn = secfp_decap_complete_cbk;
	resp.cb_arg = areq;
	resp.cb_arg_len = sizeof(areq);
	
	ret = g_ipsec_la_packet_decap(&_asf_device->handle,G_IPSEC_LA_CTRL_FLAG_ASYNC,
		pSA->sa_handle ,1,&in_data, &out_data,&resp);

	return ret;
}




