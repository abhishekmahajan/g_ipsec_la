/*
#    Copyright (c) 2016 Intel Corporation.
#    All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
*/


#include <linux/string.h>
#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/skbuff.h>
#include "../../asfffp/driver/asftmr.h"
#include "../../asfffp/driver/asf.h"
#include "../../asfffp/driver/asfipsec.h"
#include "ipsfpapi.h"
#include "ipsecfp.h"
#include <crypto/aead.h>
#include <crypto/authenc.h>
#include <crypto/internal/aead.h>
#include <net/esp.h>
#include <net/xfrm.h>
#include <linux/crypto.h>
#include "ipsec_linux_crypto.h"

#define MAX_AUTH_ENC_ALGO	8
#define MAX_ALGO_TYPE		2

//GLobal
//Pointer to in/out AEAD structures 
static struct crypto_aead *ptr_aead_out[AEAD_ARRAY_SIZE];
static struct crypto_aead *ptr_aead_in[AEAD_ARRAY_SIZE];

//Sequence number corresponding to AEAD
static struct Seq_output seq_output[AEAD_ARRAY_SIZE];

struct algo_info {
	const char *alg_name;
	int alg_type;
};

enum alg_type {
	ENCRYPTION = 0,
	AUTHENTICATION,
	INVALID
};

static const struct algo_info asf_algo_types[MAX_ALGO_TYPE][MAX_AUTH_ENC_ALGO] = {
	{
		{"cbc(aes)", ASF_IPSEC_EALG_AES},
		{"cbc(des3_ede)", ASF_IPSEC_EALG_3DESCBC},
		{"cbc(des)", ASF_IPSEC_EALG_DESCBC},
		{"rfc3686(ctr(aes))", ASF_IPSEC_EALG_AES_CTR},
		{"rfc4309(ccm(aes))", ASF_IPSEC_EALG_AES_CCM_ICV8},
		{"rfc4106(gcm(aes))", ASF_IPSEC_EALG_AES_GCM_ICV8},
		{"rfc4543(gcm(aes))", ASF_IPSEC_EALG_NULL_AES_GMAC},
		{NULL, -1}
	},
	{
		{"hmac(sha1)", ASF_IPSEC_AALG_SHA1HMAC},
		{"hmac(sha256)", ASF_IPSEC_AALG_SHA256HMAC},
		{"hmac(sha384)", ASF_IPSEC_AALG_SHA384HMAC},
		{"hmac(sha512)", ASF_IPSEC_AALG_SHA512HMAC},
		{"hmac(md5)", ASF_IPSEC_AALG_MD5HMAC},
		{"xcbc(aes)", ASF_IPSEC_AALG_AESXCBC},
		{"digest_null", ASF_IPSEC_AALG_NONE},
		{NULL, -1}
	}
};

struct esp_skb_cb {
	struct xfrm_skb_cb xfrm;
	void *tmp;
};

#define ESP_SKB_CB(__skb) ((struct esp_skb_cb *)&((__skb)->cb[0]))

static inline __be32 *esp_tmp_seqhi(void *tmp)
{
	ASF_FP_LINUX_CRYPTO_FENTRY;	
	ASF_FP_LINUX_CRYPTO_FEXIT;
	return PTR_ALIGN((__be32 *)tmp, __alignof__(__be32));
}

static inline void asf_aead_request_set_ad(struct aead_request *req,
                                       unsigned int assoclen)
{
	req->assoclen = assoclen;
}

static inline struct scatterlist *esp_givreq_sg(
        struct crypto_aead *aead, struct aead_givcrypt_request *req)
{
	ASF_FP_LINUX_CRYPTO_FENTRY;	
	ASF_FP_LINUX_CRYPTO_FEXIT;
	return (void *)ALIGN((unsigned long)(req + 1) +
						  crypto_aead_reqsize(aead),
						  __alignof__(struct scatterlist));

}

static inline struct scatterlist *esp_req_sg(struct crypto_aead *aead,
    struct aead_request *req)
{
	ASF_FP_LINUX_CRYPTO_FENTRY;	
	ASF_FP_LINUX_CRYPTO_FEXIT;
	return (void *)ALIGN((unsigned long)(req + 1) + 
						  crypto_aead_reqsize(aead),
						  __alignof__(struct scatterlist));
}

/* Get encryption algo name by length.
*/
static inline const char * ealg_getnamebylength(int len_type)
{
	int i;
	ASF_FP_LINUX_CRYPTO_FENTRY;	

	if(len_type == ASF_IPSEC_EALG_AES_CCM_ICV8 ||
	   len_type == ASF_IPSEC_EALG_AES_CCM_ICV12 || 
	   len_type == ASF_IPSEC_EALG_AES_CCM_ICV16 )
	{
		len_type = ASF_IPSEC_EALG_AES_CCM_ICV8;
	}
	if(len_type == ASF_IPSEC_EALG_AES_GCM_ICV8 ||
		len_type == ASF_IPSEC_EALG_AES_GCM_ICV12 || 
		len_type == ASF_IPSEC_EALG_AES_GCM_ICV16 )
	{
		len_type = ASF_IPSEC_EALG_AES_GCM_ICV8;
	}
	for(i=0; ;i++) 
	{
		const struct algo_info *info = &asf_algo_types[ENCRYPTION][i];
		if (info->alg_type == -1)
			break;
		else if (info->alg_type == len_type)
		{              
			ASF_FP_LINUX_CRYPTO_FEXIT;
			return info->alg_name;
		}
	}
	ASF_FP_LINUX_CRYPTO_FEXIT;
	return NULL;
}

/* Get auth algo name by length.
*/
static inline const char * aalg_getnamebylength(int len_type)
{
	int i;
	ASF_FP_LINUX_CRYPTO_FENTRY;	
	for(i=0; ;i++) 
	{              
		const struct algo_info *info = &asf_algo_types[AUTHENTICATION][i];
		if(unlikely(info->alg_type == -1))
			break;
		if(info->alg_type == len_type)
		{
			ASF_FP_LINUX_CRYPTO_FEXIT;
			return info->alg_name;
		}
	}
	ASF_FP_LINUX_CRYPTO_FEXIT;
	return NULL;
}

/* To hex dump the data of packet for debugging.
*/
void asf_ipsec_hex_dump(u8 *ptr, unsigned int len)
{
	int i;
	printk("HEX DUMP : ptr = 0x%x, length = %u\n", ptr, len);
	for(i=0; i < len; i++)
	{
		printk("0x%02x ", *ptr++);
	}
	printk("\n");
}
/* This function is used to copy data.
*/
inline void asf_mem_cpy(u8 *ptr, int offset, unsigned int len)
{
	/*int i;
	for(i=0; i < len; i++)
	{
		*(ptr + offset) = *(ptr);
		ptr++;
	}*/
	asfCopyWords((unsigned int*)(ptr + offset), (unsigned int*)ptr, len);
}

/* Get auth algo name from authalgo
*/
static const char * get_auth_algo(unsigned char ucAuthAlgo) 
{
	unsigned int auth_algo;
	ASF_FP_LINUX_CRYPTO_FENTRY;	

	switch (ucAuthAlgo)
	{
		case SECFP_HMAC_MD5:
			auth_algo = ASF_IPSEC_AALG_MD5HMAC;
			break;
		case SECFP_HMAC_SHA1:
			auth_algo = ASF_IPSEC_AALG_SHA1HMAC;
			break;
		case SECFP_HMAC_AES_XCBC_MAC:
			auth_algo = ASF_IPSEC_AALG_AESXCBC;
			break;
		case SECFP_HMAC_SHA256:
			auth_algo = ASF_IPSEC_AALG_SHA256HMAC;
			break;
		case SECFP_HMAC_SHA384:
			auth_algo = ASF_IPSEC_AALG_SHA384HMAC;
			break;
		case SECFP_HMAC_SHA512:
			auth_algo = ASF_IPSEC_AALG_SHA512HMAC;
			break;
		case SECFP_HMAC_NULL:
			auth_algo = ASF_IPSEC_AALG_NONE;
			break;
		default:
			ASF_FP_LINUX_CRYPTO_WARN("unsupported auth algo %d\n",
							ucAuthAlgo);
			ASF_FP_LINUX_CRYPTO_FEXIT;
			return NULL;
	}
	ASF_FP_LINUX_CRYPTO_FEXIT;
	return aalg_getnamebylength(auth_algo);
}

/* Get algo name for kernel from ciperAlgo 
*/
static const char * get_enc_algo(unsigned char ucCipherAlgo) 
{
	unsigned int enc_algo;
	ASF_FP_LINUX_CRYPTO_FENTRY;	
	switch(ucCipherAlgo)
	{
		case SECFP_DES :
			enc_algo = ASF_IPSEC_EALG_DESCBC;
			break;
		case SECFP_3DES:
			enc_algo = ASF_IPSEC_EALG_3DESCBC;
			break;
		case SECFP_AES:
			enc_algo = ASF_IPSEC_EALG_AES;
			break;
		case SECFP_AESCTR:
			enc_algo = ASF_IPSEC_EALG_AES_CTR;
			break;
		case SECFP_AES_CCM_ICV8:
			enc_algo = ASF_IPSEC_EALG_AES_CCM_ICV8;
			break;
		case SECFP_AES_CCM_ICV12:
			enc_algo = ASF_IPSEC_EALG_AES_CCM_ICV12;
			break;
		case SECFP_AES_CCM_ICV16:
			enc_algo = ASF_IPSEC_EALG_AES_CCM_ICV16;
			break;
		case SECFP_AES_GCM_ICV8:
			enc_algo = ASF_IPSEC_EALG_AES_GCM_ICV8;
			break;
		case SECFP_AES_GCM_ICV12:
			enc_algo = ASF_IPSEC_EALG_AES_GCM_ICV12;
			break;
		case SECFP_AES_GCM_ICV16:
			enc_algo = ASF_IPSEC_EALG_AES_GCM_ICV16;
			break;
		case SECFP_NULL_AES_GMAC:
			enc_algo = ASF_IPSEC_EALG_NULL_AES_GMAC;
			break;
		case SECFP_ESP_NULL:
			enc_algo = ASF_IPSEC_EALG_NULL;
			break;
		default:
			ASF_FP_LINUX_CRYPTO_DEBUG("unsupported encr algo %d\n",
							ucCipherAlgo);
			ASF_FP_LINUX_CRYPTO_FEXIT;
			return NULL;
	}
	ASF_FP_LINUX_CRYPTO_FEXIT;
	return ealg_getnamebylength(enc_algo); 
}

static inline struct aead_request *esp_tmp_req(struct crypto_aead *aead, u8 *iv)
{
	struct aead_request *req;
	ASF_FP_LINUX_CRYPTO_FENTRY;	

	req = (void *)PTR_ALIGN(iv + crypto_aead_ivsize(aead),
							crypto_tfm_ctx_alignment());
	aead_request_set_tfm(req, aead);

	ASF_FP_LINUX_CRYPTO_FEXIT;
	return req;
}

static inline struct aead_givcrypt_request *esp_tmp_givreq(
        struct crypto_aead *aead, u8 *iv)
{
	struct aead_givcrypt_request *req;
	ASF_FP_LINUX_CRYPTO_FENTRY;	

	req = (void *)PTR_ALIGN(iv + crypto_aead_ivsize(aead),
							crypto_tfm_ctx_alignment());
	aead_givcrypt_set_tfm(req, aead);
	ASF_FP_LINUX_CRYPTO_FEXIT;
	return req;
}

static inline u8 *esp_tmp_iv(struct crypto_aead *aead, void *tmp, int seqhilen)
{
	ASF_FP_LINUX_CRYPTO_FENTRY;	
	ASF_FP_LINUX_CRYPTO_FEXIT;
	return crypto_aead_ivsize(aead) ? PTR_ALIGN((u8 *)tmp + seqhilen,
			crypto_aead_alignmask(aead) + 1) : tmp + seqhilen;
}

/* This function is to get mtu size
   Currently this function is not used.
*/
static u32 get_mtu_size(struct crypto_aead *aead, int mtu)
{
	u32 mtu_size = 1456; //todo
	ASF_FP_LINUX_CRYPTO_FENTRY;	
#if 0
	//struct crypto_aead *aead = x->data;
	u32 blksize = ALIGN(crypto_aead_blocksize(aead), 4);
	unsigned int net_adj;

	// Tunnel mode
	int x_props_mode = XFRM_MODE_TUNNEL; //1  
	int x_props_header_len = 44;

	ASF_FP_LINUX_CRYPTO_DEBUG("Entered Function get_mtu_size()");
		
	//switch (x->props.mode) {
	switch (x_props_mode) {
	case XFRM_MODE_TRANSPORT:
	case XFRM_MODE_BEET:
			net_adj = sizeof(struct iphdr);
			break;
	case XFRM_MODE_TUNNEL:
			net_adj = 0;
			break;
	default:
			BUG();
	}

	ASF_FP_LINUX_CRYPTO_DEBUG("About to Exit Function get_mtu_size()");
	//return ((mtu - x->props.header_len - crypto_aead_authsize(aead) -
	//return ((mtu - x_props_header_len - crypto_aead_authsize(aead) -
				//net_adj) & ~(blksize - 1)) + net_adj - 2;
	/*  Return MTU as 1400 */
#endif
	ASF_FP_LINUX_CRYPTO_FEXIT;
	return mtu_size;
}

/* Allocate an AEAD request structure with extra space for SG and IV.
 *
 * For alignment considerations the IV is placed at the front, followed
 * by the request and finally the SG list.
 */
static void *esp_alloc_tmp(struct crypto_aead *aead, int nfrags, int seqhilen)
{
	unsigned int len;

	ASF_FP_LINUX_CRYPTO_FENTRY;	

	len = seqhilen;
	len += crypto_aead_ivsize(aead);

	if (likely(len)) {
		len += crypto_aead_alignmask(aead) &
				~(crypto_tfm_ctx_alignment() - 1);
		len = ALIGN(len, crypto_tfm_ctx_alignment());
	}

        len += sizeof(struct aead_givcrypt_request) + crypto_aead_reqsize(aead);
	len = ALIGN(len, __alignof__(struct scatterlist));

	len += sizeof(struct scatterlist) * nfrags;

	ASF_FP_LINUX_CRYPTO_FEXIT;
	return kmalloc(len, GFP_ATOMIC);
}

/* Allocate out aead at the time of creation of new out SA. 
   pSA : pointer to out SA
   ptr_aead : pointer to crypto_aead created corresponding to SA
*/
int32_t asf_alloc_aead_out(outSA_t *pSA, struct crypto_aead ** ptr_aead)
{
	struct crypto_aead * aead = NULL;
	struct crypto_authenc_key_param *param;
	struct rtattr *rta;
	char *key;
	char *p;
	char authenc_name[CRYPTO_MAX_ALG_NAME];
	unsigned int keylen;
	int err;
	int aeadAlgo = 0;
	int saltLen=0;

	ASF_FP_LINUX_CRYPTO_FENTRY;	
        err = -EINVAL;
        if(unlikely(!(pSA->SAParams.bEncrypt)))
                goto error;

        err = -ENAMETOOLONG;

	//Check if AEAD algorithm
	if(pSA->SAParams.ucCipherAlgo >= 14 && pSA->SAParams.ucCipherAlgo < 24)
	{
		aeadAlgo = 1;
		if(unlikely(snprintf(authenc_name,CRYPTO_MAX_ALG_NAME,"%s", 
			get_enc_algo(pSA->SAParams.ucCipherAlgo)) >= CRYPTO_MAX_ALG_NAME))
		goto error;
	}
        else
	{
	    ASF_FP_LINUX_CRYPTO_DEBUG("test: asf_alloc_aead_out -Not AEAD ALOGO \
			pSA->SAParams.ucCipherAlgo = %d: %d \n", 
			pSA->SAParams.ucCipherAlgo, __LINE__);
            if (pSA->SAParams.bUseExtendedSequenceNumber)
            {
                if(unlikely(snprintf(authenc_name, CRYPTO_MAX_ALG_NAME,
                            "authencesn(%s,%s)",
                            pSA->SAParams.bAuth ? get_auth_algo(pSA->SAParams.ucAuthAlgo) : 
			    "digest_null", 
                            get_enc_algo(pSA->SAParams.ucCipherAlgo)) >= CRYPTO_MAX_ALG_NAME))
                        goto error;
            } 
            else 
            {
                if(unlikely (snprintf(authenc_name, CRYPTO_MAX_ALG_NAME,
                             "authenc(%s,%s)",
                             pSA->SAParams.bAuth ? get_auth_algo(pSA->SAParams.ucAuthAlgo) : 
			     "digest_null", 
                             get_enc_algo(pSA->SAParams.ucCipherAlgo)) >= CRYPTO_MAX_ALG_NAME) )
                        goto error;
            }
	}
	ASF_FP_LINUX_CRYPTO_DEBUG("asf_alloc_aead_out authenc_name = %s: %d\n", 
			authenc_name, __LINE__);
        aead = crypto_alloc_aead(authenc_name, 0, 0);
        err = PTR_ERR(aead);
        if(unlikely (IS_ERR(aead)))
                goto error;
	if(!aeadAlgo)
	{
        	keylen = (pSA->SAParams.bAuth ? pSA->SAParams.AuthKeyLen : 0) +
                	pSA->SAParams.EncKeyLen + RTA_SPACE(sizeof(*param));
        	err = -ENOMEM;
        	key = kmalloc(keylen, GFP_KERNEL);

		ASF_FP_LINUX_CRYPTO_DEBUG("asf_alloc_aead_out keylen = %d \
			pSA->SAParams.EncKeyLen = %d pSA->SAParams.AuthKeyLen = %d \
			: %d\n", keylen, pSA->SAParams.EncKeyLen, 
			pSA->SAParams.AuthKeyLen, __LINE__);

        	if(unlikely (!key))
                	goto error;
	}
	else
	{
                switch(pSA->SAParams.ucCipherAlgo)
                {
                        case SECFP_AESCTR:
                                saltLen = AES_CTR_SALT_LEN;
                        break;
                        case SECFP_AES_CCM_ICV8:
                        case SECFP_AES_CCM_ICV12:
                        case SECFP_AES_CCM_ICV16:
                                saltLen = AES_CCM_SALT_LEN;
                        break;
                        case SECFP_AES_GCM_ICV8:
                        case SECFP_AES_GCM_ICV12:
                        case SECFP_AES_GCM_ICV16:
                                saltLen = AES_GCM_SALT_LEN;
                        break;
                        case SECFP_NULL_AES_GMAC:
                                saltLen = AES_GMAC_SALT_LEN;
                        break;
                default:
                        ;
                }

        	keylen = pSA->SAParams.EncKeyLen + saltLen ;
        	err = -ENOMEM;
       		key = kmalloc(keylen, GFP_KERNEL);
        	if(unlikely (!key))
                	goto error;
	}
        p = key;
	if(!aeadAlgo)
	{
        	rta = (void *)p;
        	rta->rta_type = CRYPTO_AUTHENC_KEYA_PARAM;
        	rta->rta_len = RTA_LENGTH(sizeof(*param));
        	param = RTA_DATA(rta);
        	p += RTA_SPACE(sizeof(*param));
        
		if (likely(pSA->SAParams.bAuth)) 
        	{
                	struct xfrm_algo_desc *aalg_desc;
        
                	memcpy(p, pSA->SAParams.ucAuthKey, pSA->SAParams.AuthKeyLen);
                	p += pSA->SAParams.AuthKeyLen;

                	aalg_desc = xfrm_aalg_get_byname(get_auth_algo(pSA->SAParams.ucAuthAlgo), 0);
                	BUG_ON(!aalg_desc);

                	err = -EINVAL;
                	if (aalg_desc->uinfo.auth.icv_fullbits / 8 != crypto_aead_authsize(aead)) 
			{
                        	pr_info("ESP: %s digestsize %u != %hu\n",
                                	get_auth_algo(pSA->SAParams.ucAuthAlgo),
                                	crypto_aead_authsize(aead),
                        	aalg_desc->uinfo.auth.icv_fullbits / 8);
                        	goto free_key;
                	}
		}
	}
	if(aeadAlgo)
	{
	   ASF_FP_LINUX_CRYPTO_DEBUG("asf_alloc_aead_out AEAD algo setkey: %d \n", __LINE__);
           memcpy(p, pSA->SAParams.ucEncKey, (pSA->SAParams.EncKeyLen + saltLen));
      	   err = crypto_aead_setkey(aead, key, keylen);
           if(unlikely (err))
                goto free_key;
	   ASF_FP_LINUX_CRYPTO_DEBUG("asf_alloc_aead_out AEAD algo setauthsize: %d \n", __LINE__);
           err = crypto_aead_setauthsize(aead, pSA->SAParams.uICVSize);
           if(unlikely (err))
              	goto free_key;
	}
	else
	{	
		ASF_FP_LINUX_CRYPTO_DEBUG("asf_alloc_aead_out not a AEAD algo setauthsize: %d \n",
				 __LINE__);
      		err = crypto_aead_setauthsize(aead, pSA->SAParams.uICVSize);
        	if(unlikely (err))
        	      	goto free_key;
        	param->enckeylen = cpu_to_be32(pSA->SAParams.EncKeyLen);
        	memcpy(p, pSA->SAParams.ucEncKey, (pSA->SAParams.EncKeyLen));
        
		ASF_FP_LINUX_CRYPTO_DEBUG("asf_alloc_aead_out not a AEAD algo setkey: %d \n", __LINE__);
        	err = crypto_aead_setkey(aead, key, keylen);
        	if(unlikely (err))
         	       goto free_key;
	}
        
       	*ptr_aead = aead;

	ASF_FP_LINUX_CRYPTO_DEBUG("asf_alloc_aead_out  : %d\n", __LINE__);
	//Freekey after successful setting	
       	if(likely(key != NULL))
               	kfree(key);
	ASF_FP_LINUX_CRYPTO_FEXIT;
       	return err;

free_key:
error:
        if(key != NULL)
                kfree(key);
        if(aead != NULL)
                crypto_free_aead(aead);
	ASF_FP_LINUX_CRYPTO_FEXIT;
        return err;
}

/* Allocate in aead at the time of creation of new in SA. 
   pSA : pointer to in SA
   ptr_aead : pointer to crypto_aead created corresponding to in SA
*/
int32_t asf_alloc_aead_in(inSA_t *pSA, struct crypto_aead ** ptr_aead)
{
        struct crypto_aead * aead = NULL;
        struct crypto_authenc_key_param *param;
        struct rtattr *rta;
        char *key;
        char *p;
        char authenc_name[CRYPTO_MAX_ALG_NAME];
        unsigned int keylen;
        int err;
	int aeadAlgo = 0;
	int saltLen=0;

	ASF_FP_LINUX_CRYPTO_FENTRY;	

        err = -EINVAL;
        if(unlikely(!(pSA->SAParams.bEncrypt)))
                goto error;

        err = -ENAMETOOLONG;
	ASF_FP_LINUX_CRYPTO_DEBUG("asf_alloc_aead_in pSA->SAParams.ucCipherAlgo = %d: \
				%d \n", pSA->SAParams.ucCipherAlgo, __LINE__);

	//Check if AEAD algorithm
	if(likely(pSA->SAParams.ucCipherAlgo >= 14 && pSA->SAParams.ucCipherAlgo < 24))
	{
		ASF_FP_LINUX_CRYPTO_DEBUG("asf_alloc_aead_in -AEAD ALOGO \
			pSA->SAParams.ucCipherAlgo = %d: %d \n", 
			pSA->SAParams.ucCipherAlgo, __LINE__);
		aeadAlgo = 1;
		if(unlikely(snprintf(authenc_name,CRYPTO_MAX_ALG_NAME,"%s", 
			get_enc_algo(pSA->SAParams.ucCipherAlgo)) >= CRYPTO_MAX_ALG_NAME))
		goto error;
	}
        else
	{
	   ASF_FP_LINUX_CRYPTO_DEBUG("asf_alloc_aead_in -Not AEAD ALOGO \
			pSA->SAParams.ucCipherAlgo = %d: %d \n", 
			pSA->SAParams.ucCipherAlgo, __LINE__);
	   if (pSA->SAParams.bUseExtendedSequenceNumber)
           {
                if (unlikely(snprintf(authenc_name, CRYPTO_MAX_ALG_NAME,
                            "authencesn(%s,%s)",
                            pSA->SAParams.bAuth ? get_auth_algo(pSA->SAParams.ucAuthAlgo) :
			    "digest_null", 
                            get_enc_algo(pSA->SAParams.ucCipherAlgo)) >= CRYPTO_MAX_ALG_NAME))
                        goto error;
           }
           else
           {
                if (unlikely(snprintf(authenc_name, CRYPTO_MAX_ALG_NAME,
                             "authenc(%s,%s)",
                             pSA->SAParams.bAuth ? get_auth_algo(pSA->SAParams.ucAuthAlgo) : 
			     "digest_null", 
                             get_enc_algo(pSA->SAParams.ucCipherAlgo)) >= CRYPTO_MAX_ALG_NAME) )
                        goto error;
           }
	}
	ASF_FP_LINUX_CRYPTO_DEBUG("asf_alloc_aead_in authenc_name = %s: %d \n", authenc_name, __LINE__);

        aead = crypto_alloc_aead(authenc_name, 0, 0);
        err = PTR_ERR(aead);
        if(unlikely (IS_ERR(aead)))
                goto error;
	if(unlikely (!aeadAlgo))
	{
        	keylen = (pSA->SAParams.bAuth ? pSA->SAParams.AuthKeyLen : 0) +
        		pSA->SAParams.EncKeyLen + RTA_SPACE(sizeof(*param));
        	err = -ENOMEM;
       		key = kmalloc(keylen, GFP_KERNEL);

		ASF_FP_LINUX_CRYPTO_DEBUG("test: asf_alloc_aead_in keylen = %d \
			pSA->SAParams.EncKeyLen = %d pSA->SAParams.AuthKeyLen = %d \
			: %d\n", keylen, pSA->SAParams.EncKeyLen, 
			pSA->SAParams.AuthKeyLen, __LINE__);

        	if(unlikely (!key))
                	goto error;
	}
	else
	{
                switch(pSA->SAParams.ucCipherAlgo)
                {
                        case SECFP_AESCTR:
                                saltLen = AES_CTR_SALT_LEN;
                        break;
                        case SECFP_AES_CCM_ICV8:
                        case SECFP_AES_CCM_ICV12:
                        case SECFP_AES_CCM_ICV16:
                                saltLen = AES_CCM_SALT_LEN;
                        break;
                        case SECFP_AES_GCM_ICV8:
                        case SECFP_AES_GCM_ICV12:
                        case SECFP_AES_GCM_ICV16:
                                saltLen = AES_GCM_SALT_LEN;
                        break;
                        case SECFP_NULL_AES_GMAC:
                                saltLen = AES_GMAC_SALT_LEN;
                        break;
                default:
                        ;
                }

        	keylen = pSA->SAParams.EncKeyLen+saltLen ;
        	err = -ENOMEM;
       		key = kmalloc(keylen, GFP_KERNEL);
        	if (unlikely(!key))
                	goto error;
	}

        p = key;
	if(!aeadAlgo)
	{
        	rta = (void *)p;
        	rta->rta_type = CRYPTO_AUTHENC_KEYA_PARAM;
      		rta->rta_len = RTA_LENGTH(sizeof(*param));
        	param = RTA_DATA(rta);
        	p += RTA_SPACE(sizeof(*param));

        	if (likely(pSA->SAParams.bAuth))
        	{
         	       struct xfrm_algo_desc *aalg_desc;
        
                	memcpy(p, pSA->SAParams.ucAuthKey, pSA->SAParams.AuthKeyLen);
                	p += pSA->SAParams.AuthKeyLen;

                	aalg_desc = xfrm_aalg_get_byname(get_auth_algo(pSA->SAParams.ucAuthAlgo), 0);
                	BUG_ON(!aalg_desc);

               		err = -EINVAL;
                	if (aalg_desc->uinfo.auth.icv_fullbits / 8 != crypto_aead_authsize(aead)) 
			{
                        	pr_info("ESP: %s digestsize %u != %hu\n",
                                	get_auth_algo(pSA->SAParams.ucAuthAlgo),
                                	crypto_aead_authsize(aead),
                        	aalg_desc->uinfo.auth.icv_fullbits / 8);
                        	goto free_key;
                	}
		}
	}
	ASF_FP_LINUX_CRYPTO_DEBUG("asf_alloc_aead_in : %d\n", __LINE__);
	ASF_FP_LINUX_CRYPTO_DEBUG("asf_alloc_aead_in %u %u %u %u %u: %d\n", 
        	crypto_aead_ivsize((struct crypto_aead *)aead ),
        	crypto_aead_authsize((struct crypto_aead *) aead),
        	crypto_aead_blocksize((struct crypto_aead *) aead),
        	crypto_aead_get_flags((struct crypto_aead *) aead),
		pSA->SAParams.uICVSize,
      		__LINE__);
	ASF_FP_LINUX_CRYPTO_DEBUG("asf_alloc_aead_in pSA->SAParams.uICVSize = %d: %d \n", 
			pSA->SAParams.uICVSize, __LINE__);
	ASF_FP_LINUX_CRYPTO_DEBUG("asf_alloc_aead_in pSA->SAParams.EncKeyLen = %x: %d \n", 
			pSA->SAParams.EncKeyLen, __LINE__);
	ASF_FP_LINUX_CRYPTO_DEBUG("asf_alloc_aead_in returning authenc_name = %s: %d \n", 
			authenc_name, __LINE__);

	if(aeadAlgo)
	{

	   ASF_FP_LINUX_CRYPTO_DEBUG("asf_alloc_aead_in AEAD algo setkey: %d \n", __LINE__);
           memcpy(p, pSA->SAParams.ucEncKey, (pSA->SAParams.EncKeyLen + saltLen));
           err = crypto_aead_setkey(aead, key, keylen);
           if(unlikely (err))
                goto free_key;
	   ASF_FP_LINUX_CRYPTO_DEBUG("asf_alloc_aead_in AEAD algo setauthsize: %d \n", __LINE__);
      	   err = crypto_aead_setauthsize(aead, pSA->SAParams.uICVSize);
      	   if(unlikely (err))
              	goto free_key;
	}
	else
	{	
		ASF_FP_LINUX_CRYPTO_DEBUG("asf_alloc_aead_in not a AEAD algo setauthsize: %d \n", 
				__LINE__);
      		err = crypto_aead_setauthsize(aead, pSA->SAParams.uICVSize);
      		if(unlikely (err))
        	      	goto free_key;
        	param->enckeylen = cpu_to_be32(pSA->SAParams.EncKeyLen);
        	memcpy(p, pSA->SAParams.ucEncKey, (pSA->SAParams.EncKeyLen));
        
		ASF_FP_LINUX_CRYPTO_DEBUG("asf_alloc_aead_in not a AEAD algo setkey: %d \n", 
				__LINE__);
        	err = crypto_aead_setkey(aead, key, keylen);
      		if(unlikely (err))
         	       goto free_key;
	}
               
        *ptr_aead = aead;
        if(likely(key != NULL))
                kfree(key);
	ASF_FP_LINUX_CRYPTO_FEXIT;
        return err;

free_key:
error:
	if(key != NULL)
		kfree(key);
	if(aead != NULL)
		crypto_free_aead(aead);
	ASF_FP_LINUX_CRYPTO_FEXIT;
	return err;
}

/* This function is the callback function to be called after encryption completion.
   This is for asynchronous processing.
*/
void asf_fp_linux_encap_complete_cbk(struct crypto_async_request *base, int err)
{
	//Not called currently - for future use
	ASF_FP_LINUX_CRYPTO_FENTRY;	
	ASF_FP_LINUX_CRYPTO_FEXIT;
}

/* This function is to encrypt the received packets.
   pSA : pointer to out SA to be used for encryption,
   skb : pointer to sk_buff - packet received for encryption,
   cbk : callback function to be called after encryption,
   areq : pointer to packet
*/
int32_t asf_fp_linux_encap(outSA_t *pSA, struct sk_buff *skb, 
    void (*cbk)(struct device *dev, u32 *desc, u32 status, void *areq),void *areq)
{
	int err;
	struct ip_esp_hdr *esph;
	struct crypto_aead *aead = NULL;
	struct aead_givcrypt_request *req;
	struct scatterlist *sg;
	struct scatterlist *asg;
	struct sk_buff *trailer;
	void *tmp;
	u8 *iv;
	u8 *tail;
	int blksize;
	int clen;
	int alen;
	int plen;
	int tfclen;
	int nfrags;
	int assoclen;
	int sglists;
	int seqhilen;
	__be32 *seqhi;

	int tfcpad;
	char *ch;
	int i;
	unsigned int network_hdr_len;

	unsigned int * saddr;
	unsigned int * daddr;
	struct iphdr *iph;
	int hash;
	__u8 protocol=0;
	int esphSize = sizeof(*esph);
	int crypto_ivsize;

	ASF_FP_LINUX_CRYPTO_FENTRY;	
	
	//Added to make aead efficient 
	//Find aead if already exist otherwise create and store in hash. 
	hash = pSA->SAParams.ulSPI & 0x0ff;
	if(likely(ptr_aead_out[hash] != NULL))
	{
		ASF_FP_LINUX_CRYPTO_DEBUG("asf_fp_linux_encap using existing aead: %d\n",
			 __LINE__);
                aead = ptr_aead_out[hash];
		crypto_ivsize = crypto_aead_ivsize(aead);
	}
	else
	{
		ASF_FP_LINUX_CRYPTO_ERR("asf_fp_linux_encap using AEAD not found -Hash 0x%x %d\n", 
			hash, __LINE__);
		goto error;		
	}
        //End - added to make aead efficient
 	
	// Check if it is tunnel / transport mode
	if(pSA->SAParams.bEncapsulationMode == ASF_IPSEC_SA_SAFLAGS_TUNNELMODE)
	{
		//copy ipheader before it get encrypted 
		asf_mem_cpy((u8 *)skb->data - MAC_LEN, - (IP_HEADER + crypto_ivsize 
				+ esphSize), MAC_LEN + IP_HEADER);	
		//FOR IPV4 copy tunnel ip address
		saddr = (unsigned int *)(skb->data - ( crypto_ivsize + esphSize + 8));  
		daddr = (unsigned int *)(skb->data - ( crypto_ivsize + esphSize + 4));  
		*saddr = pSA->SAParams.tunnelInfo.addr.iphv4.saddr;
		*daddr = pSA->SAParams.tunnelInfo.addr.iphv4.daddr;
		network_hdr_len = skb_network_header_len(skb);
		skb_set_network_header(skb, -(network_hdr_len + esphSize + 
					crypto_ivsize));
		skb_set_mac_header(skb, -(network_hdr_len + esphSize + crypto_ivsize));
		skb_set_transport_header(skb, -(esphSize + crypto_ivsize));
	}
	else// ASF_IPSEC_SA_SAFLAGS_TRANSPORTMODE
	{
		iph = (struct iphdr *)skb->data;
		protocol = iph->protocol; //save protocol 
		asf_mem_cpy((u8 *)skb->data - MAC_LEN, - (crypto_ivsize + 
			esphSize), MAC_LEN + IP_HEADER);	//shifting mac+ip header bytes up 
		//mac pointing to old mac address  
		skb_set_mac_header(skb, -MAC_LEN-1);
		network_hdr_len = skb_network_header_len(skb);
		skb_set_network_header(skb, -(esphSize + crypto_ivsize));
		skb_set_transport_header(skb, -(esphSize + crypto_ivsize) + network_hdr_len);
        	skb_pull(skb, IP_HEADER);
	
	}
        /* skb is pure payload to encrypt */
        /* Need to test TFC val and its length */
        tfclen = 0;
        tfcpad = 0x00;
	ASF_FP_LINUX_CRYPTO_DEBUG("asf_fp_linux_encap skb->len = %u: %d\n", skb->len, __LINE__);

	alen = crypto_aead_authsize(aead);
	//tfcpad not used
	if (tfcpad) 
	{
		struct xfrm_dst *dst = (struct xfrm_dst *)skb_dst(skb);
		u32 padto;

		padto = min((u32)tfcpad, (u32)get_mtu_size(aead, dst->child_mtu_cached));
		if (skb->len < padto)
			tfclen = padto - skb->len;
	}

	blksize = ALIGN(crypto_aead_blocksize(aead), 4);
	clen = ALIGN(skb->len + 2 + tfclen, blksize);
	plen = clen - skb->len - tfclen;

	err = skb_cow_data(skb, tfclen + plen + alen, &trailer);
	if(unlikely (err < 0))
		goto error;
	nfrags = err;
	assoclen = esphSize;
	sglists = 1;
	seqhilen = 0;

	if(pSA->SAParams.bUseExtendedSequenceNumber)
	{
		sglists += 2;
		seqhilen += sizeof(__be32);
		assoclen += seqhilen;
	}

	tmp = esp_alloc_tmp(aead, nfrags + sglists, seqhilen);
	if (unlikely(!tmp)) {
		err = -ENOMEM;
		goto error;
	}

	seqhi = esp_tmp_seqhi(tmp);
	iv = esp_tmp_iv(aead, tmp, seqhilen);
	req = esp_tmp_givreq(aead, iv);
	asg = esp_givreq_sg(aead, req);
	sg = asg + sglists;

        /* Fill padding... */
        tail = skb_tail_pointer(trailer);
        if (tfclen) {
                memset(tail, 0, tfclen);
                tail += tfclen;
        }
        do {
                int i;
                for (i = 0; i < plen - 2; i++)
                        tail[i] = i + 1;
        } while (0);

	tail[plen - 2] = plen - 2;
	//tail[plen - 1] = *skb_mac_header(skb);
	//tail[plen - 1] = iph->protocol;
	
	if(pSA->SAParams.bEncapsulationMode == ASF_IPSEC_SA_SAFLAGS_TUNNELMODE)
	{
		//workaround - setting it as IP
		tail[plen - 1] = 4;
	}
	else //ASF_IPSEC_SA_SAFLAGS_TRANSPORTMODE
	{
		//tail[plen - 1] = *skb_mac_header(skb);
		tail[plen - 1] = protocol;
	}
	pskb_put(skb, trailer, clen - skb->len + alen);
        skb_push(skb, -skb_network_offset(skb));
	
	esph = ip_esp_hdr(skb);
	iph = (struct iphdr *)skb->data;
	iph->protocol = IPPROTO_ESP;

	/* this is non-NULL only with UDP Encapsulation */
	if (pSA->SAParams.bDoUDPEncapsulationForNATTraversal)
	{
		struct udphdr *uh;
		__be32 *udpdata32;
		__be16 sport, dport;
		int encap_type;

		sport = pSA->SAParams.IPsecNatInfo.usSrcPort;
		dport = pSA->SAParams.IPsecNatInfo.usDstPort;
		encap_type = pSA->SAParams.IPsecNatInfo.ulNATt;

		uh = (struct udphdr *)esph;
		uh->source = sport;
		uh->dest = dport;
		uh->len = htons(skb->len - skb_transport_offset(skb));
		uh->check = 0;

		switch (encap_type) {
		default:
		case ASF_IPSEC_IKE_NATtV2:
				esph = (struct ip_esp_hdr *)(uh + 1);
				break;
		case ASF_IPSEC_IKE_NATtV1:
				udpdata32 = (__be32 *)(uh + 1);
				udpdata32[0] = udpdata32[1] = 0;
				esph = (struct ip_esp_hdr *)(udpdata32 + 2);
				break;
		}

		*skb_mac_header(skb) = IPPROTO_UDP;
	}

        esph->spi = pSA->SAParams.ulSPI;

	//set sequence number and increment count
        esph->seq_no = htonl(seq_output[hash].low++);

	sg_init_table(sg, nfrags);

	skb_to_sgvec(skb, sg,
		 esph->enc_data + crypto_ivsize - skb->data,
		 clen + alen);

	ASF_FP_LINUX_CRYPTO_DEBUG("Before encrypt asf_fp_linux_encap esph->seg_no = %u:\
			 %d\n", esph->seq_no, __LINE__);
        if (pSA->SAParams.bUseExtendedSequenceNumber)
        {
		sg_init_table(asg, 3);
		sg_set_buf(asg, &esph->spi, sizeof(__be32));
		//set high sequence number and increment
		*seqhi = htonl(seq_output[hash].high);
		if (unlikely(seq_output[hash].low==0xffffffff)) 
		{
		   seq_output[hash].high++;
		   seq_output[hash].low=0;
		}
		sg_set_buf(asg + 1, seqhi, seqhilen);
		sg_set_buf(asg + 2, &esph->seq_no, sizeof(__be32));
	}
	else
	{
		sg_init_one(asg, esph, esphSize);
	}

	aead_givcrypt_set_callback(req, 0, asf_fp_linux_encap_complete_cbk, skb);
	aead_givcrypt_set_crypt(req, sg, sg, clen, iv);
	aead_givcrypt_set_assoc(req, asg, assoclen);
	aead_givcrypt_set_giv(req, esph->enc_data, XFRM_SKB_CB(skb)->seq.output.low);

	ASF_FP_LINUX_CRYPTO_DEBUG("Before encrypt asf_fp_linux_encap skb->data = 0x%x: \
			%d\n", skb->data, __LINE__);
	//asf_ipsec_hex_dump(skb->data, 108+44);

	ESP_SKB_CB(skb)->tmp = tmp;
	err = crypto_aead_givencrypt(req);
	
	if (unlikely(err == -EINPROGRESS))
			goto error;

	if(unlikely (err == -EBUSY))
			err = NET_XMIT_DROP;

	ASF_FP_LINUX_CRYPTO_DEBUG("After encrypt asf_fp_linux_encap skb->data = 0x%x: \
			%d\n", skb->data, __LINE__);
	//asf_ipsec_hex_dump(skb->data, skb->len);//108+44);
	skb->mac_len = MAC_LEN;
	skb->mac_header = skb->network_header - skb->mac_len;

	iph->tot_len = htons(skb->len);

	iph->check = 0x00;
	iph->check = (ip_fast_csum((u8 *)iph, iph->ihl));

	ASF_FP_LINUX_CRYPTO_DEBUG("iph->check = 0x%x csum 0x%x iph->ihl = 0x%x : %d\n", 
			iph->check, ip_fast_csum((u8 *)iph, iph->ihl),  iph->ihl, __LINE__);

	kfree(tmp);
	secfp_outComplete(NULL, NULL, err, (void *)(skb));
		
error:

	ASF_FP_LINUX_CRYPTO_FEXIT;
	return err;
}
/* This function is the callback function called after decryption.
   This function is not used currently - for future use
*/
void asf_fp_linux_decap_complete_cbk(struct crypto_async_request *base, int err)
{
	//Not called - for future use
	ASF_FP_LINUX_CRYPTO_FENTRY;	
	ASF_FP_LINUX_CRYPTO_FEXIT;
}
/* This function is to decrypt the received packets.
   pSA : pointer to out SA to be used for decryption,
   skb : pointer to sk_buff - packet received for decryption,
   cbk : callback function to be called after decryption,
   areq : pointer to packeti received.
*/
int32_t asf_fp_linux_decap(inSA_t *pSA, struct sk_buff *skb,
                           void (*cbk)(struct device *dev, u32 *desc, u32 status, void *areq),void *areq)
{
	struct ip_esp_hdr *esph;
	struct crypto_aead *aead = NULL;
	struct aead_request *req;
	struct sk_buff *trailer;
	int elen;
	int nfrags;
	int assoclen;
	int sglists;
	int seqhilen;
	__be32 *seqhi;
	void *tmp;
	u8 *iv;
	struct scatterlist *sg;
	struct scatterlist *asg;
	int err = -EINVAL;

	char *tail;
	int i;
	unsigned int network_hdr_len;
	unsigned int saddr;
	unsigned int daddr;
	int hash;
	int alen;
	struct iphdr *iph;
 	int padlen;	
	int esphSize = sizeof(*esph);
	int crypto_ivsize;
	ASF_FP_LINUX_CRYPTO_FENTRY;	
 
	//Added to make aead efficient
	//Find aead if already exist otherwise create and store in hash. 
	hash = pSA->SAParams.ulSPI & 0x0ff;
	if(likely(ptr_aead_in[hash] != NULL))
	{
              	ASF_FP_LINUX_CRYPTO_DEBUG("asf_fp_linux_decap using existing aead: %d\n",
				 __LINE__);
        	aead = ptr_aead_in[hash];
		crypto_ivsize = crypto_aead_ivsize(aead);
	}
	else
	{
		ASF_FP_LINUX_CRYPTO_ERR("test: asf_fp_linux_decap aead not found: %d\n", 
				__LINE__);
		goto out;
	}

	skb->len += esphSize;
	skb->data -= esphSize;

	elen = skb->len - esphSize - crypto_ivsize;


	ASF_FP_LINUX_CRYPTO_DEBUG("asf_fp_linux_decap skb->len = %u sizeof(*esph) = %u \
			elen = %u crypto_aead_ivsize(aead) = %u: %d\n", skb->len, esphSize,
			elen, crypto_ivsize, __LINE__);

	if (unlikely(!pskb_may_pull(skb, esphSize + crypto_ivsize)))
		goto out;

	if (unlikely(elen <= 0))
		goto out;

	err = skb_cow_data(skb, 0, &trailer);
	if (unlikely(err < 0))
		goto out;

	nfrags = err;

	assoclen = esphSize;
	sglists = 1;
	seqhilen = 0;

	if (pSA->SAParams.bUseExtendedSequenceNumber) {
		sglists += 2;
		seqhilen += sizeof(__be32);
		assoclen += seqhilen;
	}

	err = -ENOMEM;
	tmp = esp_alloc_tmp(aead, nfrags + sglists, seqhilen);
	if(unlikely (!tmp))
		goto out;

	ESP_SKB_CB(skb)->tmp = tmp;
	seqhi = esp_tmp_seqhi(tmp);
	iv = esp_tmp_iv(aead, tmp, seqhilen);
	req = esp_tmp_req(aead, iv);
	asg = esp_req_sg(aead, req);
	sg = asg + sglists;

	skb->ip_summed = CHECKSUM_NONE;

	esph = (struct ip_esp_hdr *)skb->data;

	iv = esph->enc_data;

	sg_init_table(sg, nfrags);

	skb_to_sgvec(skb, sg, esphSize + crypto_ivsize, elen);

	if (pSA->SAParams.bUseExtendedSequenceNumber)
	{
		sg_init_table(asg, 3);
		sg_set_buf(asg, &esph->spi, sizeof(__be32));
		*seqhi = XFRM_SKB_CB(skb)->seq.input.hi;
		sg_set_buf(asg + 1, seqhi, seqhilen);
		sg_set_buf(asg + 2, &esph->seq_no, sizeof(__be32));
	} 
	else
	{
		sg_init_one(asg, esph, esphSize);
	}

	aead_request_set_callback(req, 0, asf_fp_linux_decap_complete_cbk, skb);
	aead_request_set_crypt(req, sg, sg, elen, iv);
	aead_request_set_assoc(req, asg, assoclen);

	ASF_FP_LINUX_CRYPTO_DEBUG("asf_fp_linux_decap Before Decrypt skb->len = %u \
			skb->data_len = %u skb->data = 0x%x elen = %u: %d\n", 
			skb->len, skb->data_len, skb->data, elen, __LINE__);
	//asf_ipsec_hex_dump(skb->data, skb->len);

	err = crypto_aead_decrypt(req);
	if(unlikely(err != 0))
	{
		ASF_FP_LINUX_CRYPTO_ERR("asf_fp_linux_decap crypto_aead_decrypt ERROR %d: \
				%d\n", err, __LINE__);
		goto out;
	}
	else
	{
		ASF_FP_LINUX_CRYPTO_DEBUG("asf_fp_linux_decap SUCCESSFULLY DECRYPTED : \
				%d\n", __LINE__);
	}

	ASF_FP_LINUX_CRYPTO_DEBUG("asf_fp_linux_decap After Decrypt skb->len = %u \
			skb->data_len = %u skb->data = 0x%x elen = %u: %d\n", 
			skb->len, skb->data_len, skb->data, elen, __LINE__);
	//asf_ipsec_hex_dump(skb->data, skb->len);
	kfree(ESP_SKB_CB(skb)->tmp);

	if(pSA->SAParams.bEncapsulationMode == ASF_IPSEC_SA_SAFLAGS_TRANSPORTMODE)
	{
		skb->len -= crypto_aead_authsize(aead);
		iph = skb->data - skb_network_header_len(skb);
		tail = skb->data + skb->len-1;
		
		padlen = tail[-1] + 2;// padding len + protocol + len
		if(unlikely(padlen >= skb->len))
		{
			ASF_FP_LINUX_CRYPTO_ERR("asf_fp_linux_decap ipsec esp packet \
				has grabage padlen = %d skb->len %d: %d\n", padlen,
				skb->len, __LINE__);
		}	
		skb->len -= padlen; 
		iph->protocol = tail[0];	
		iph->tot_len = htons(skb->len + skb_network_header_len(skb) -(esphSize 
				+ crypto_ivsize));
		iph->check = 0x00;
		iph->check = (ip_fast_csum((u8 *)iph, iph->ihl));
        	//asf_ipsec_hex_dump(skb->data-14-20, skb->len+14+20);
	}
	else
	{
//		asf_ipsec_hex_dump(skb->data, skb->len);
		tail = skb->data + skb->len-1 - crypto_aead_authsize(aead);
		padlen = tail[-1] + 2;		// padding len + protocol + len
		ASF_FP_LINUX_CRYPTO_DEBUG("asf_fp_linux_decap ipsec esp packet \
			TAIL = 0x%x protocol:%d padlen:%d T padlen %d skb->len %d: %d\n",
			tail, tail [0], tail[-1], padlen, skb->len, __LINE__);

	}
	*(uintptr_t *)&(skb->cb[SECFP_IPHDR_INDEX]) = (uintptr_t)
					((skb->data-skb_network_header_len(skb)));

	pskb_trim(skb,skb->len - crypto_aead_authsize(aead) - padlen); 
	__skb_pull(skb, (esphSize + crypto_ivsize));

//	asf_ipsec_hex_dump(skb->data, skb->len);

	if(likely(aead != NULL))
	{
		//IV size is added in skb cb
		skb->cb[SECFP_IV_DATA_INDEX] = crypto_ivsize;
		ASF_FP_LINUX_CRYPTO_DEBUG("After decap asf_fp_linux_encap \
			skb->cb[SECFP_IV_DATA_INDEX] = 0x%x skb->cb[SECFP_IPHDR_INDEX] = 0x%x:\
			 %d\n", skb->cb[SECFP_IV_DATA_INDEX], skb->cb[SECFP_IPHDR_INDEX], __LINE__);
	}

        secfp_inComplete(NULL, NULL, err, (void *)(skb));

out:
	ASF_FP_LINUX_CRYPTO_FEXIT;
	return err;
}
/* This function is used to create aead corresponding to new in SA.
   pSA : pointer to in SA
*/
int32_t asf_fp_linux_createInSAVIpsec(inSA_t *pSA)
{
	int hash, ret = 0;
	ASF_FP_LINUX_CRYPTO_FENTRY;	
	hash = pSA->SAParams.ulSPI & 0x0ff;
        if(ptr_aead_in[hash] == NULL)
        {
                asf_alloc_aead_in(pSA, &ptr_aead_in[hash]);
        }
	ASF_FP_LINUX_CRYPTO_FEXIT;
	return ret;
}

/* This function is used to create aead corresponding to new out SA.
   pSA : pointer to out SA
*/
int32_t asf_fp_linux_createOutSAVIpsec(outSA_t *pSA)
{
	int hash,ret = 0;
	ASF_FP_LINUX_CRYPTO_FENTRY;	
	hash = pSA->SAParams.ulSPI & 0x0ff;
        if(ptr_aead_out[hash] == NULL)
        {
                asf_alloc_aead_out(pSA, &ptr_aead_out[hash]);
		seq_output[hash].high = 0;
                seq_output[hash].low = 2;
        }
	ASF_FP_LINUX_CRYPTO_FEXIT;
	return ret;
}

/* This function is used to delete corresponding to deleted in SA.
   pSA : pointer to in SA
*/
int32_t asf_fp_linux_deleteInSAVIpsec(inSA_t *pSA)
{
	int hash, ret = 0;
	ASF_FP_LINUX_CRYPTO_FENTRY;	
	hash = pSA->SAParams.ulSPI & 0x0ff;
	if(ptr_aead_in[hash] != NULL)
    	{
        	crypto_free_aead(ptr_aead_in[hash]);
        	ptr_aead_in[hash] = NULL;
    	}
	ASF_FP_LINUX_CRYPTO_FEXIT;
	return ret;
}

/* This function is used to delete aead corresponding to deleted out SA.
   pSA : pointer to out SA
*/
int32_t asf_fp_linux_deleteOutSAVIpsec(outSA_t *pSA)
{
	int hash, ret = 0;
	ASF_FP_LINUX_CRYPTO_FENTRY;	
	hash = pSA->SAParams.ulSPI & 0x0ff;
	if(ptr_aead_out[hash] != NULL)
	{
     		crypto_free_aead(ptr_aead_out[hash]);
        	ptr_aead_out[hash] = NULL;
    	}
	ASF_FP_LINUX_CRYPTO_FEXIT;
	return ret;
}

/* This function is init function called on module insertion.
   Called for initialization of various variables used in this file.
*/
void asf_fp_linux_init()
{
	int i, ret = 0;
	ASF_FP_LINUX_CRYPTO_FENTRY;
	//initiallize all ptr to NULL	
	for (i = 0; i < AEAD_ARRAY_SIZE; i++)
	{
		ptr_aead_out[i] = NULL;
		ptr_aead_in[i] = NULL;
                seq_output[i].high = 0;
                seq_output[i].low = 0;

	}
	ASF_FP_LINUX_CRYPTO_FEXIT;
	return ret;
}

/* This function is deinit function called on module removal.
   Called for freeing the allocated memory for 
   various variables used in this file.
*/
void asf_fp_linux_deinit()
{
	int i, ret = 0;
	ASF_FP_LINUX_CRYPTO_FENTRY;
	//Free all allocated aead 
	for(i=0;i< AEAD_ARRAY_SIZE;i++)
	{
        	if(ptr_aead_out[i] != NULL)
         	{
			crypto_free_aead(ptr_aead_out[i]);
			ptr_aead_out[i] = NULL;
         	}
		if(ptr_aead_in[i] != NULL)	
		{
			crypto_free_aead(ptr_aead_in[i]);
			ptr_aead_in[i] = NULL;
         	}
    	}
	ASF_FP_LINUX_CRYPTO_FEXIT;
	return ret;
}


