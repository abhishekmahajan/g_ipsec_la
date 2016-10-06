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


#ifndef _ASF_FP_IPSEC_LINUX_CRYPTO_
#define _ASF_FP_IPSEC_LINUX_CRYPTO_

#include <linux/version.h>

#include "../../asfffp/driver/asfparry.h"
#include "../../asfffp/driver/asfmpool.h"
#include "../../asfffp/driver/asftmr.h"
#include "../../asfffp/driver/gplcode.h"
#include "../../asfffp/driver/asf.h"
#include "../../asfffp/driver/asfcmn.h"
#include "../../asfffp/driver/asfterm.h"
#include "../../asfffp/driver/asfipsec.h"
#include "../../asfffp/driver/asfreasm.h"
#include "ipseccmn.h"

#define MAC_LEN 14
#define IP_HEADER 20
#define ESP_LEN 8
#define AEAD_ARRAY_SIZE 256 

//For Debug logging in syslogs.
#define ASF_FP_LINUX_CRYPTO_FEXIT ASFIPSEC_FEXIT
#define ASF_FP_LINUX_CRYPTO_FENTRY ASFIPSEC_FENTRY

#define ASF_FP_LINUX_CRYPTO_PRINT ASFIPSEC_PRINT
#define ASF_FP_LINUX_CRYPTO_WARN ASFIPSEC_WARN
#define ASF_FP_LINUX_CRYPTO_DEBUG ASFIPSEC_DEBUG
#define ASF_FP_LINUX_CRYPTO_DBG2 ASFIPSEC_DBGL2
#define ASF_FP_LINUX_CRYPTO_ERR ASFIPSEC_ERR

typedef struct Seq_output {
        __u32 low;
        __u32 high;
}Seq_output;


void asf_fp_linux_init(void);

void asf_fp_linux_deinit(void);

int32_t asf_fp_linux_createInSAVIpsec(inSA_t *pSA);

int32_t asf_fp_linux_createOutSAVIpsec(outSA_t *pSA);

int32_t asf_fp_linux_deleteInSAVIpsec(inSA_t *pSA);

int32_t asf_fp_linux_deleteOutSAVIpsec(outSA_t *pSA);

void asf_fp_linux_encap_complete_cbk(struct crypto_async_request *base, int err);

int32_t asf_fp_linux_encap(
    outSA_t *pSA, 
    struct sk_buff *skb, 
    void (*cbk)(struct device *dev, u32 *desc, u32 status, void *areq),
    void *areq);

void asf_fp_linux_decap_complete_cbk(struct crypto_async_request *base, int err);

int32_t asf_fp_linux_decap(
    inSA_t *pSA, 
    struct sk_buff *skb,
    void (*cbk)(struct device *dev, u32 *desc, u32 status, void *areq),
    void *areq);

void asf_mem_cpy(u8 *ptr, int offset, unsigned int len);

#endif

