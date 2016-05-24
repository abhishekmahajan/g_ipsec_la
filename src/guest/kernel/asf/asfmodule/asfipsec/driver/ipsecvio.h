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
#ifndef _ASF_IPSEC_VIO_
#define _ASF_IPSEC_VIO_
int32_t secfp_createInSAVIpsec(inSA_t *pSA);
void asf_virtio_interface_init(void);
int32_t secfp_createOutSAVIpsec(outSA_t *pSA);
int32_t secfp_deleteOutSAVIpsec(outSA_t *pSA);
int32_t secfp_deleteInSAVIpsec(inSA_t *pSA);
void secfp_encap_complete_cbk(void *cb_arg, int32_t cb_arg_len, void *outargs);
int32_t secfp_vio_encap(outSA_t *pSA, struct sk_buff *skb, void (*cbk)(struct device *dev, u32 *desc,
				u32 status, void *areq), void *areq);
void secfp_decap_complete_cbk(void *cb_arg, int32_t cb_arg_len, void *outargs);
int32_t secfp_vio_decap(inSA_t *pSA,
		struct sk_buff *skb,
		void (*cbk)(struct device *dev, u32 *desc,
			u32 status, void *areq),
			void *areq);

#define g_ipsec_la_avail_devices_get_num	virt_ipsec_avail_devices_get_num
#define g_ipsec_la_get_api_version			virt_ipsec_get_api_version
#define g_ipsec_la_packet_decap				virt_ipsec_packet_decap
#define g_ipsec_la_packet_encap				virt_ipsec_packet_encap
#define g_ipsec_la_avail_devices_get_info	virt_ipsec_avail_devices_get_info
#define g_ipsec_la_open						virt_ipsec_la_open
#define g_ipsec_la_sa_add					virt_ipsec_sa_add
#define g_ipsec_la_sa_del					virt_ipsec_sa_del

int32_t virt_ipsec_avail_devices_get_num(uint32_t *nr_devices);
int32_t virt_ipsec_get_api_version(char *version);
int32_t	virt_ipsec_packet_decap(
	struct g_ipsec_la_handle *handle, 
	enum g_ipsec_la_control_flags flags,
	struct g_ipsec_la_sa_handle *sa_handle, /* SA Handle */
	uint32_t num_sg,	/* number of Scatter Gather elements */
	struct g_ipsec_la_data *in_data,/* Array of data blocks */
	struct g_ipsec_la_data *out_data, /* Array of out data blocks*/
	struct g_ipsec_la_resp_args *resp);
int32_t virt_ipsec_packet_encap(
	struct g_ipsec_la_handle *handle, 
	enum g_ipsec_la_control_flags flags,
	struct g_ipsec_la_sa_handle *sa_handle, /* SA Handle */
	uint32_t num_sg, /* num of Scatter Gather elements */
	struct g_ipsec_la_data *in_data,
	/* Array of data blocks */
	struct g_ipsec_la_data *out_data, 
	/* Array of output data blocks */
	struct g_ipsec_la_resp_args *resp);
int32_t virt_ipsec_avail_devices_get_info(
	struct g_ipsec_la_avail_devices_get_inargs *in,
	struct g_ipsec_la_avail_devices_get_outargs *out);
int32_t virt_ipsec_la_open(
		enum g_ipsec_la_mode mode, 
		struct g_ipsec_la_open_inargs *in, 
		struct g_ipsec_la_open_outargs *out);
int32_t virt_ipsec_sa_add(
	struct g_ipsec_la_handle *handle,
	const struct g_ipsec_la_sa_add_inargs *in,
	enum g_ipsec_la_control_flags flags,
	struct g_ipsec_la_sa_add_outargs *out,
	struct g_ipsec_la_resp_args *resp);
int32_t virt_ipsec_sa_del(
	struct g_ipsec_la_handle *handle,
       const struct g_ipsec_la_sa_del_inargs *in,
       enum g_ipsec_la_control_flags flags,
       struct g_ipsec_la_sa_del_outargs *out,
       struct g_ipsec_la_resp_args *resp);

#endif

