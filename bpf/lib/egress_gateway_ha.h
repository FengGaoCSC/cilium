/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_EGRESS_GATEWAY_HA_H_
#define __LIB_EGRESS_GATEWAY_HA_H_

#include "lib/identity.h"

#include "maps.h"

#ifdef ENABLE_EGRESS_GATEWAY_COMMON

#ifdef ENABLE_EGRESS_GATEWAY_HA
static __always_inline
struct egress_gw_ha_policy_entry *lookup_ip4_egress_gw_ha_policy(__be32 saddr, __be32 daddr)
{
	struct egress_gw_ha_policy_key key = {
		.lpm_key = { EGRESS_IPV4_PREFIX, {} },
		.saddr = saddr,
		.daddr = daddr,
	};
	return map_lookup_elem(&EGRESS_GW_HA_POLICY_MAP, &key);
}

static __always_inline
struct egress_gw_ha_ct_entry *lookup_ip4_egress_ct(struct ipv4_ct_tuple *ct_key)
{
	return map_lookup_elem(&EGRESS_GW_HA_CT_MAP, ct_key);
}

static __always_inline
void update_egress_gw_ha_ct_entry(struct ipv4_ct_tuple *ct_key, __be32 gateway)
{
	struct egress_gw_ha_ct_entry egress_ct = {
		.gateway_ip = gateway
	};

	map_update_elem(&EGRESS_GW_HA_CT_MAP, ct_key, &egress_ct, 0);
}

static __always_inline
__be32 pick_egress_gateway(const struct egress_gw_ha_policy_entry *policy)
{
	unsigned int index = get_prandom_u32() % policy->size;

	/* Just being extra defensive here while keeping the verifier happy.
	 * Userspace should always guarantee the invariant:
	 *     policy->size < EGRESS_GW_HA_MAX_GATEWAY_NODES"
	 */
	index %= EGRESS_GW_HA_MAX_GATEWAY_NODES;

	return policy->gateway_ips[index];
}

/* egress_gw_ha_policy_entry_is_excluded_cidr returns true if the given policy
 * entry represents an excluded CIDR.
 *
 * Excluded CIDRs are expressed with policy entries with a single gateway IP set
 * to the special EGRESS_GATEWAY_EXCLUDED_CIDR IPv4 (0.0.0.1)
 */
static __always_inline
bool egress_gw_ha_policy_entry_is_excluded_cidr(const struct egress_gw_ha_policy_entry *policy)
{
	return policy->size == 1 &&
		policy->gateway_ips[0] == EGRESS_GATEWAY_EXCLUDED_CIDR;
}
#endif /* ENABLE_EGRESS_GATEWAY_HA */

static __always_inline
bool egress_gw_ha_request_needs_redirect(struct ipv4_ct_tuple *rtuple __maybe_unused,
					 int ct_status __maybe_unused,
					 __u32 *tunnel_endpoint __maybe_unused)
{
#if defined(ENABLE_EGRESS_GATEWAY_HA)
	struct ipv4_ct_tuple ct_key;
	struct egress_gw_ha_ct_entry *egress_ct;

	struct egress_gw_ha_policy_entry *egress_gw_policy;
	struct endpoint_info *gateway_node_ep;
	__be32 gateway_ip;

	/* If the packet is a reply or is related, it means that outside
	 * has initiated the connection, and so we should skip egress
	 * gateway, since an egress policy is only matching connections
	 * originating from a pod.
	 */
	if (ct_status == CT_REPLY || ct_status == CT_RELATED)
		return false;

	/* The first iteration of egress_gw_ha_request_needs_redirect() would
	 * receive the full IPv4 header as parameter, extract the source and
	 * destination IPs and ports, and build the IPv4 tuple for the ct_key
	 * from that.
	 * To avoid rebuilding this tuple and having to deal with fragmentation,
	 * this function now receives the IPv4 tuple from handle_ipv4_from_lxc().
	 *
	 * As this is a CT tuple which has been already flipped by ct_lookup4(),
	 * for backward compatibility with the existing entries in the egressgw
	 * CT map, we need to flip its addresses back (ports were already
	 * flipped _before_ the call to ct_lookup4(), so after being flipped
	 * again they are now in the correct order).
	 *
	 * Moreover, clear the tuple's flags as in the first iteration it wasn't
	 * used.
	 */
	memcpy(&ct_key, rtuple, sizeof(ct_key));
	ipv4_ct_tuple_swap_addrs(&ct_key);
	ct_key.flags = 0;

	/* Established connection should have its gateway in the EgressCT map: */
	if (ct_status == CT_ESTABLISHED) {
		egress_ct = lookup_ip4_egress_ct(&ct_key);
		if (egress_ct) {
			/* If there's an entry, extract the IP of the gateway node from
			 * the egress_ct struct and forward the packet to the gateway
			 */
			gateway_ip = egress_ct->gateway_ip;

			goto do_egress_gateway_redirect;
		}
	}

	/* Lookup the (src IP, dst IP) tuple in the the egress policy map */
	egress_gw_policy = lookup_ip4_egress_gw_ha_policy(ipv4_ct_reverse_tuple_saddr(rtuple),
							  ipv4_ct_reverse_tuple_daddr(rtuple));
	if (!egress_gw_policy)
		return false;

	if (!egress_gw_policy->size) {
		/* If no gateway is found we return that the connection is
		 * "redirected" and the caller will handle this special case
		 * and drop the traffic.
		 */
		*tunnel_endpoint = EGRESS_GATEWAY_NO_GATEWAY;
		return true;
	}

	/* If this is an excluded CIDR, skip redirection */
	if (egress_gw_ha_policy_entry_is_excluded_cidr(egress_gw_policy))
		return false;

	/* Otherwise encap and redirect the packet to egress gateway
	 * node through a tunnel.
	 */
	gateway_ip = pick_egress_gateway(egress_gw_policy);

	/* And add an egress CT entry to pin the selected gateway node
	 * for the connection
	 */
	update_egress_gw_ha_ct_entry(&ct_key, gateway_ip);

do_egress_gateway_redirect:
	/* If the gateway node is the local node, then just let the
	 * packet go through, as it will be SNATed later on by
	 * handle_nat_fwd().
	 */
	gateway_node_ep = __lookup_ip4_endpoint(gateway_ip);
	if (gateway_node_ep && (gateway_node_ep->flags & ENDPOINT_F_HOST))
		return false;

	*tunnel_endpoint = gateway_ip;
	return true;
#else
	return false;
#endif /* ENABLE_EGRESS_GATEWAY_HA */
}

static __always_inline
bool egress_gw_ha_snat_needed(__be32 saddr __maybe_unused,
			      __be32 daddr __maybe_unused,
			      __be32 *snat_addr __maybe_unused)
{
#if defined(ENABLE_EGRESS_GATEWAY_HA)
	struct egress_gw_ha_policy_entry *egress_gw_policy;

	egress_gw_policy = lookup_ip4_egress_gw_ha_policy(saddr, daddr);
	if (!egress_gw_policy)
		return false;

	if (!egress_gw_policy->size)
		return false;

	/* If this is an excluded CIDR, skip SNAT */
	if (egress_gw_ha_policy_entry_is_excluded_cidr(egress_gw_policy))
		return false;

	*snat_addr = egress_gw_policy->egress_ip;
	return true;
#else
	return false;
#endif /* ENABLE_EGRESS_GATEWAY_HA */
}

static __always_inline
bool egress_gw_ha_reply_needs_redirect(struct iphdr *ip4 __maybe_unused,
				       __u32 *tunnel_endpoint __maybe_unused,
				       __u32 *dst_sec_identity __maybe_unused)
{
#if defined(ENABLE_EGRESS_GATEWAY_HA)
	struct egress_gw_ha_policy_entry *egress_gw_policy;
	struct remote_endpoint_info *info;

	/* Find a matching policy by looking up the reverse address tuple: */
	egress_gw_policy = lookup_ip4_egress_gw_ha_policy(ip4->daddr, ip4->saddr);
	if (!egress_gw_policy)
		return false;

	/* FIXME: no gateway traffic should be dropped in a future release */
	if (!egress_gw_policy->size)
		return false;

	/* If this is an excluded CIDR, skip redirection */
	if (egress_gw_ha_policy_entry_is_excluded_cidr(egress_gw_policy))
		return false;

	info = ipcache_lookup4(&IPCACHE_MAP, ip4->daddr, V4_CACHE_KEY_LEN, 0);
	if (!info || info->tunnel_endpoint == 0)
		return false;

	*tunnel_endpoint = info->tunnel_endpoint;
	*dst_sec_identity = info->sec_identity;
	return true;
#else
	return false;
#endif /* ENABLE_EGRESS_GATEWAY_HA */
}

#endif /* ENABLE_EGRESS_GATEWAY_COMMON */

#endif /* __LIB_EGRESS_GATEWAY_HA_H_ */
