/* Copyright (c) 2021 Connected Way, LLC. All rights reserved.
 * Use of this source code is governed by a Creative Commons 
 * Attribution-NoDerivatives 4.0 International license that can be
 * found in the LICENSE file.
 */
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <netdb.h>
#include <stdio.h>

#include "ofc/core.h"
#include "ofc/types.h"
#include "ofc/config.h"
#include "ofc/libc.h"
#include "ofc/heap.h"
#include "ofc/net.h"
#include "ofc/net_internal.h"

#if defined(OFC_KERBEROS)
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <resolv.h>
#endif

/**
 * \defgroup net_linux Linux Network Implementation
 */

/** \{ */

OFC_VOID ofc_net_init_impl(OFC_VOID) {
  signal (SIGPIPE, SIG_IGN) ;
}

OFC_VOID ofc_net_register_config_impl(OFC_HANDLE hEvent) {
}

OFC_VOID ofc_net_unregister_config_impl(OFC_HANDLE hEvent) {
}

#if defined(OFC_KERBEROS)
OFC_VOID ofc_net_resolve_svc(OFC_CCHAR *svc, OFC_UINT *count, OFC_CHAR ***dc)
{
  OFC_CHAR *ret = OFC_NULL;
  struct __res_state res;

  if (res_ninit(&res) == 0)
    {
      unsigned char answer[PACKETSZ];
      int len = res_nsearch(&res, svc, C_IN, T_SRV, answer, sizeof(answer));
      if (len >= 0)
	{
	  ns_msg handle;
	  ns_rr rr;

	  ns_initparse(answer, len, &handle);
          *count = ns_msg_count(handle, ns_s_an);
          *dc = ofc_malloc(*count * (sizeof(OFC_CHAR *) * *count));
	  for (int i = 0; i < ns_msg_count(handle, ns_s_an) ; i++)
	    {
	      if (ns_parserr(&handle, ns_s_an, i, &rr) >= 0 &&
		  ns_rr_type(rr) == T_SRV)
		{
		  char dname[MAXCDNAME];
		  // decompress domain name
		  if (dn_expand(ns_msg_base(handle),
				ns_msg_end(handle),
				ns_rr_rdata(rr) + 3 * NS_INT16SZ,
				dname,
				sizeof(dname)) >= 0)
		    {
                      (*dc)[i] = ofc_strdup(dname);
		    }
		}
	    }
	}
      else
	{
	  ofc_log(OFC_LOG_WARN, "Could not resolve search for kerberos\n");
	}
    }
  else
    {
      ofc_log(OFC_LOG_WARN, "Could Not Init Resolver Library for getting Domain DC\n");
    }
}
#endif

static OFC_BOOL match_families(struct ifaddrs *ifaddrp) {
  OFC_BOOL ret ;

  ret = OFC_FALSE ;
#if defined(OFC_DISCOVER_IPV4)
  if (ifaddrp->ifa_addr->sa_family == AF_INET)
    ret = OFC_TRUE ;
#endif
#if defined(OFC_DISCOVER_IPV6)
  if (ifaddrp->ifa_addr->sa_family == AF_INET6)
    {
      struct sockaddr_in6 *sock6 ;

      sock6 = (struct sockaddr_in6 *) ifaddrp->ifa_addr ;
      /* ignore the link local address */
      if (((sock6->sin6_addr.s6_addr[0] & 0xFF) != 0xFE) ||
	  ((sock6->sin6_addr.s6_addr[1] & 0xC0) != 0x80))
	ret = OFC_TRUE ;
    }
#endif      
  return (ret) ;
}

OFC_INT ofc_net_interface_count_impl(OFC_VOID) {
  int max_count;
  struct ifaddrs *ifap ;
  struct ifaddrs *ifap_index ;

  max_count = 0 ;
  if (getifaddrs(&ifap) == 0)
    {
      /*
       * Count the number of entries
       */
      for (ifap_index = ifap ; 
	   ifap_index != NULL ;
	   ifap_index = ifap_index->ifa_next) 
	{
	  if (!(ifap_index->ifa_flags & IFF_LOOPBACK) &&
	      ((ifap_index->ifa_flags & IFF_UP)) &&
	      match_families (ifap_index))
	    max_count++ ;
	}
      freeifaddrs (ifap) ;
    }
  return (max_count) ;
}

OFC_VOID ofc_net_interface_addr_impl(OFC_INT index,
                                     OFC_IPADDR *pinaddr,
                                     OFC_IPADDR *pbcast,
                                     OFC_IPADDR *pmask) {
  int max_count;
  struct ifaddrs *ifap ;
  struct ifaddrs *ifap_index ;
  struct sockaddr_in *pAddrInet ;
  struct sockaddr_in6 *pAddrInet6 ;
  OFC_BOOL found ;
  OFC_INT i ;

  max_count = 0 ;

  if (pinaddr != OFC_NULL)
    {
      pinaddr->ip_version = OFC_FAMILY_IP ;
      pinaddr->u.ipv4.addr = OFC_INADDR_NONE ;
    }
  if (pbcast != OFC_NULL)
    {
      pbcast->ip_version = OFC_FAMILY_IP ;
      pbcast->u.ipv4.addr = OFC_INADDR_NONE ;
    }
  if (pmask != OFC_NULL)
    {
      pmask->ip_version = OFC_FAMILY_IP ;
      pmask->u.ipv4.addr = OFC_INADDR_NONE ;
    }

  if (getifaddrs(&ifap) == 0)
    {
      /*
       * Count the number of entries
       */
      found = OFC_FALSE ;
      for (ifap_index = ifap ; 
	   ifap_index != NULL && !found ; )
	{
	  if (!(ifap_index->ifa_flags & IFF_LOOPBACK) &&
	      (ifap_index->ifa_flags & IFF_UP) &&
	      match_families (ifap_index))
	    {
	      if (max_count == index)
		found = OFC_TRUE ;
	      else
		{
		  max_count++ ;
		  ifap_index = ifap_index->ifa_next ;
		}
	    }
	  else
	    ifap_index = ifap_index->ifa_next ;
	}

      if (found) 
	{
	  if (ifap_index->ifa_addr->sa_family == AF_INET)
	    {
	      if (pinaddr != OFC_NULL)
		{
		  pAddrInet = (struct sockaddr_in *) ifap_index->ifa_addr ;
		  pinaddr->ip_version = OFC_FAMILY_IP ;
		  pinaddr->u.ipv4.addr = 
		    OFC_NET_NTOL (&pAddrInet->sin_addr.s_addr, 0) ;
		}

	      if (pmask != OFC_NULL)
		{
		  pAddrInet = (struct sockaddr_in *) ifap_index->ifa_netmask ;
		  pmask->ip_version = OFC_FAMILY_IP ;
		  pmask->u.ipv4.addr = 
		    OFC_NET_NTOL (&pAddrInet->sin_addr.s_addr, 0) ;
		}
	      if (pbcast != OFC_NULL)
		{
		  pAddrInet = (struct sockaddr_in *) ifap_index->ifa_netmask ;
		  pbcast->ip_version = OFC_FAMILY_IP ;
		  pbcast->u.ipv4.addr = OFC_INADDR_BROADCAST ;
		  pbcast->u.ipv4.addr &= 
		    ~OFC_NET_NTOL (&pAddrInet->sin_addr.s_addr, 0) ;
		  pAddrInet = (struct sockaddr_in *) ifap_index->ifa_addr ;
		  pbcast->u.ipv4.addr |=
		    OFC_NET_NTOL (&pAddrInet->sin_addr.s_addr, 0) ;
		}
	    }
	  else if (ifap_index->ifa_addr->sa_family == AF_INET6) {
                OFC_INT scope;

                pAddrInet6 = (struct sockaddr_in6 *) ifap_index->ifa_addr;
                scope = pAddrInet6->sin6_scope_id;

		if (pinaddr != OFC_NULL) {
		  pAddrInet6 = (struct sockaddr_in6 *) ifap_index->ifa_addr ;
		  pinaddr->ip_version = OFC_FAMILY_IPV6 ;
		  for (i = 0 ; i < 16 ; i++)
		    pinaddr->u.ipv6._s6_addr[i] =
		      pAddrInet6->sin6_addr.s6_addr[i] ;
		  pinaddr->u.ipv6.scope = scope;
		}

		if (pmask != OFC_NULL) {
		  pAddrInet6 = (struct sockaddr_in6 *) ifap_index->ifa_netmask ;
		  pmask->ip_version = OFC_FAMILY_IPV6 ;
		  for (i = 0 ; i < 16 ; i++)
		    pmask->u.ipv6._s6_addr[i] =
		      pAddrInet6->sin6_addr.s6_addr[i] ;
		  pmask->u.ipv6.scope = scope;
		}
		if (pbcast != OFC_NULL) {
		  pbcast->ip_version = OFC_FAMILY_IPV6 ;
		  pbcast->u.ipv6 = ofc_in6addr_bcast ;
		  pbcast->u.ipv6.scope = scope;
		}
	    }
	}
      freeifaddrs(ifap) ;
    }
}

OFC_CORE_LIB OFC_VOID
ofc_net_interface_wins_impl(OFC_INT index, OFC_INT *num_wins,
                            OFC_IPADDR **winslist) {
  /*
   * This is not provided by the platform
   */
  if (num_wins != OFC_NULL)
    *num_wins = 0 ;
  if (winslist != OFC_NULL)
    *winslist = OFC_NULL ;
}

OFC_VOID ofc_net_resolve_dns_name_impl(OFC_LPCSTR name,
                                       OFC_UINT16 *num_addrs,
                                       OFC_IPADDR *ip) {
  struct addrinfo *res ;
  struct addrinfo *p ;
  struct addrinfo hints ;

  OFC_INT i ;
  OFC_INT j ;
  OFC_IPADDR temp ;
  int ret ;

#if defined(OFC_DISCOVER_IPV6)
#if defined(OFC_DISCOVER_IPV4)
  hints.ai_family = AF_UNSPEC ;
#else
  hints.ai_family = AF_INET6 ;
#endif
#else
#if defined(OFC_DISCOVER_IPV4)
  hints.ai_family = AF_INET ;
#else
#error "Neither IPv4 nor IPv6 Configured"
#endif
#endif
  hints.ai_socktype = 0 ;
  hints.ai_flags = AI_ADDRCONFIG ;

  if (ofc_pton(name, &temp) != 0)
    hints.ai_flags |= AI_NUMERICHOST ;

  res = NULL ;
  ret = getaddrinfo (name, NULL, &hints, &res) ;

  if (ret != 0)
    {
      *num_addrs = 0 ;
    }
  else
    {
      for (i = 0, p = res ; p != NULL && i < *num_addrs ; i++, p = p->ai_next)
	{
	  if (p->ai_family == AF_INET)
	    {
	      struct sockaddr_in *sa ;
	      sa = (struct sockaddr_in *) p->ai_addr ;

	      ip[i].ip_version = OFC_FAMILY_IP ;
	      ip[i].u.ipv4.addr = OFC_NET_NTOL (&sa->sin_addr.s_addr, 0) ;
	    }
	  else if (p->ai_family == AF_INET6)
	    {
	      struct sockaddr_in6 *sa6 ;
	      sa6 = (struct sockaddr_in6 *) p->ai_addr ;

	      ip[i].ip_version = OFC_FAMILY_IPV6 ;
	      for (j = 0 ; j < 16 ; j++)
		{
		  ip[i].u.ipv6._s6_addr[j] = 
		    sa6->sin6_addr.s6_addr[j] ; 
		}
	      ip[i].u.ipv6.scope = sa6->sin6_scope_id ;
	    }
	}
      freeaddrinfo (res) ;
      *num_addrs = i ;
    }
}

OFC_CORE_LIB OFC_VOID
ofc_net_set_handle_impl(OFC_UINT64 network_handle)
{
}

/** \} */
