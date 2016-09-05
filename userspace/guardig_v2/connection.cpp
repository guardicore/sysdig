/*
 * connection.cpp
 *
 *  Created on: Sep 4, 2016
 *      Author: user
 */

#include <arpa/inet.h>
#include "event.h"
#include "connection.h"

void connection::print()
{
	struct in_addr sip, dip;
	char sip_buf[20], dip_buf[20];
	const char *proto, *type;

	if (m_type == SCAP_FD_IPV4_SOCK)
		type = "ipv4";
	else
		type = "unknown";


	if (m_proto == SCAP_L4_TCP)
		proto = "tcp";
	else if (m_proto == SCAP_L4_TCP)
		proto = "udp";
	else
		proto = "unknown";


	sip.s_addr = m_sip;
	dip.s_addr = m_dip;
	strncpy(sip_buf, inet_ntoa(sip), sizeof(sip_buf));
	strncpy(dip_buf, inet_ntoa(dip), sizeof(dip_buf));
	sip_buf[sizeof(sip_buf) - 1] = '\0';
	dip_buf[sizeof(dip_buf) - 1] = '\0';

	printf("C %s %d %lu %lu %ld %ld %d %s %s \"%s\" \"%s\" \"unknown\" %d \"%s\" %s~%d->%s~%d %d\n",
				m_evt_name.c_str(), m_pid, m_time, m_time_ns, m_errorcode, m_fd, 1 /* threads */, type,
				proto, m_proc_path.c_str(), m_proc_name.c_str(), m_ppid, m_pproc_name.c_str(), sip_buf,
				m_sport, dip_buf, m_dport, m_uid);
}

