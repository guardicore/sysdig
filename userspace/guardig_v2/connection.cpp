/*
 * connection.cpp
 *
 *  Created on: Sep 4, 2016
 *      Author: user
 */

#include <arpa/inet.h>
#include "event.h"
#include "connection.h"
#include "process.h"
#include "defs.h"


connection *filedescriptor::add_connection(connection &conninfo)
{
	return m_conntable.add(conninfo.m_conntuple, conninfo);
}


connection *filedescriptor::get_connection(ipv4tuple &conntuple)
{
	return m_conntable.get(conntuple);
}


void filedescriptor::delete_connection(ipv4tuple &conntuple)
{
	m_conntable.remove(conntuple);
}


void connection::print()
{
	struct in_addr sip, dip;
	char sip_buf[20], dip_buf[20];
	const char *proto, *type;

	if (m_fdinfo == NULL || m_fdinfo->m_procinfo == NULL)
	{
		ASSERT(false);
		return;
	}

	if (m_fdinfo->m_type == SCAP_FD_IPV4_SOCK)
		type = "ipv4";
	else
		type = "unknown";


	if (m_fdinfo->m_proto == SOCK_STREAM)
		proto = "tcp";
	else if (m_fdinfo->m_proto == SOCK_DGRAM)
		proto = "udp";
	else
		proto = "unknown";


	sip.s_addr = m_conntuple.m_sip;
	dip.s_addr = m_conntuple.m_dip;
	strncpy(sip_buf, inet_ntoa(sip), sizeof(sip_buf));
	strncpy(dip_buf, inet_ntoa(dip), sizeof(dip_buf));
	sip_buf[sizeof(sip_buf) - 1] = '\0';
	dip_buf[sizeof(dip_buf) - 1] = '\0';

	printf("C %s %ld %u %u %ld %ld %d %s %s \"%s\" \"%s\" \"unknown\" %ld \"%s\" %s~%d->%s~%d %d\n",
				m_evt_name.c_str(), m_fdinfo->m_procinfo->m_pid, m_time_s, m_time_ns, m_errorcode,
				m_fdinfo->m_fd, 1 /* threads */, type, proto, m_fdinfo->m_procinfo->m_exe.c_str(),
				m_fdinfo->m_procinfo->m_comm.c_str(), m_fdinfo->m_procinfo->m_ppid, m_fdinfo->m_procinfo->m_pcomm.c_str(),
				sip_buf, m_conntuple.m_sport, dip_buf, m_conntuple.m_dport, m_fdinfo->m_procinfo->m_uid);
}


void connection::print_close(uint64_t ts)
{
	set_time(ts);
	m_evt_name = "close";

	print();
}


void connection::print_volume()
{
	struct in_addr sip, dip;
	char sip_buf[20], dip_buf[20];
	const char *proto, *type;

	if (m_fdinfo == NULL || m_fdinfo->m_procinfo == NULL)
	{
		ASSERT(false);
		return;
	}

	if (m_fdinfo->m_type == SCAP_FD_IPV4_SOCK)
		type = "ipv4";
	else
		type = "unknown";


	if (m_fdinfo->m_proto == SOCK_STREAM)
		proto = "tcp";
	else if (m_fdinfo->m_proto == SOCK_DGRAM)
		proto = "udp";
	else
		proto = "unknown";


	sip.s_addr = m_conntuple.m_sip;
	dip.s_addr = m_conntuple.m_dip;
	strncpy(sip_buf, inet_ntoa(sip), sizeof(sip_buf));
	strncpy(dip_buf, inet_ntoa(dip), sizeof(dip_buf));
	sip_buf[sizeof(sip_buf) - 1] = '\0';
	dip_buf[sizeof(dip_buf) - 1] = '\0';

	printf("V %s %ld %u %u %ld %ld %d %s %s \"%s\" \"%s\" \"unknown\" %ld \"%s\" %s~%d->%s~%d %d %lu %lu\n",
				m_evt_name.c_str(), m_fdinfo->m_procinfo->m_pid, m_time_s, m_time_ns, m_errorcode,
				m_fdinfo->m_fd, 1 /* threads */, type, proto, m_fdinfo->m_procinfo->m_exe.c_str(),
				m_fdinfo->m_procinfo->m_comm.c_str(), m_fdinfo->m_procinfo->m_ppid, m_fdinfo->m_procinfo->m_pcomm.c_str(),
				sip_buf, m_conntuple.m_sport, dip_buf, m_conntuple.m_dport, m_fdinfo->m_procinfo->m_uid,
				m_sent_bytes, m_recv_bytes);
}

