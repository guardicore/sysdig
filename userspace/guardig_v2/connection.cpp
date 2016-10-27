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

#define RESET_COLOR "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

bool g_isatty = false;
char g_colors[][10] = {KRED, KGRN, KYEL, KBLU, KMAG, KCYN, KWHT};
uint32_t connection::color_idx = 0;

connection *filedescriptor::add_connection(connection &conninfo)
{
	switch(m_proto)
	{
	case SOCK_DGRAM:
		return m_conntable.add(conninfo.m_conntuple, conninfo);
	case SOCK_STREAM:
		m_tcp_conn_valid = true;
		m_tcp_conn = conninfo;
		return &m_tcp_conn;
	default:
		TRACE_DEBUG("unknown protocol");
		return NULL;
	}
}


connection *filedescriptor::get_connection(ipv4tuple &conntuple)
{
	switch(m_proto)
	{
	case SOCK_DGRAM:
		return m_conntable.get(conntuple);

	case SOCK_STREAM:
		if (m_tcp_conn_valid && m_tcp_conn.m_conntuple == conntuple)
			return &m_tcp_conn;
		else
			return NULL;

	default:
		TRACE_DEBUG("unknown protocol");
		return NULL;
	}
}


void filedescriptor::delete_connection(ipv4tuple &conntuple)
{
	switch(m_proto)
	{
	case SOCK_DGRAM:
		m_conntable.remove(conntuple);
		break;

	case SOCK_STREAM:
		if (m_tcp_conn_valid)
		{
			m_tcp_conn_valid = false;
			m_tcp_conn.init();
		}
		break;

	default:
		TRACE_DEBUG("unknown protocol");
		break;
	}
}


void filedescriptor::close_all_connections(CloseReason reason, uint64_t timestamp)
{
	switch(m_proto)
	{
	case SOCK_DGRAM:
		for ( auto it = m_conntable.begin(); it != m_conntable.end(); )
		{
			connection *conninfo = &(it->second);
#ifdef PRINT_REPORTS
			conninfo->print_volume();
			conninfo->print_close(reason, timestamp);
#endif
			it = m_conntable.erase(it);
		}
		break;

	case SOCK_STREAM:
		if (m_tcp_conn_valid)
		{
#ifdef PRINT_REPORTS
			m_tcp_conn.print_volume();
			m_tcp_conn.print_close(reason, timestamp);
#endif
			m_tcp_conn_valid = false;
		}
		break;

	default:
		TRACE_DEBUG("unknown protocol");
		break;
	}
}


/*
* Removes all inactive connections from fd.
* @return wether the fd has no connections after removal and can be deleted. 
*/
bool filedescriptor::close_inactive_connections(uint64_t timestamp)
{
	time_t timestamp_sec = timestamp / 1000000000;

	// FIXME: change the event name to "timeout"
	switch(m_proto)
	{
	case SOCK_DGRAM:
		for ( auto it = m_conntable.begin(); it != m_conntable.end(); )
		{
			connection *conninfo = &(it->second);
			if (timestamp_sec - conninfo->m_active_time > INACTIVE_CONN_REMOVE_SECONDS)
			{
#ifdef PRINT_REPORTS
				conninfo->print_volume();
				conninfo->print_close(GD_TIMEOUT, timestamp);
#endif
				it = m_conntable.erase(it);
			}
			else
				++it;
		}
		return m_conntable.size() == 0;

	case SOCK_STREAM:
		if (m_tcp_conn_valid)
		{
			if (timestamp_sec - m_tcp_conn.m_active_time > INACTIVE_CONN_REMOVE_SECONDS)
			{
#ifdef PRINT_REPORTS
				m_tcp_conn.print_volume();
				m_tcp_conn.print_close(GD_TIMEOUT, timestamp);
#endif
				m_tcp_conn_valid = false;
			}
		}
		return true;

	default:
		TRACE_DEBUG("unknown protocol");
		break;
	}
}


void connection::print(bool with_volume)
{
	struct in_addr sip, dip;
	char sip_buf[20], dip_buf[20];
	const char *proto, *type;

	if (!m_printed_creation)
	{
		m_printed_creation = true;

		//
		// choose color
		//
		if (g_isatty)
			m_color = color_idx++ % (sizeof(g_colors) / sizeof(g_colors[0]));
	}

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

	if (with_volume)
	{
		if (g_isatty)
			printf("%s", g_colors[m_color]);

		printf("V %s %ld %u %u %ld %ld %d %s %s \"%s\" \"%s\" \"unknown\" %ld \"%s\" %s~%d->%s~%d %d %lu %lu\n",
				m_evt_name.c_str(), m_fdinfo->m_procinfo->m_pid, m_time_s, m_time_ns, m_errorcode,
				m_fdinfo->m_fd, 1 /* threads */, type, proto, m_fdinfo->m_procinfo->m_exe.c_str(),
				m_fdinfo->m_procinfo->m_comm.c_str(), m_fdinfo->m_procinfo->m_ppid, m_fdinfo->m_procinfo->m_pcomm.c_str(),
				sip_buf, m_conntuple.m_sport, dip_buf, m_conntuple.m_dport, m_fdinfo->m_procinfo->m_uid,
				m_sent_bytes, m_recv_bytes);

		if (g_isatty)
		{
			printf(RESET_COLOR);
			fflush(stdout);
		}
	}
	else
	{
		if (g_isatty)
			printf("%s", g_colors[m_color]);

		printf("C %s %ld %u %u %ld %ld %d %s %s \"%s\" \"%s\" \"unknown\" %ld \"%s\" %s~%d->%s~%d %d\n",
				m_evt_name.c_str(), m_fdinfo->m_procinfo->m_pid, m_time_s, m_time_ns, m_errorcode,
				m_fdinfo->m_fd, 1 /* threads */, type, proto, m_fdinfo->m_procinfo->m_exe.c_str(),
				m_fdinfo->m_procinfo->m_comm.c_str(), m_fdinfo->m_procinfo->m_ppid, m_fdinfo->m_procinfo->m_pcomm.c_str(),
				sip_buf, m_conntuple.m_sport, dip_buf, m_conntuple.m_dport, m_fdinfo->m_procinfo->m_uid);

		if (g_isatty)
		{
			printf(RESET_COLOR);
			fflush(stdout);
		}
	}
}


void connection::print_close(CloseReason reason, uint64_t ts)
{
	if (m_printed_creation)
	{
		set_time(ts);
		m_errorcode = 0;

#ifdef _DEBUG
		switch (reason)
		{
		case GD_NORMAL:
			m_evt_name = "close";
			break;
		case GD_TIMEOUT:
			m_evt_name = "timeout";
			break;
		case GD_PROC_EXIT:
			m_evt_name = "procexit";
			break;
		case GD_MISSED_CLOSE:
			m_evt_name = "missed_close";
			break;
		default:
			ASSERT(false);
			return;
		}
#else
		m_evt_name = "close";
#endif

		print();
	}
}


void connection::print_volume()
{
	if (m_printed_creation)
	{
		print(true);
	}
}

