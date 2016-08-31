#include <arpa/inet.h>
#include "utils.h"
#include "threadinfo.h"
#include "fdinfo.h"
#include "event.h"
#include "scap.h"
#include "trace.h"

void print_connection(const char *evt_name, guardig_evt *pgevent)
{
	static const char *sock_type = "ipv4";
	guardig_threadinfo *tinfo = pgevent->m_tinfo;
	guardig_fdinfo_t *fdinfo = pgevent->m_fdinfo;
	const char *proto;

	if (tinfo == NULL || fdinfo == NULL)
		return;

	if (fdinfo->is_tcp_socket())
	{
		proto = "tcp";
	}
	else if (fdinfo->is_udp_socket())
	{
		proto = "udp";
	}
	else
	{
		TRACE_DEBUG("unknown protocol");
		return;
	}

	printf("C %s %ld %u %u %d %ld %d %s %s \"%s\" \"%s\" \"unknown\" %d \"%s\" %s~%d->%s~%d \"%s\"\n",
			evt_name, tinfo->m_pid, 0 /* time */, 0 /* time_ns */, pgevent->m_errorcode,
			tinfo->m_lastevent_fd /* FIXME: there should be a better way */,
			1 /* threads */, sock_type, proto, "<path>", tinfo->m_exe.c_str(), -1 /* ppid */, "<parent_proc_name>",
			inet_ntoa(*((struct in_addr *)&fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip)),
			fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport,
			inet_ntoa(*((struct in_addr *)&fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip)),
			fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport,
			"<user>");
}



