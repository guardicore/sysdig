#include <netinet/in.h>
#include "defs.h"
#include "parser.h"
#include "trace.h"


//
// Helper function to allocate a socket fd, initialize it by parsing its parameters and add it to the fd table of the given thread.
//
inline void guardig_parser::add_socket(guardig_evt *evt, int64_t fd, uint32_t domain, uint32_t type, uint32_t protocol)
{
	guardig_fdinfo_t fdi;

	//
	// Populate the new fdi
	//
	memset(&(fdi.m_sockinfo.m_ipv4info), 0, sizeof(fdi.m_sockinfo.m_ipv4info));
	fdi.m_type = SCAP_FD_UNKNOWN;
	fdi.m_sockinfo.m_ipv4info.m_fields.m_l4proto = SCAP_L4_UNKNOWN;

	if(domain == PPM_AF_UNIX)
	{
		fdi.m_type = SCAP_FD_UNIX_SOCK;
	}
	else if(domain == PPM_AF_INET || domain == PPM_AF_INET6)
	{
		fdi.m_type = (domain == PPM_AF_INET)? SCAP_FD_IPV4_SOCK : SCAP_FD_IPV6_SOCK;

		if(protocol == IPPROTO_TCP)
		{
			fdi.m_sockinfo.m_ipv4info.m_fields.m_l4proto = SCAP_L4_TCP;
		}
		else if(protocol == IPPROTO_UDP)
		{
			fdi.m_sockinfo.m_ipv4info.m_fields.m_l4proto = SCAP_L4_UDP;
		}
		else if(protocol == IPPROTO_IP)
		{
			//
			// XXX: we mask type because, starting from linux 2.6.27, type can be ORed with
			//      SOCK_NONBLOCK and SOCK_CLOEXEC. We need to validate that byte masking is
			//      acceptable
			//
			if((type & 0xff) == SOCK_STREAM)
			{
				fdi.m_sockinfo.m_ipv4info.m_fields.m_l4proto = SCAP_L4_TCP;
			}
			else if((type & 0xff) == SOCK_DGRAM)
			{
				fdi.m_sockinfo.m_ipv4info.m_fields.m_l4proto = SCAP_L4_UDP;
			}
			else
			{
				ASSERT(false);
			}
		}
		else if(protocol == IPPROTO_ICMP)
		{
			fdi.m_sockinfo.m_ipv4info.m_fields.m_l4proto = SCAP_L4_ICMP;
		}
	}
	else
	{
		if(domain != 16 &&  // AF_NETLINK, used by processes to talk to the kernel
		        domain != 10 && // IPv6
		        domain != 17)   // AF_PACKET, used for packet capture
		{
			//
			// IPv6 will go here
			//
			ASSERT(false);
		}
	}

#ifndef INCLUDE_UNKNOWN_SOCKET_FDS
	if(fdi.m_type == SCAP_FD_UNKNOWN)
	{
		return;
	}
#endif

	//
	// Add the fd to the table.
	//
	evt->m_fdinfo = evt->m_tinfo->add_fd(fd, &fdi);
}


uint8_t* guardig_parser::reserve_event_buffer()
{
	if(m_tmp_events_buffer.empty())
	{
		return (uint8_t*)malloc(sizeof(uint8_t)*SP_EVT_BUF_SIZE);
	}
	else
	{
		auto ptr = m_tmp_events_buffer.top();
		m_tmp_events_buffer.pop();
		return ptr;
	}
}


void guardig_parser::store_event(guardig_evt *evt)
{
	guardig_threadinfo *tinfo;
	bool update_tinfo = false;

	if (evt->m_tinfo == NULL)
	{
		TRACE_DEBUG("tinfo is NULL");
		return;
	}

	uint32_t elen;

	//
	// Make sure the event data is going to fitevt->m_tinfo = new guardig_threadinfo;
	//
	elen = scap_event_getlen(evt->m_pevt);

	if(elen > SP_EVT_BUF_SIZE)
	{
		TRACE_DEBUG("event data is too big");
		ASSERT(false);
		return;
	}

	if(evt->m_tinfo->m_lastevent_data == NULL)
	{
		evt->m_tinfo->m_lastevent_data = reserve_event_buffer();
	}
	memcpy(evt->m_tinfo->m_lastevent_data, evt->m_pevt, elen);
	evt->m_tinfo->m_lastevent_cpuid = evt->get_cpuid();
}


bool guardig_parser::retrieve_enter_event(guardig_evt *enter_evt, guardig_evt *exit_evt)
{
	//
	// Make sure there's a valid thread info
	//
	if (exit_evt->m_tinfo == NULL)
	{
		TRACE_DEBUG("tinfo is NULL");
		return false;
	}

	//
	// Retrieve the copy of the enter event and initialize it
	//
	if(!(exit_evt->m_tinfo->is_lastevent_data_valid() && exit_evt->m_tinfo->m_lastevent_data))
	{
		//
		// This happen especially at the beginning of trace files, where events
		// can be truncated
		//
		return false;
	}

	enter_evt->init(exit_evt->m_tinfo->m_lastevent_data, exit_evt->m_tinfo->m_lastevent_cpuid);

	//
	// Make sure that we're using the right enter event, to prevent inconsistencies when events
	// are dropped
	//
	if(enter_evt->get_type() != (exit_evt->get_type() - 1))
	{
		exit_evt->m_tinfo->set_lastevent_data_validity(false);
		return false;
	}

	return true;
}


void guardig_parser::parse_socket_exit(guardig_evt *pgevent)
{
	guardig_evt_param *parinfo;
	int64_t fd;
	uint32_t domain;
	uint32_t type;
	uint32_t protocol;
	guardig_evt *enter_evt = &m_tmp_evt;

	//
	// NOTE: we don't check the return value of get_param() because we know the arguments we need are there.
	// XXX this extraction would be much faster if we parsed the event mnaually to extract the
	// parameters in one scan. We don't care too much because we assume that we get here
	// seldom enough that saving few tens of CPU cycles is not important.
	//
	parinfo = pgevent->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd = *(int64_t *)parinfo->m_val;

	if(fd < 0)
	{
		//
		// socket() failed. Nothing to add to the table.
		//
		TRACE_DEBUG("socket failed");
		return;
	}

	//
	// Load the enter event so we can access its arguments
	//
	if(!retrieve_enter_event(enter_evt, pgevent))
	{
		TRACE_DEBUG("couldn't retrieve enter event");
		return;
	}

	//
	// Extract the arguments
	//
	parinfo = enter_evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	domain = *(uint32_t *)parinfo->m_val;

	parinfo = enter_evt->get_param(1);
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	type = *(uint32_t *)parinfo->m_val;

	parinfo = enter_evt->get_param(2);
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	protocol = *(uint32_t *)parinfo->m_val;

	TRACE_DEBUG("new socket: tid: %lu, fd: %ld, domain: %u, type: %u, protocol: %u",
			pgevent->m_pevt->tid, fd, domain, type, protocol);
	//
	// Allocate a new fd descriptor, populate it and add it to the thread fd table
	//
	add_socket(pgevent, fd, domain, type, protocol);
	return;
}


void guardig_parser::process_event(guardig *inspector, guardig_evt *pgevent)
{

	pgevent->m_tinfo = inspector->get_threadinfo(pgevent->m_pevt->tid);

	switch(pgevent->m_pevt->type)
	{
	case PPME_SOCKET_CONNECT_E:
	case PPME_SOCKET_CONNECT_X:
		TRACE_DEBUG("New connect event");
		break;

	case PPME_SOCKET_SOCKET_E:
		store_event(pgevent);
		break;

	case PPME_SOCKET_SOCKET_X:
		parse_socket_exit(pgevent);
		break;

	default:
		break;
	}

	return;
}
