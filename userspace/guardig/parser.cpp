#include <netinet/in.h>
#include "defs.h"
#include "parser.h"
#include "trace.h"
#include "utils.h"


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


bool guardig_parser::set_ipv4_addresses_and_ports(guardig_fdinfo_t* fdinfo, uint8_t* packed_data)
{
	uint32_t tsip, tdip;
	uint16_t tsport, tdport;

	tsip = *(uint32_t *)(packed_data + 1);
	tsport = *(uint16_t *)(packed_data + 5);
	tdip = *(uint32_t *)(packed_data + 7);
	tdport = *(uint16_t *)(packed_data + 11);

	if(fdinfo->m_type == SCAP_FD_IPV4_SOCK)
	{
		if((tsip == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip &&
			tsport == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport &&
			tdip == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip &&
			tdport == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport) ||
			(tdip == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip &&
			tdport == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport &&
			tsip == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip &&
			tsport == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport)
			)
		{
			return false;
		}
	}

	fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip = tsip;
	fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport = tsport;
	fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip = tdip;
	fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport = tdport;

	return true;
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


void guardig_parser::parse_bind_exit(guardig_evt *pgevent)
{
	guardig_evt_param *parinfo;
	int64_t retval;
	const char *parstr;
	uint8_t *packed_data;
	uint8_t family;

	if (pgevent->m_tinfo == NULL)
	{
		TRACE_DEBUG("tinfo is null");
		return;
	}

	parinfo = pgevent->get_param(0);
	ASSERT(parinfo->m_len == sizeof(uint64_t));
	retval = *(int64_t*)parinfo->m_val;

	if(retval < 0)
	{
		return;
	}

	parinfo = pgevent->get_param(1);
	if(parinfo->m_len == 0)
	{
		//
		// No address, there's nothing we can really do with this.
		// This happens for socket types that we don't support, so we have the assertion
		// to make sure that this is not a type of socket that we support.
		//

		// FIXME: This can happen because we're are not closing sockets yet, so if there was once an
		// IPv4 socket and now it's an IPv6 socket which we ignored this assert can be false.
		// Uncomment these lines after I add support to close events.
		//if (pgevent->m_fdinfo != NULL)
		//	ASSERT(!(pgevent->m_fdinfo->is_unix_socket() || pgevent->m_fdinfo->is_ipv4_socket()));
		return;
	}

	packed_data = (uint8_t*)parinfo->m_val;

	family = *packed_data;

	if (pgevent->m_fdinfo == NULL)
	{
		ASSERT(family != PPM_AF_INET);
		return;
	}

	//
	// Update the FD info with this tuple, assume that if port > 0, means that
	// the socket is used for listening
	//
	if(family == PPM_AF_INET)
	{
		uint16_t port = *(uint16_t *)(packed_data + 5);
		if(port > 0)
		{
			pgevent->m_fdinfo->m_type = SCAP_FD_IPV4_SERVSOCK;
			pgevent->m_fdinfo->m_sockinfo.m_ipv4serverinfo.m_port = port;
		}

		TRACE_DEBUG("bind: %s, tid: %ld, fd: %ld, port: %hu (AF_INET)",
				pgevent->m_tinfo->m_exe.c_str(),
				pgevent->m_tinfo->m_tid, pgevent->m_tinfo->m_lastevent_fd, port);
	}
	else if (family == PPM_AF_INET6)
	{
		uint16_t port = *(uint16_t *)(packed_data + 17);
		if(port > 0)
		{
			pgevent->m_fdinfo->m_type = SCAP_FD_IPV6_SERVSOCK;
			pgevent->m_fdinfo->m_sockinfo.m_ipv6serverinfo.m_port = port;
		}
		TRACE_DEBUG("bind: %s, tid: %ld, fd: %ld, port: %hu (AF_INET6)",
				pgevent->m_tinfo->m_exe.c_str(),
				pgevent->m_tinfo->m_tid, pgevent->m_tinfo->m_lastevent_fd, port);
	}

	//
	// Update the name of this socket
	//
	//evt->m_fdinfo->m_name = evt->get_param_as_str(1, &parstr, sinsp_evt::PF_SIMPLE);
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

	if (domain != PPM_AF_INET)
	{
		TRACE_DEBUG("domain not supprted: %d", domain);
		return;
	}

	TRACE_DEBUG("socket: %s, tid: %lu, fd: %ld, domain: %u, type: %u, protocol: %u",
			pgevent->m_tinfo->m_exe.c_str(),
			pgevent->m_pevt->tid, fd, domain, type, protocol);
	//
	// Allocate a new fd descriptor, populate it and add it to the thread fd table
	//
	add_socket(pgevent, fd, domain, type, protocol);
	return;
}


void guardig_parser::parse_accept_exit(guardig_evt *pgevent)
{
	guardig_evt_param *parinfo;
	int64_t fd;
	uint8_t* packed_data;
	//unordered_map<int64_t, sinsp_fdinfo_t>::iterator fdit;
	guardig_fdinfo_t fdi;
	const char *parstr;

	//
	// Lookup the thread
	//
	if(!pgevent->m_tinfo)
	{
		ASSERT(false);
		return;
	}

	//
	// Extract the fd
	//
	parinfo = pgevent->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd = *(int64_t *)parinfo->m_val;

	if(fd < 0)
	{
		//
		// Accept failure.
		// Do nothing.
		//
		//TRACE_DEBUG("accept failed: %ld", fd);
		return;
	}

	//
	// Update the last event fd. It's needed by the filtering engine
	//
	//evt->m_tinfo->m_lastevent_fd = fd;

	//
	// Extract the address
	//
	parinfo = pgevent->get_param(1);
	if(parinfo->m_len == 0)
	{
		//
		// No address, there's nothing we can really do with this.
		// This happens for socket types that we don't support, so we have the assertion
		// to make sure that this is not a type of socket that we support.
		//
		return;
	}

	packed_data = (uint8_t*)parinfo->m_val;

	//
	// Populate the fd info class
	//
	if(*packed_data == PPM_AF_INET)
	{
		set_ipv4_addresses_and_ports(&fdi, packed_data);
		fdi.m_type = SCAP_FD_IPV4_SOCK;
		fdi.m_sockinfo.m_ipv4info.m_fields.m_l4proto = SCAP_L4_TCP;
	}
	else if(*packed_data == PPM_AF_INET6)
	{
		//
		// We only support IPv4-mapped IPv6 addresses (http://en.wikipedia.org/wiki/IPv6#IPv4-mapped_IPv6_addresses)
		// for the moment
		//
		// FIXME: IPv6 is not supported at the moment
		return;
		/*
		uint8_t* sip = packed_data + 1;
		uint8_t* dip = packed_data + 19;

		if(sinsp_utils::is_ipv4_mapped_ipv6(sip) && sinsp_utils::is_ipv4_mapped_ipv6(dip))
		{
			set_ipv4_mapped_ipv6_addresses_and_ports(&fdi, packed_data);
			fdi.m_type = SCAP_FD_IPV4_SOCK;
			fdi.m_sockinfo.m_ipv4info.m_fields.m_l4proto = SCAP_L4_TCP;
		}
		else
		{
			fdi.m_type = SCAP_FD_IPV6_SOCK;
		}
		*/
	}
	else if(*packed_data == PPM_AF_UNIX)
	{
		//fdi.m_type = SCAP_FD_UNIX_SOCK;
		//set_unix_info(&fdi, packed_data);
		TRACE_DEBUG("unix socket is ignored");
		return;
	}
	else
	{
		TRACE_DEBUG("unsupported family");
		//
		// Unsupported family
		//
		return;
	}

	//fdi.m_name = evt->get_param_as_str(1, &parstr, sinsp_evt::PF_SIMPLE);
	fdi.m_flags = 0;

	/*
	if(m_fd_listener)
	{
		m_fd_listener->on_accept(evt, fd, packed_data, &fdi);
	}
	*/

	//
	// Mark this fd as a server
	//
	fdi.set_role_server();

	//
	// Add the entry to the table
	//
	pgevent->m_fdinfo = pgevent->m_tinfo->add_fd(fd, &fdi);

	print_connection("accept", pgevent);
	/*
	TRACE_DEBUG("accept: %s, tid: %ld, fd: %ld, dip: %08x, dport: %hu",
				pgevent->m_tinfo->m_exe.c_str(),
				pgevent->m_tinfo->m_tid, fd,
				pgevent->m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip,
				pgevent->m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport);
	*/
}


void guardig_parser::parse_connect_exit(guardig_evt *pgevent)
{
	guardig_evt_param *parinfo;
	uint8_t *packed_data;
	uint8_t family;
	unordered_map<int64_t, guardig_fdinfo_t>::iterator fdit;
	const char *parstr;
	int64_t retval;

	if (pgevent->m_tinfo == NULL)
	{
		TRACE_DEBUG("tinfo is null");
		return;
	}

	parinfo = pgevent->get_param(0);
	ASSERT(parinfo->m_len == sizeof(uint64_t));
	retval = *(int64_t*)parinfo->m_val;

	if (retval < 0)
	{
		//
		// connections that return with a SE_EINPROGRESS are totally legit.
		//
		if(retval != -EINPROGRESS)
		{
			return;
		}
	}

	parinfo = pgevent->get_param(1);
	if(parinfo->m_len == 0)
	{
		//
		// No address, there's nothing we can really do with this.
		// This happens for socket types that we don't support, so we have the assertion
		// to make sure that this is not a type of socket that we support.
		//
		if (pgevent->m_fdinfo != NULL)
			ASSERT(!(pgevent->m_fdinfo->is_unix_socket() || pgevent->m_fdinfo->is_ipv4_socket()));
		return;
	}

	packed_data = (uint8_t*)parinfo->m_val;

	//
	// Validate the family
	//
	family = *packed_data;

	if (pgevent->m_fdinfo == NULL)
	{
		ASSERT(family != PPM_AF_INET);
		return;
	}

	//
	// Fill the fd with the socket info
	//
	if(family == PPM_AF_INET || family == PPM_AF_INET6)
	{
		if(family == PPM_AF_INET6)
		{
			TRACE_DEBUG("IPv6 is not supported at the moment");
			return;
			//
			// For the moment, we only support IPv4-mapped IPv6 addresses
			// (http://en.wikipedia.org/wiki/IPv6#IPv4-mapped_IPv6_addresses)
			//
			/*
			uint8_t* sip = packed_data + 1;
			uint8_t* dip = packed_data + 19;

			if(!(sinsp_utils::is_ipv4_mapped_ipv6(sip) && sinsp_utils::is_ipv4_mapped_ipv6(dip)))
			{
				pgevent->m_fdinfo->m_name = pgevent->get_param_as_str(1, &parstr, sinsp_evt::PF_SIMPLE);
				pgevent->m_fdinfo->m_type = SCAP_FD_IPV6_SOCK;
				return;
			}

			pgevent->m_fdinfo->m_type = SCAP_FD_IPV4_SOCK;
			*/
		}

		//
		// This should happen only in case of a bug in our code, because I'm assuming that the OS
		// causes a connect with the wrong socket type to fail.
		// Assert in debug mode and just keep going in release mode.
		//
		ASSERT(pgevent->m_fdinfo->m_type == SCAP_FD_IPV4_SOCK ||
				pgevent->m_fdinfo->m_type == SCAP_FD_IPV4_SERVSOCK);

#ifndef HAS_ANALYZER
		//
		// Update the FD info with this tuple
		//
		if(family == PPM_AF_INET)
		{
			set_ipv4_addresses_and_ports(pgevent->m_fdinfo, packed_data);
			//
			// guyk: This line handles the case in which bind is called before
			// connect, which sets the type to SCAP_FD_IPV4_SERVSOCK even though
			// now we know that it's a client socket.
			//
			pgevent->m_fdinfo->m_type = SCAP_FD_IPV4_SOCK;
		}
		else
		{
			TRACE_DEBUG("IPv6 is not supported at the moment");
			return;
			//m_inspector->m_parser->set_ipv4_mapped_ipv6_addresses_and_ports(pgevent->m_fdinfo, packed_data);
		}
#endif

		//
		// Add the friendly name to the fd info
		//
		// FIXME: this can come handful in the future
		//pgevent->m_fdinfo->m_name = pgevent->get_param_as_str(1, &parstr, sinsp_evt::PF_SIMPLE);
	}
	else
	{
		if(!pgevent->m_fdinfo->is_unix_socket())
		{
			//
			// This should happen only in case of a bug in our code, because I'm assuming that the OS
			// causes a connect with the wrong socket type to fail.
			// Assert in debug mode and just keep going in release mode.
			//
			ASSERT(false);
		}


		// NOTE: we don't care about UNIX sockets
		return;

		//
		// Add the friendly name to the fd info
		//
		/*
		pgevent->m_fdinfo->m_name = pgevent->get_param_as_str(1, &parstr, sinsp_evt::PF_SIMPLE);

#ifndef HAS_ANALYZER
		//
		// Update the FD with this tuple
		//
		m_inspector->m_parser->set_unix_info(pgevent->m_fdinfo, packed_data);
#endif
		 */
	}

	//
	// Mark this fd as a client
	//
	pgevent->m_fdinfo->set_role_client();

	//
	// Call the protocol decoder callbacks associated to this event
	//
	// FIXME: I should use the callbacks mechanism to print the connect events.
	/*
	vector<sinsp_protodecoder*>::iterator it;
	for(it = m_connect_callbacks.begin(); it != m_connect_callbacks.end(); ++it)
	{
		(*it)->on_event(evt, CT_CONNECT);
	}
	*/

	//
	// If there's a listener callback, invoke it
	//
	/*
	if(m_fd_listener)
	{
		m_fd_listener->on_connect(evt, packed_data);
	}
	*/
	/*
	TRACE_DEBUG("connect: %s, tid: %ld, fd: %ld, dip: %08x, dport: %hu",
			pgevent->m_tinfo->m_exe.c_str(),
			pgevent->m_tinfo->m_tid, pgevent->m_tinfo->m_lastevent_fd,
			pgevent->m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip,
			pgevent->m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport);
			*/
	print_connection("connect", pgevent);
}


void guardig_parser::parse_clone_exit(guardig_evt *evt)
{
	guardig_evt_param* parinfo;
	int64_t tid = evt->get_tid();
	int64_t childtid;
	bool is_inverted_clone = false; // true if clone() in the child returns before the one in the parent
	bool tid_collision = false;
	bool valid_parent = true;
	bool in_container = false;
	int64_t vtid = tid;
	int64_t vpid = -1;
	uint16_t etype = evt->get_type();

	//
	// Validate the return value and get the child tid
	//
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	childtid = *(int64_t *)parinfo->m_val;

	switch(evt->get_type())
	{
	case PPME_SYSCALL_CLONE_11_X:
		parinfo = evt->get_param(8);
		break;
	case PPME_SYSCALL_CLONE_16_X:
	case PPME_SYSCALL_FORK_X:
	case PPME_SYSCALL_VFORK_X:
		parinfo = evt->get_param(13);
		break;
	case PPME_SYSCALL_CLONE_17_X:
	case PPME_SYSCALL_FORK_17_X:
	case PPME_SYSCALL_VFORK_17_X:
		parinfo = evt->get_param(14);
		break;
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_20_X:
		parinfo = evt->get_param(15);
		break;
	default:
		ASSERT(false);
	}
	ASSERT(parinfo->m_len == sizeof(int32_t));
	uint32_t flags = *(int32_t *)parinfo->m_val;

	if(childtid < 0)
	{
		//
		// clone() failed. Do nothing and keep going.
		//
		return;
	}

	//
	// Get the vtid to check if the clone is within a container
	//
	switch(etype)
	{
	case PPME_SYSCALL_CLONE_11_X:
	case PPME_SYSCALL_CLONE_16_X:
	case PPME_SYSCALL_CLONE_17_X:
	case PPME_SYSCALL_FORK_X:
	case PPME_SYSCALL_FORK_17_X:
	case PPME_SYSCALL_VFORK_X:
	case PPME_SYSCALL_VFORK_17_X:
		break;
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_20_X:
		parinfo = evt->get_param(18);
		ASSERT(parinfo->m_len == sizeof(int64_t));
		vtid = *(int64_t *)parinfo->m_val;

		parinfo = evt->get_param(19);
		ASSERT(parinfo->m_len == sizeof(int64_t));
		vpid = *(int64_t *)parinfo->m_val;
		break;
	default:
		ASSERT(false);
	}

	if(tid != vtid)
	{
		in_container = true;
	}

	if(childtid == 0)
	{
		//
		// clone() returns 0 in the child.
		// Validate that the child thread info has actually been created.
		//
		if(!evt->m_tinfo)
		{
			//
			// No thread yet.
			// This happens if
			//  - clone() returns in the child before than in the parent.
			//  - we dropped the clone exit event in the parent.
			//  - clone was executed in a container
			// In both cases, we create the thread entry here
			//
			// XXX: inverted_clone flag should be useless for containers
			// since just the child's clone is allowed to create a thread
			//
			is_inverted_clone = true;

			//
			// The tid to add is the one that generated this event
			//
			childtid = tid;

			//
			// Check if this is a process or a new thread
			//
			if(flags & PPM_CL_CLONE_THREAD)
			{
				//
				// This is a thread, the parent tid is the pid
				//
				parinfo = evt->get_param(4);
				ASSERT(parinfo->m_len == sizeof(int64_t));
				tid = *(int64_t *)parinfo->m_val;
			}
			else
			{
				//
				// This is not a thread, the parent tid is ptid
				//
				parinfo = evt->get_param(5);
				ASSERT(parinfo->m_len == sizeof(int64_t));
				tid = *(int64_t *)parinfo->m_val;
			}

			//
			// Keep going and add the event with the standard code below
			//
		}
		else
		{
			//
			// We are in the child's clone. If we are in a container, make
			// sure the vtid/vpid are reflected because the father was maybe
			// running outside the container so created the child thread without
			// knowing the internal vtid/vpid
			//
			if(in_container)
			{
				//evt->m_tinfo->m_vtid = vtid;
				//evt->m_tinfo->m_vpid = vpid;
			}

			return;
		}
	}
	else
	{
		//
		// We are in the father. If the father is running in a container,
		// don't create the child process but wait until we see child, because
		// the father just sees the internal tid of the child
		//
		if(in_container)
		{
			return;
		}
	}

	//
	// Lookup the thread that called clone() so we can copy its information
	//
	guardig_threadinfo* ptinfo = m_inspector->get_thread(tid, true, true);
	if(NULL == ptinfo)
	{
		//
		// No clone() caller, we probably missed earlier events.
		// We simply return and ignore the event, which means this thread won't be added to the table.
		//
		ASSERT(false);
		return;
	}

	if(ptinfo->m_comm == "<NA>" && ptinfo->m_uid == 0xffffffff)
	{
		valid_parent = false;
	}

	//
	// See if the child is already there
	//
	guardig_threadinfo* child = m_inspector->get_thread(childtid, false, true);
	if(NULL != child)
	{
		//
		// If this was an inverted clone, all is fine, we've already taken care
		// of adding the thread table entry in the child.
		// Otherwise, we assume that the entry is there because we missed the exit event
		// for a previous thread and we replace the info structure.
		//
		if(child->m_flags & PPM_CL_CLONE_INVERTED)
		{
			return;
		}
		else
		{
			TRACE_DEBUG("tid collision. need to remove_thread!");
			//m_inspector->remove_thread(childtid, true);
			tid_collision = true;
		}
	}

	//
	// Allocate the new thread info and initialize it
	// XXX this should absolutely not do a malloc, but get the item from a
	// preallocated list
	//
	guardig_threadinfo tinfo(m_inspector);

	//
	// Set the tid and parent tid
	//
	tinfo.m_tid = childtid;
	tinfo.m_ptid = tid;

	if(valid_parent)
	{
		// Copy the command name from the parent
		tinfo.m_comm = ptinfo->m_comm;

		// Copy the full executable name from the parent
		tinfo.m_exe = ptinfo->m_exe;

		// Copy the command arguments from the parent
		tinfo.m_args = ptinfo->m_args;

		// Copy the root from the parent
		//tinfo.m_root = ptinfo->m_root;

		// Copy the session id from the parent
		//tinfo.m_sid = ptinfo->m_sid;
	}
	else
	{
		//
		// Parent is an invalid thread, which is strange since it's performing
		// a clone. We try to remove and look it up in proc.
		//
		TRACE_DEBUG("tid collision. need to remove_thread!");
		//m_inspector->remove_thread(tid, true);
		tid_collision = true;

		ptinfo = m_inspector->get_thread(tid,
			true, true);

		if(ptinfo == NULL)
		{
			//
			// This can happen if the thread table has reached max capacity
			//
			ASSERT(false);
			return;
		}

		if(ptinfo->m_comm != "<NA>" && ptinfo->m_uid != 0xffffffff)
		{
			//
			// Parent found in proc, use its data
			//
			tinfo.m_comm = ptinfo->m_comm;
			tinfo.m_exe = ptinfo->m_exe;
			tinfo.m_args = ptinfo->m_args;
			//tinfo.m_root = ptinfo->m_root;
			//tinfo.m_sid = ptinfo->m_sid;
		}
		else
		{
			//
			// Parent not found in proc, use the event data.
			// (The session id will remain unset)
			//
			parinfo = evt->get_param(1);
			tinfo.m_exe = (char*)parinfo->m_val;

			switch(etype)
			{
			case PPME_SYSCALL_CLONE_11_X:
			case PPME_SYSCALL_CLONE_16_X:
			case PPME_SYSCALL_FORK_X:
			case PPME_SYSCALL_VFORK_X:
				tinfo.m_comm = tinfo.m_exe;
				break;
			case PPME_SYSCALL_CLONE_17_X:
			case PPME_SYSCALL_CLONE_20_X:
			case PPME_SYSCALL_FORK_17_X:
			case PPME_SYSCALL_FORK_20_X:
			case PPME_SYSCALL_VFORK_17_X:
			case PPME_SYSCALL_VFORK_20_X:
				parinfo = evt->get_param(13);
				tinfo.m_comm = parinfo->m_val;
				break;
			default:
				ASSERT(false);
			}

			parinfo = evt->get_param(2);
			tinfo.set_args(parinfo->m_val, parinfo->m_len);

			//
			// Also, propagate the same values to the parent
			//
			ptinfo->m_comm = tinfo.m_comm;
			ptinfo->m_exe = tinfo.m_exe;
			ptinfo->set_args(parinfo->m_val, parinfo->m_len);
		}
	}

	// Copy the pid
	parinfo = evt->get_param(4);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	tinfo.m_pid = *(int64_t *)parinfo->m_val;

	// Get the flags, and check if this is a thread or a new thread
	tinfo.m_flags = flags;

	//
	// If clone()'s PPM_CL_CLONE_THREAD is not set it means that a new
	// thread was created. In that case, we set the pid to the one of the CHILD thread that
	// is going to be created.
	//
	if(!(tinfo.m_flags & PPM_CL_CLONE_THREAD))
	{
		tinfo.m_pid = childtid;
	}

	//
	// Copy the fd list
	// XXX this is a gross oversimplification that will need to be fixed.
	// What we do is: if the child is NOT a thread, we copy all the parent fds.
	// The right thing to do is looking at PPM_CL_CLONE_FILES, but there are
	// syscalls like open and pipe2 that can override PPM_CL_CLONE_FILES with the O_CLOEXEC flag
	//
	if(!(tinfo.m_flags & PPM_CL_CLONE_THREAD))
	{
		tinfo.m_fdtable = *(ptinfo->get_fd_table());

		//
		// It's important to reset the cache of the child thread, to prevent it from
		// referring to an element in the parent's table.
		//
		tinfo.m_fdtable.reset_cache();
	}
	//if((tinfo.m_flags & (PPM_CL_CLONE_FILES)))
	//{
	//    tinfo.m_fdtable = ptinfo.m_fdtable;
	//}

	if(is_inverted_clone)
	{
		tinfo.m_flags |= PPM_CL_CLONE_INVERTED;
	}

	// Copy the command name
	parinfo = evt->get_param(1);
	tinfo.m_exe = (char*)parinfo->m_val;

	switch(etype)
	{
	case PPME_SYSCALL_CLONE_11_X:
	case PPME_SYSCALL_CLONE_16_X:
	case PPME_SYSCALL_FORK_X:
	case PPME_SYSCALL_VFORK_X:
		tinfo.m_comm = tinfo.m_exe;
		break;
	case PPME_SYSCALL_CLONE_17_X:
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_17_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_17_X:
	case PPME_SYSCALL_VFORK_20_X:
		parinfo = evt->get_param(13);
		tinfo.m_comm = parinfo->m_val;
		break;
	default:
		ASSERT(false);
	}

	// Get the command arguments
	parinfo = evt->get_param(2);
	tinfo.set_args(parinfo->m_val, parinfo->m_len);

	// Copy the working directory
	//parinfo = evt->get_param(6);
	//tinfo.set_cwd(parinfo->m_val, parinfo->m_len);

	// Copy the fdlimit
	//parinfo = evt->get_param(7);
	//ASSERT(parinfo->m_len == sizeof(int64_t));
	//tinfo.m_fdlimit = *(int64_t *)parinfo->m_val;

	/*
	switch(etype)
	{
	case PPME_SYSCALL_CLONE_11_X:
		break;
	case PPME_SYSCALL_CLONE_16_X:
	case PPME_SYSCALL_CLONE_17_X:
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_X:
	case PPME_SYSCALL_FORK_17_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_X:
	case PPME_SYSCALL_VFORK_17_X:
	case PPME_SYSCALL_VFORK_20_X:
		// Get the pgflt_maj
		parinfo = evt->get_param(8);
		ASSERT(parinfo->m_len == sizeof(uint64_t));
		tinfo.m_pfmajor = *(uint64_t *)parinfo->m_val;

		// Get the pgflt_min
		parinfo = evt->get_param(9);
		ASSERT(parinfo->m_len == sizeof(uint64_t));
		tinfo.m_pfminor = *(uint64_t *)parinfo->m_val;

		// Get the vm_size
		parinfo = evt->get_param(10);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		tinfo.m_vmsize_kb = *(uint32_t *)parinfo->m_val;

		// Get the vm_rss
		parinfo = evt->get_param(11);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		tinfo.m_vmrss_kb = *(uint32_t *)parinfo->m_val;

		// Get the vm_swap
		parinfo = evt->get_param(12);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		tinfo.m_vmswap_kb = *(uint32_t *)parinfo->m_val;
		break;
	default:
		ASSERT(false);
	}
	*/

	// Copy the uid
	switch(etype)
	{
	case PPME_SYSCALL_CLONE_11_X:
		parinfo = evt->get_param(9);
		break;
	case PPME_SYSCALL_CLONE_16_X:
	case PPME_SYSCALL_FORK_X:
	case PPME_SYSCALL_VFORK_X:
		parinfo = evt->get_param(14);
		break;
	case PPME_SYSCALL_CLONE_17_X:
	case PPME_SYSCALL_FORK_17_X:
	case PPME_SYSCALL_VFORK_17_X:
		parinfo = evt->get_param(15);
		break;
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_20_X:
		parinfo = evt->get_param(16);
		break;
	default:
		ASSERT(false);
	}
	ASSERT(parinfo->m_len == sizeof(int32_t));
	tinfo.m_uid = *(int32_t *)parinfo->m_val;

	// Copy the uid
	switch(etype)
	{
	case PPME_SYSCALL_CLONE_11_X:
		parinfo = evt->get_param(10);
		break;
	case PPME_SYSCALL_CLONE_16_X:
	case PPME_SYSCALL_FORK_X:
	case PPME_SYSCALL_VFORK_X:
		parinfo = evt->get_param(15);
		break;
	case PPME_SYSCALL_CLONE_17_X:
	case PPME_SYSCALL_FORK_17_X:
	case PPME_SYSCALL_VFORK_17_X:
		parinfo = evt->get_param(16);
		break;
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_20_X:
		parinfo = evt->get_param(17);
		break;
	default:
		ASSERT(false);
	}
	ASSERT(parinfo->m_len == sizeof(int32_t));
	tinfo.m_gid = *(int32_t *)parinfo->m_val;

	//
	// If we're in a container, vtid and vpid are
	// initialized to the values coming from the event,
	// otherwise they are just set to tid and pid. We can't
	// use the event in that case because in a non-container
	// case also the clone exit from the father can create a
	// child process, and it doesn't have the right vtid and vpid
	// values
	//
	if(in_container)
	{
		//tinfo.m_vtid = vtid;
		//tinfo.m_vpid = vpid;
	}
	else
	{
		//tinfo.m_vtid = tinfo.m_tid;
		//tinfo.m_vpid = tinfo.m_pid;
	}

	//
	// Set cgroups and heuristically detect container id
	//
	/*
	switch(etype)
	{
		case PPME_SYSCALL_FORK_20_X:
		case PPME_SYSCALL_VFORK_20_X:
		case PPME_SYSCALL_CLONE_20_X:
			parinfo = evt->get_param(14);
			tinfo.set_cgroups(parinfo->m_val, parinfo->m_len);
			m_inspector->m_container_manager.resolve_container(&tinfo, m_inspector->m_islive);
			break;
	}
	*/

	//
	// Initilaize the thread clone time
	//
	//tinfo.m_clone_ts = evt->get_ts();

	//
	// Add the new thread to the table
	//
	m_inspector->add_thread(tinfo);

	//
	// If we had to erase a previous entry for this tid and rebalance the table,
	// make sure we reinitialize the tinfo pointer for this event, as the thread
	// generating it might have gone away.
	//
	if(tid_collision)
	{
		reset(evt);
		TRACE_DEBUG("tid collision for %lu (%s)", tinfo.m_tid, tinfo.m_comm.c_str());
#ifdef HAS_ANALYZER
		m_inspector->m_tid_collisions.push_back(tinfo.m_tid);
#endif
#ifdef _DEBUG
		/*
		g_logger.format(guardig_logger::SEV_INFO,
			"tid collision for %" PRIu64 "(%s)",
			tinfo.m_tid, tinfo.m_comm.c_str());
			*/
#endif
	}

	return;
}


//
// Called before starting the parsing.
// Returns false in case of issues resetting the state.
//
bool guardig_parser::reset(guardig_evt *evt)
{
	//
	// Before anything can happen, the event needs to be initialized
	//
	evt->init();

	ppm_event_flags eflags = evt->get_info_flags();
	uint16_t etype = evt->get_type();

	//
	// Ignore scheduler events
	//
	/*
	if(eflags & EF_SKIPPARSERESET)
	{
		if(etype == PPME_PROCINFO_E)
		{
			evt->m_tinfo = m_inspector->get_thread(evt->m_pevt->tid, false, false);
		}
		else
		{
			evt->m_tinfo = NULL;
		}

		return false;
	}
	*/

	//
	// Find the thread info
	//

	//
	// If we're exiting a clone or if we have a scheduler event
	// (many kernel thread), we don't look for /proc
	//
	bool query_os;
	if(etype == PPME_SYSCALL_CLONE_11_X ||
		etype == PPME_SYSCALL_CLONE_16_X ||
		etype == PPME_SYSCALL_CLONE_17_X ||
		etype == PPME_SYSCALL_CLONE_20_X ||
		etype == PPME_SYSCALL_FORK_X ||
		etype == PPME_SYSCALL_FORK_17_X ||
		etype == PPME_SYSCALL_FORK_20_X ||
		etype == PPME_SYSCALL_VFORK_X ||
		etype == PPME_SYSCALL_VFORK_17_X ||
		etype == PPME_SYSCALL_VFORK_20_X ||
		etype == PPME_SCHEDSWITCH_6_E)
	{
		query_os = false;
	}
	else
	{
		query_os = true;
	}

	evt->m_tinfo = m_inspector->get_thread(evt->m_pevt->tid, query_os, false);

	/*
	if(etype == PPME_SCHEDSWITCH_6_E)
	{
		return false;
	}
	*/

	if(!evt->m_tinfo)
	{
		if(etype == PPME_SYSCALL_CLONE_11_X ||
			etype == PPME_SYSCALL_CLONE_16_X ||
			etype == PPME_SYSCALL_CLONE_17_X ||
			etype == PPME_SYSCALL_CLONE_20_X ||
			etype == PPME_SYSCALL_FORK_X ||
			etype == PPME_SYSCALL_FORK_17_X ||
			etype == PPME_SYSCALL_FORK_20_X ||
			etype == PPME_SYSCALL_VFORK_X ||
			etype == PPME_SYSCALL_VFORK_17_X ||
			etype == PPME_SYSCALL_VFORK_20_X)
		{
#ifdef GATHER_INTERNAL_STATS
			m_inspector->m_thread_manager->m_failed_lookups->decrement();
#endif
		}
		else
		{
			TRACE_DEBUG("couldn't find thread: %ld", evt->m_pevt->tid);
			ASSERT(false);
		}

		return false;
	}

	// FIXME: do we actually need this?
	if(query_os)
	{
		evt->m_tinfo->m_flags |= PPM_CL_ACTIVE;
	}

	if(PPME_IS_ENTER(etype))
	{
		evt->m_tinfo->m_lastevent_fd = -1;
		evt->m_tinfo->m_lastevent_type = etype;

		if(eflags & EF_USES_FD)
		{
			guardig_evt_param *parinfo;

			//
			// Get the fd.
			// The fd is always the first parameter of the enter event.
			//
			parinfo = evt->get_param(0);
			ASSERT(parinfo->m_len == sizeof(int64_t));
			ASSERT(evt->get_param_info(0)->type == PT_FD);

			evt->m_tinfo->m_lastevent_fd = *(int64_t *)parinfo->m_val;
			evt->m_fdinfo = evt->m_tinfo->get_fd(evt->m_tinfo->m_lastevent_fd);
		}

		//evt->m_tinfo->m_latency = 0;
		//evt->m_tinfo->m_last_latency_entertime = evt->get_ts();
	}
	else
	{
		guardig_threadinfo* tinfo = evt->m_tinfo;

		//
		// event latency
		//
		/*
		if(tinfo->m_last_latency_entertime != 0)
		{
			tinfo->m_latency = evt->get_ts() - tinfo->m_last_latency_entertime;
			ASSERT((int64_t)tinfo->m_latency >= 0);
		}
		*/

		if(etype == tinfo->m_lastevent_type + 1)
		{
			tinfo->set_lastevent_data_validity(true);
		}
		else
		{
			tinfo->set_lastevent_data_validity(false);

			return false;
			/*
			if(tinfo->m_lastevent_type != PPME_TRACER_E)
			{
				return false;
			}
			*/
		}

		//
		// Error detection logic
		//
		if(evt->m_info->nparams != 0 &&
			((evt->m_info->params[0].name[0] == 'r' && evt->m_info->params[0].name[1] == 'e' && evt->m_info->params[0].name[2] == 's') ||
			(evt->m_info->params[0].name[0] == 'f' && evt->m_info->params[0].name[1] == 'd')))
		{
			guardig_evt_param *parinfo;

			parinfo = evt->get_param(0);
			ASSERT(parinfo->m_len == sizeof(int64_t));
			int64_t res = *(int64_t *)parinfo->m_val;

			if(res < 0)
			{
				evt->m_errorcode = -(int32_t)res;
			}
		}

		//
		// Retrieve the fd
		//
		if(eflags & EF_USES_FD)
		{
			evt->m_fdinfo = tinfo->get_fd(tinfo->m_lastevent_fd);

			if(evt->m_fdinfo == NULL)
			{
				//TRACE_DEBUG("couldn't find fdinfo");
				return false;
			}

			/*
			if(evt->m_errorcode != 0 && m_fd_listener)
			{
				m_fd_listener->on_error(evt);
			}
			*/

			// FIXME: ignore this case for now, maybe we'll relate to it later.

			/*
			if(evt->m_fdinfo->m_flags & sinsp_fdinfo_t::FLAGS_CLOSE_CANCELED)
			{
				//
				// A close gets canceled when the same fd is created succesfully between
				// close enter and close exit.
				// If that happens
				//
				erase_fd_params eparams;

				evt->m_fdinfo->m_flags &= ~sinsp_fdinfo_t::FLAGS_CLOSE_CANCELED;
				eparams.m_fd = CANCELED_FD_NUMBER;
				eparams.m_fdinfo = tinfo->get_fd(CANCELED_FD_NUMBER);

				//
				// Remove the fd from the different tables
				//
				eparams.m_remove_from_table = true;
				eparams.m_inspector = m_inspector;
				eparams.m_tinfo = tinfo;
				eparams.m_ts = evt->get_ts();

				erase_fd(&eparams);
			}
			*/
		}
	}

	return true;
}


void guardig_parser::process_event(guardig *inspector, guardig_evt *pgevent)
{

	// FIXME: this name is not indicative
	reset(pgevent);

	switch(pgevent->m_pevt->type)
	{
	case PPME_SOCKET_SOCKET_E:
		store_event(pgevent);
		break;

	case PPME_SOCKET_SOCKET_X:
		parse_socket_exit(pgevent);
		break;

	case PPME_SOCKET_BIND_X:
		parse_bind_exit(pgevent);
		break;

	case PPME_SOCKET_CONNECT_X:
		parse_connect_exit(pgevent);
		break;

	case PPME_SOCKET_ACCEPT_X:
	case PPME_SOCKET_ACCEPT_5_X:
	case PPME_SOCKET_ACCEPT4_X:
	case PPME_SOCKET_ACCEPT4_5_X:
		parse_accept_exit(pgevent);
		break;

	case PPME_SYSCALL_CLONE_11_X:
	case PPME_SYSCALL_CLONE_16_X:
	case PPME_SYSCALL_CLONE_17_X:
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_X:
	case PPME_SYSCALL_FORK_17_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_X:
	case PPME_SYSCALL_VFORK_17_X:
	case PPME_SYSCALL_VFORK_20_X:
		parse_clone_exit(pgevent);
		break;

	case PPME_SYSCALL_EXECVE_8_X:
	case PPME_SYSCALL_EXECVE_13_X:
	case PPME_SYSCALL_EXECVE_14_X:
	case PPME_SYSCALL_EXECVE_15_X:
	case PPME_SYSCALL_EXECVE_16_X:
		//parse_execve_exit(evt);
		break;

	case PPME_PROCEXIT_E:
	case PPME_PROCEXIT_1_E:
		//parse_thread_exit(evt);
		break;

	default:
		break;
	}

	return;
}
