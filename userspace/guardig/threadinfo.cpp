/*
 * threadinfo.cpp
 *
 *  Created on: Aug 30, 2016
 *      Author: user
 */

#include "guardig.h"
#include "threadinfo.h"
#include "defs.h"


void guardig_threadinfo::add_fd_from_scap(scap_fdinfo *fdi, OUT guardig_fdinfo_t *res)
{
	guardig_fdinfo_t* newfdi = res;
	newfdi->reset();
	bool do_add = true;

	newfdi->m_type = fdi->type;
	newfdi->m_openflags = 0;
	newfdi->m_type = fdi->type;
	newfdi->m_flags = guardig_fdinfo_t::FLAGS_FROM_PROC;
	newfdi->m_ino = fdi->ino;

	switch(newfdi->m_type)
	{
	case SCAP_FD_IPV4_SOCK:
		newfdi->m_sockinfo.m_ipv4info.m_fields.m_sip = fdi->info.ipv4info.sip;
		newfdi->m_sockinfo.m_ipv4info.m_fields.m_dip = fdi->info.ipv4info.dip;
		newfdi->m_sockinfo.m_ipv4info.m_fields.m_sport = fdi->info.ipv4info.sport;
		newfdi->m_sockinfo.m_ipv4info.m_fields.m_dport = fdi->info.ipv4info.dport;
		newfdi->m_sockinfo.m_ipv4info.m_fields.m_l4proto = fdi->info.ipv4info.l4proto;
		// FIXME: do I need to fix ports?
		// If either sip or dip is 0, fix them
		// m_inspector->m_network_interfaces->update_fd(newfdi);
		//newfdi->m_name = ipv4tuple_to_string(&newfdi->m_sockinfo.m_ipv4info, m_inspector->m_hostname_and_port_resolution_enabled);
		break;
	case SCAP_FD_IPV4_SERVSOCK:
		newfdi->m_sockinfo.m_ipv4serverinfo.m_ip = fdi->info.ipv4serverinfo.ip;
		newfdi->m_sockinfo.m_ipv4serverinfo.m_port = fdi->info.ipv4serverinfo.port;
		newfdi->m_sockinfo.m_ipv4serverinfo.m_l4proto = fdi->info.ipv4serverinfo.l4proto;
		//newfdi->m_name = ipv4serveraddr_to_string(&newfdi->m_sockinfo.m_ipv4serverinfo, m_inspector->m_hostname_and_port_resolution_enabled);

		//
		// We keep note of all the host bound server ports.
		// We'll need them later when patching connections direction.
		//
		//m_inspector->m_thread_manager->m_server_ports.insert(newfdi->m_sockinfo.m_ipv4serverinfo.m_port);

		break;
	case SCAP_FD_IPV6_SOCK:
		// Not supported atm
		/*
		if(guardig_utils::is_ipv4_mapped_ipv6((uint8_t*)&fdi->info.ipv6info.sip) &&
			guardig_utils::is_ipv4_mapped_ipv6((uint8_t*)&fdi->info.ipv6info.dip))
		{
			//
			// This is an IPv4-mapped IPv6 addresses (http://en.wikipedia.org/wiki/IPv6#IPv4-mapped_IPv6_addresses).
			// Convert it into the IPv4 representation.
			//
			newfdi->m_type = SCAP_FD_IPV4_SOCK;
			newfdi->m_sockinfo.m_ipv4info.m_fields.m_sip = fdi->info.ipv6info.sip[3];
			newfdi->m_sockinfo.m_ipv4info.m_fields.m_dip = fdi->info.ipv6info.dip[3];
			newfdi->m_sockinfo.m_ipv4info.m_fields.m_sport = fdi->info.ipv6info.sport;
			newfdi->m_sockinfo.m_ipv4info.m_fields.m_dport = fdi->info.ipv6info.dport;
			newfdi->m_sockinfo.m_ipv4info.m_fields.m_l4proto = fdi->info.ipv6info.l4proto;
			m_inspector->m_network_interfaces->update_fd(newfdi);
			newfdi->m_name = ipv4tuple_to_string(&newfdi->m_sockinfo.m_ipv4info, m_inspector->m_hostname_and_port_resolution_enabled);
		}
		else
		{
			copy_ipv6_address(newfdi->m_sockinfo.m_ipv6info.m_fields.m_sip, fdi->info.ipv6info.sip);
			copy_ipv6_address(newfdi->m_sockinfo.m_ipv6info.m_fields.m_dip, fdi->info.ipv6info.dip);
			newfdi->m_sockinfo.m_ipv6info.m_fields.m_sport = fdi->info.ipv6info.sport;
			newfdi->m_sockinfo.m_ipv6info.m_fields.m_dport = fdi->info.ipv6info.dport;
			newfdi->m_sockinfo.m_ipv6info.m_fields.m_l4proto = fdi->info.ipv6info.l4proto;
			newfdi->m_name = ipv6tuple_to_string(&newfdi->m_sockinfo.m_ipv6info, m_inspector->m_hostname_and_port_resolution_enabled);
		}
		*/
		do_add = false;
		break;
	case SCAP_FD_IPV6_SERVSOCK:
		// not supported
		/*
		copy_ipv6_address(newfdi->m_sockinfo.m_ipv6serverinfo.m_ip, fdi->info.ipv6serverinfo.ip);
		newfdi->m_sockinfo.m_ipv6serverinfo.m_port = fdi->info.ipv6serverinfo.port;
		newfdi->m_sockinfo.m_ipv6serverinfo.m_l4proto = fdi->info.ipv6serverinfo.l4proto;
		newfdi->m_name = ipv6serveraddr_to_string(&newfdi->m_sockinfo.m_ipv6serverinfo, m_inspector->m_hostname_and_port_resolution_enabled);

		//
		// We keep note of all the host bound server ports.
		// We'll need them later when patching connections direction.
		//
		m_inspector->m_thread_manager->m_server_ports.insert(newfdi->m_sockinfo.m_ipv6serverinfo.m_port);
		*/
		do_add = false;
		break;
	case SCAP_FD_UNIX_SOCK:
		do_add = false;
		break;
	case SCAP_FD_FIFO:
	case SCAP_FD_FILE:
	case SCAP_FD_DIRECTORY:
	case SCAP_FD_UNSUPPORTED:
	case SCAP_FD_SIGNALFD:
	case SCAP_FD_EVENTPOLL:
	case SCAP_FD_EVENT:
	case SCAP_FD_INOTIFY:
	case SCAP_FD_TIMERFD:
		do_add = false;
		break;
	default:
		ASSERT(false);
		do_add = false;
		break;
	}

	//
	// Call the protocol decoder callbacks associated to notify them about this FD
	//
	/*
	ASSERT(m_inspector != NULL);
	vector<guardig_protodecoder*>::iterator it;

	for(it = m_inspector->m_parser->m_open_callbacks.begin();
		it != m_inspector->m_parser->m_open_callbacks.end(); ++it)
	{
		(*it)->on_fd_from_proc(newfdi);
	}
	*/

	//
	// Add the FD to the table
	//
	if(do_add)
	{
		m_fdtable.add(fdi->fd, newfdi);
	}
}


guardig_fdinfo_t* guardig_threadinfo::add_fd(int64_t fd, guardig_fdinfo_t *fdinfo)
{
	guardig_fdinfo_t *res;
	guardig_fdtable *fdtable = get_fd_table();

	if (fdtable == NULL)
		return NULL;

	res = fdtable->add(fd, fdinfo);

	//
	// Update the last event fd. It's needed by the filtering engine
	//
	//m_lastevent_fd = fd;

	return res;
}


void guardig_threadinfo::set_args(const char* args, size_t len)
{
	m_args.clear();

	size_t offset = 0;
	while(offset < len)
	{
		m_args.push_back(args + offset);
		offset += m_args.back().length() + 1;
	}
}

/*
void guardig_threadinfo::set_cwd(const char* cwd, uint32_t cwdlen)
{
	char tpath[SCAP_MAX_PATH_SIZE];
	sinsp_threadinfo* tinfo = get_cwd_root();

	if(tinfo)
	{
		sinsp_utils::concatenate_paths(tpath,
			SCAP_MAX_PATH_SIZE,
			(char*)tinfo->m_cwd.c_str(),
			(uint32_t)tinfo->m_cwd.size(),
			cwd,
			cwdlen);

		tinfo->m_cwd = tpath;

		if(tinfo->m_cwd[tinfo->m_cwd.size() - 1] != '/')
		{
			tinfo->m_cwd += '/';
		}
	}
	else
	{
		ASSERT(false);
	}
}
*/


void guardig_threadinfo::init()
{
	set_lastevent_data_validity(false);
	m_main_thread = NULL;
	m_lastevent_data = NULL;
	m_lastevent_cpuid = -1;
	m_pid = (uint64_t) - 1LL;
	m_tid = (uint64_t) - 1LL;
	m_ptid = (uint64_t) - 1LL;
	m_lastevent_type = -1;
	m_lastevent_fd = (uint64_t) - 1LL;
	m_flags = PPM_CL_NAME_CHANGED;
	m_uid = -1;
	m_gid = -1;
}


void guardig_threadinfo::init(scap_threadinfo *pi)
{
	scap_fdinfo *fdi;
	scap_fdinfo *tfdi;

	init();

	m_tid = pi->tid;
	m_pid = pi->pid;
	m_ptid = pi->ptid;
	//m_sid = pi->sid;

	m_comm = pi->comm;
	m_exe = pi->exe;
	set_args(pi->args, pi->args_len);
	//set_env(pi->env, pi->env_len);
	//set_cwd(pi->cwd, (uint32_t)strlen(pi->cwd));
	m_flags |= pi->flags;
	m_flags |= PPM_CL_ACTIVE; // Assume that all the threads coming from /proc are real, active threads
	m_fdtable.clear();
	//m_fdlimit = pi->fdlimit;
	m_uid = pi->uid;
	m_gid = pi->gid;
	//m_vmsize_kb = pi->vmsize_kb;
	//m_vmrss_kb = pi->vmrss_kb;
	//m_vmswap_kb = pi->vmswap_kb;
	//m_pfmajor = pi->pfmajor;
	//m_pfminor = pi->pfminor;
	//m_nchilds = 0;
	//m_vtid = pi->vtid;
	//m_vpid = pi->vpid;

	//set_cgroups(pi->cgroups, pi->cgroups_len);
	//m_root = pi->root;
	//ASSERT(m_inspector);
	//m_inspector->m_container_manager.resolve_container(this, m_inspector->m_islive);
	//
	// Prepare for filtering
	//
	guardig_fdinfo_t tfdinfo;
	//guardig_evt tevt;
	//scap_evt tscapevt;

	//
	// Initialize the fake events for filtering
	//
	// FIXME: do we need to send a fake event?
	/*
	tscapevt.ts = 0;
	tscapevt.type = PPME_SYSCALL_READ_X;
	tscapevt.len = 0;

	tevt.m_inspector = m_inspector;
	tevt.m_info = &(g_infotables.m_event_info[PPME_SYSCALL_READ_X]);
	tevt.m_pevt = NULL;
	tevt.m_cpuid = 0;
	tevt.m_evtnum = 0;
	tevt.m_pevt = &tscapevt;
	*/

	// FIXME: I'll probably have to uncomment this code to get existing FDs

	bool match = false;

	HASH_ITER(hh, pi->fdlist, fdi, tfdi)
	{
		add_fd_from_scap(fdi, &tfdinfo);
	}

	// FIXME: isn't this a memory leak?
	//m_lastevent_data = NULL;
}


guardig_threadinfo* guardig_threadinfo::lookup_thread()
{
	return m_inspector->get_thread(m_pid, true, false);
}

