#include <netinet/in.h>
#include <string.h>
#include "defs.h"
#include "parser.h"
#include "trace.h"
#include "connection.h"
#include "process.h"


void guardig_parser::parse_accept_exit(guardig_evt *pgevent)
{
	guardig_evt_param *parinfo;
	uint8_t* packed_data;
	connection conn("accept");

	if (!(pgevent->m_pevt->type == PPME_SOCKET_ACCEPT4_5_X ||
		  pgevent->m_pevt->type == PPME_SOCKET_ACCEPT_5_X))
	{
		TRACE_DEBUG("accept variant not supported yet");
		return;
	}

	conn.m_time = pgevent->m_pevt->ts;
	conn.m_errorcode = 0;

	//
	// Extract the fd
	//
	parinfo = pgevent->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	conn.m_fd = *(int64_t *)parinfo->m_val;

	if(conn.m_fd < 0)
	{
		//
		// Accept failure.
		// Do nothing.
		//
		return;
	}

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
		conn.m_sip = *(uint32_t *)(packed_data + 1);
		conn.m_sport = *(uint16_t *)(packed_data + 5);
		conn.m_dip = *(uint32_t *)(packed_data + 7);
		conn.m_dport = *(uint16_t *)(packed_data + 11);
		conn.m_type = SCAP_FD_IPV4_SOCK;
		conn.m_proto = SCAP_L4_TCP;
	}
	else if(*packed_data == PPM_AF_INET6)
	{
		TRACE_DEBUG("IPv6 is not supported yet");
		return;
	}
	else if(*packed_data == PPM_AF_UNIX)
	{
		TRACE_DEBUG("unix socket is ignored");
		return;
	}
	else
	{
		TRACE_DEBUG("unsupported family: %d", *packed_data);
		return;
	}

	parinfo = pgevent->get_param(6);
	//ASSERT(parinfo->m_len == sizeof(pid_t));
	conn.m_pid = *(pid_t *)parinfo->m_val;

	parinfo = pgevent->get_param(7);
	ASSERT(parinfo->m_len != 0);
	conn.m_proc_name = parinfo->m_val;

	parinfo = pgevent->get_param(8);
	//ASSERT(parinfo->m_len == sizeof(pid_t));
	conn.m_ppid = *(pid_t *)parinfo->m_val;

	parinfo = pgevent->get_param(9);
	ASSERT(parinfo->m_len != 0);
	conn.m_pproc_name = parinfo->m_val;

	parinfo = pgevent->get_param(10);
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	conn.m_uid = *(uint32_t *)parinfo->m_val;

	//
	// Add the entry to the table
	//
	// FIXME: add the entry to the process table

	process *procinfo = m_inspector->get_process(conn.m_pid);
	// FIXME: add a dummy proc if we missed the process creation.
	if (procinfo == NULL)
		return;

	if (!procinfo->m_printed_exec)
		procinfo->print();

	procinfo->add_connection(conn);
	conn.print();
}


void guardig_parser::parse_connect_exit(guardig_evt *pgevent)
{
	guardig_evt_param *parinfo;
	uint8_t *packed_data;
	uint8_t family;
	connection conn("connect");

	conn.m_time = pgevent->m_pevt->ts;

	parinfo = pgevent->get_param(0);
	ASSERT(parinfo->m_len == sizeof(uint64_t));
	conn.m_errorcode = *(int64_t*)parinfo->m_val;

	if (conn.m_errorcode < 0)
	{
		//
		// connections that return with a SE_EINPROGRESS are totally legit.
		//
		if(conn.m_errorcode != -EINPROGRESS)
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
		return;
	}

	packed_data = (uint8_t*)parinfo->m_val;

	//
	// Validate the family
	//
	family = *packed_data;

	//
	// Fill the fd with the socket info
	//
	if(family == PPM_AF_INET || family == PPM_AF_INET6)
	{
		if(family == PPM_AF_INET6)
		{
			TRACE_DEBUG("IPv6 is not supported yet");
			return;
		}

		//
		// Update the FD info with this tuple
		//
		if(family == PPM_AF_INET)
		{
			conn.m_sip = *(uint32_t *)(packed_data + 1);
			conn.m_sport = *(uint16_t *)(packed_data + 5);
			conn.m_dip = *(uint32_t *)(packed_data + 7);
			conn.m_dport = *(uint16_t *)(packed_data + 11);
			conn.m_type = SCAP_FD_IPV4_SOCK;
		}
	}
	else
	{
		if(family != PPM_AF_UNIX)
		{
			//
			// This should happen only in case of a bug in our code, because I'm assuming that the OS
			// causes a connect with the wrong socket type to fail.
			// Assert in debug mode and just keep going in release mode.
			//
			ASSERT(false);
		}

		return;
	}

	parinfo = pgevent->get_param(2);
	ASSERT(parinfo->m_len == sizeof(uint64_t));
	conn.m_fd = *(uint64_t *)parinfo->m_val;

	parinfo = pgevent->get_param(3);
	ASSERT(parinfo->m_len == sizeof(uint8_t));
	conn.m_proto = (scap_l4_proto)(*(uint8_t *)parinfo->m_val);

	parinfo = pgevent->get_param(4);
	//ASSERT(parinfo->m_len == sizeof(pid_t));
	conn.m_pid = *(pid_t *)parinfo->m_val;

	parinfo = pgevent->get_param(5);
	ASSERT(parinfo->m_len != 0);
	conn.m_proc_name = parinfo->m_val;

	parinfo = pgevent->get_param(6);
	//ASSERT(parinfo->m_len == sizeof(pid_t));
	conn.m_ppid = *(pid_t *)parinfo->m_val;

	parinfo = pgevent->get_param(7);
	ASSERT(parinfo->m_len != 0);
	conn.m_pproc_name = parinfo->m_val;

	parinfo = pgevent->get_param(8);
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	conn.m_uid = *(uint32_t *)parinfo->m_val;

	process *procinfo = m_inspector->get_process(conn.m_pid);
	// FIXME: add a dummy proc if we missed the process creation.
	// or maybe query the os with scap
	if (procinfo == NULL)
		return;

	if (!procinfo->m_printed_exec)
		procinfo->print();

	procinfo->add_connection(conn);
	conn.print();
}


/*
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

/*
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
/*
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
/*
#endif
	}

	return;
}
*/



void guardig_parser::parse_execve_exit(guardig_evt *pgevent)
{
	guardig_evt_param *parinfo;
	int64_t retval;
	uint16_t etype = pgevent->get_type();
	process proc("execve");

	// Validate the return value
	parinfo = pgevent->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	retval = *(int64_t *)parinfo->m_val;

	if(retval < 0)
	{
		return;
	}

	// Get the exe
	parinfo = pgevent->get_param(1);
	ASSERT(parinfo->m_len != 0);
	proc.m_proc_name = parinfo->m_val;

	switch(etype)
	{
	case PPME_SYSCALL_EXECVE_8_X:
	case PPME_SYSCALL_EXECVE_13_X:
	case PPME_SYSCALL_EXECVE_14_X:
		// Old trace files didn't have comm, so just set it to exe
		proc.m_comm = proc.m_proc_name;
		break;
	case PPME_SYSCALL_EXECVE_15_X:
	case PPME_SYSCALL_EXECVE_16_X:
		// Get the comm
		parinfo = pgevent->get_param(13);
		ASSERT(parinfo->m_len != 0);
		proc.m_comm = parinfo->m_val;
		break;
	default:
		ASSERT(false);
	}

	// Get the command argumentsset_cwd
	// FIXME: do we need the command arguments?
	parinfo = pgevent->get_param(2);
	ASSERT(parinfo->m_len != 0);
	proc.m_cmdline = proc.m_comm + " ";
	//evt->m_tinfo->set_args(parinfo->m_val, parinfo->m_len);
	size_t offset = 0;
	string tmp;
	while(offset < parinfo->m_len)
	{
		tmp = parinfo->m_val + offset;
		offset += tmp.length() + 1;
		proc.m_cmdline += tmp + " ";
	}

	if (proc.m_cmdline.size() > 0)
		proc.m_cmdline.pop_back(); // remove the last space

	// Get the pid
	parinfo = pgevent->get_param(4);
	ASSERT(parinfo->m_len == sizeof(uint64_t));
	proc.m_pid = *(uint64_t *)parinfo->m_val;

	// Get the working directory
	parinfo = pgevent->get_param(6);
	ASSERT(parinfo->m_len != 0);
	proc.m_cwd = parinfo->m_val;
	//evt->m_tinfo->set_cwd(parinfo->m_val, parinfo->m_len);

	switch(etype)
	{
	case PPME_SYSCALL_EXECVE_16_X:
		//
		// Set cgroups and heuristically detect container id
		//
		//parinfo = evt->get_param(14);
		//evt->m_tinfo->set_cgroups(parinfo->m_val, parinfo->m_len);
		//if(evt->m_tinfo->m_container_id.empty())
		//{
		//	m_inspector->m_container_manager.resolve_container(evt->m_tinfo, m_inspector->m_islive);
		//}
		break;
	default:
		break;
	}


	parinfo = pgevent->get_param(16);
	//ASSERT(parinfo->m_len == sizeof(pid_t));
	proc.m_ppid = *(pid_t *)parinfo->m_val;

	parinfo = pgevent->get_param(17);
	ASSERT(parinfo->m_len != 0);
	proc.m_pproc_name = parinfo->m_val;

	parinfo = pgevent->get_param(18);
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	proc.m_uid = *(uint32_t *)parinfo->m_val;

	//
	// execve starts with a clean fd list, so we get rid of the fd list that clone
	// copied from the parent
	// XXX validate this
	//
	//  scap_fd_free_table(handle, tinfo);

	//
	// Recompute the program hash
	//
	// FIXME: why do we need to hash the program?
	//evt->m_tinfo->compute_program_hash();

	m_inspector->add_process(proc);
	return;
}


void guardig_parser::parse_thread_exit(guardig_evt *pgevent)
{
	process *procinfo = NULL;
	uint64_t tid = pgevent->m_pevt->tid;

	procinfo = m_inspector->get_process(tid);
	if (procinfo == NULL)
	{
		// We should get here in 2 cases:
		// 1. this is a thread.
		// 2. we didn't see the creation of the process.
		return;
	}

	if (procinfo->m_had_connection)
	{
		procinfo->m_evt_name = "procexit";
		procinfo->print();
	}

	// FIXME: maybe I can improve this line (because I'm querying
	// 2 times for the same tid.
	m_inspector->delete_process(tid);
	return;
}


void guardig_parser::parse_close_enter(guardig_evt *pgevent)
{
	guardig_evt_param *parinfo;
	int64_t fd;
	pid_t pid;

	parinfo = pgevent->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd = *(int64_t *)parinfo->m_val;

	parinfo = pgevent->get_param(1);
	//ASSERT(parinfo->m_len == sizeof(pid_t));
	pid = *(pid_t *)parinfo->m_val;

	process *proc = m_inspector->get_process(pid);
	if (proc == NULL)
	{
		//TRACE_DEBUG("couldn't find process");
		return;
	}

	connection *conn = proc->get_connection(fd);
	if (conn == NULL)
	{
		//TRACE_DEBUG("couldn't find connection");
		return;
	}

	conn->m_flags |= connection::FLAGS_CLOSE_IN_PROGRESS;
}


void guardig_parser::parse_close_exit(guardig_evt *pgevent)
{
	guardig_evt_param *parinfo;
	int64_t retval;
	int64_t fd;
	pid_t pid;

	parinfo = pgevent->get_param(2);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd = *(int64_t *)parinfo->m_val;

	parinfo = pgevent->get_param(1);
	//ASSERT(parinfo->m_len == sizeof(pid_t));
	pid = *(pid_t *)parinfo->m_val;

	process *proc = m_inspector->get_process(pid);
	if (proc == NULL)
	{
		//TRACE_DEBUG("couldn't find process");
		return;
	}

	connection *conn = proc->get_connection(fd);
	if (conn == NULL)
	{
		//TRACE_DEBUG("couldn't find connection");
		return;
	}

	parinfo = pgevent->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	// FIXME: this assert should at least exit the function
	// in production mode.
	retval = *(int64_t *)parinfo->m_val;

	if (conn->m_flags & connection::FLAGS_CLOSE_CANCELED)
	{
		TRACE_DEBUG("*** canceled close exit ***");
		conn->m_flags &= ~connection::FLAGS_CLOSE_CANCELED;
		return;
	}

	if (retval == 0)
	{
		conn->m_evt_name = "close";
		conn->print();
		proc->delete_connection(conn->m_fd);
	}
	else
	{
		TRACE_DEBUG("close returned with: %ld", retval);
	}
}


void guardig_parser::process_event(guardig *inspector, guardig_evt *pgevent)
{

	// FIXME: this name is not indicative
	//bool retval = reset(pgevent);
	//if (retval == false)
	//	return;
	pgevent->init();

	switch(pgevent->m_pevt->type)
	{
	case PPME_SOCKET_SOCKET_E:
		//store_event(pgevent);
		break;

	case PPME_SOCKET_SOCKET_X:
		//parse_socket_exit(pgevent);
		break;

	case PPME_SOCKET_BIND_X:
		//parse_bind_exit(pgevent);
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
		//parse_clone_exit(pgevent);
		break;

	case PPME_SYSCALL_EXECVE_8_X:
	case PPME_SYSCALL_EXECVE_13_X:
	case PPME_SYSCALL_EXECVE_14_X:
	case PPME_SYSCALL_EXECVE_15_X:
	case PPME_SYSCALL_EXECVE_16_X:
		parse_execve_exit(pgevent);
		break;

	case PPME_PROCEXIT_E:
	case PPME_PROCEXIT_1_E:
		parse_thread_exit(pgevent);
		break;

	case PPME_SYSCALL_CLOSE_E:
		parse_close_enter(pgevent);
		break;

	case PPME_SYSCALL_CLOSE_X:
		parse_close_exit(pgevent);
		break;

	default:
		break;
	}

	return;
}
