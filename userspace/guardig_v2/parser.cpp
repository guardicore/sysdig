#include <netinet/in.h>
#include <string.h>
#include "defs.h"
#include "parser.h"
#include "trace.h"
#include "connection.h"
#include "process.h"


#define GET_PARAM(evt, num, var, type) 			\
	do {										\
		parinfo = evt->get_param(num);			\
		if (parinfo == NULL || 					\
			parinfo->m_len != sizeof(type)) 	\
		{ 										\
			ASSERT(false); 						\
			goto cleanup; 						\
		} 										\
		var = *(type *)parinfo->m_val;			\
	} while(0)


#define GET_PARAM_BUFFER(evt, num, var, type)	\
	do {										\
		parinfo = evt->get_param(num);			\
		if (parinfo == NULL || 					\
			parinfo->m_len == 0)			 	\
		{ 										\
			ASSERT(false); 						\
			goto cleanup; 						\
		} 										\
		var = (type)parinfo->m_val;				\
	} while(0)


void guardig_parser::parse_accept_exit(guardig_evt *pgevent)
{
	guardig_evt_param *parinfo;
	uint8_t* packed_data;
	connection conn("accept");
	process *procinfo;

	if (!(pgevent->m_pevt->type == PPME_SOCKET_ACCEPT4_5_X ||
		  pgevent->m_pevt->type == PPME_SOCKET_ACCEPT_5_X))
	{
		TRACE_DEBUG("accept variant not supported yet");
		return;
	}

	conn.set_time(pgevent->m_pevt->ts);
	conn.m_errorcode = 0;

	// Extract the fd
	GET_PARAM(pgevent, 0, conn.m_fd, int64_t);
	if(conn.m_fd < 0)
	{
		// Accept failure. Do nothing.
		return;
	}

	// Extract the address
	// This might not work for socket types that we don't support, so we have the assertion
	// to make sure that this is not a type of socket that we support.
	GET_PARAM_BUFFER(pgevent, 1, packed_data, uint8_t*);

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
		conn.m_proto = SOCK_STREAM;
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

	GET_PARAM(pgevent, 6, conn.m_pid, int64_t);
	GET_PARAM_BUFFER(pgevent, 7, conn.m_comm, char*);
	GET_PARAM(pgevent, 8, conn.m_ppid, int64_t);
	GET_PARAM_BUFFER(pgevent, 9, conn.m_pcomm, char*);
	GET_PARAM(pgevent, 10, conn.m_uid, uint32_t);

	//
	// Add the entry to the table
	//
	procinfo = m_inspector->get_process(conn.m_pid, true);
	if (procinfo == NULL)
	{
		//
		// The process is already closed, just print the connection
		// and immediately its shutdown.
		//
		conn.print();
		conn.print_close(conn.m_time);
	}
	else
	{
		if (!procinfo->m_printed_exec)
			procinfo->print();

		procinfo->add_connection(conn);
		conn.print();
	}

cleanup:
	return;
}


void guardig_parser::parse_connect_exit(guardig_evt *pgevent)
{
	guardig_evt_param *parinfo;
	uint8_t *packed_data;
	uint8_t family;
	connection conn("connect");
	process *procinfo;

	conn.set_time(pgevent->m_pevt->ts);

	GET_PARAM(pgevent, 0, conn.m_errorcode, uint64_t);

	if (conn.m_errorcode < 0)
	{
		// connections that return with a SE_EINPROGRESS are totally legit.
		if(conn.m_errorcode != -EINPROGRESS)
		{
			return;
		}
	}

	// This can fail for socket types that we don't support, so we have the assertion
	// to make sure that this is not a type of socket that we support.
	GET_PARAM_BUFFER(pgevent, 1, packed_data, uint8_t*);

	// Validate the family
	family = *packed_data;

	// Fill the fd with the socket info
	if(family == PPM_AF_INET)
	{
		// Update the FD info with this tuple
		conn.m_sip = *(uint32_t *)(packed_data + 1);
		conn.m_sport = *(uint16_t *)(packed_data + 5);
		conn.m_dip = *(uint32_t *)(packed_data + 7);
		conn.m_dport = *(uint16_t *)(packed_data + 11);
		conn.m_type = SCAP_FD_IPV4_SOCK;
	}
	else if (family == PPM_AF_INET6)
	{
		TRACE_DEBUG("ipv6 is not supported yet");
		return;
	}
	else if (family == PPM_AF_UNIX)
	{
		return;
	}
	else
	{
		// This should happen only in case of a bug in our code, because I'm assuming that the OS
		// causes a connect with the wrong socket type to fail.
		// Assert in debug mode and just keep going in release mode.
		ASSERT(false);
		return;
	}

	GET_PARAM(pgevent, 2, conn.m_fd, int64_t);
	GET_PARAM(pgevent, 3, conn.m_proto, uint16_t);
	GET_PARAM(pgevent, 4, conn.m_pid, int64_t);
	GET_PARAM_BUFFER(pgevent, 5, conn.m_comm, char*);
	GET_PARAM(pgevent, 6, conn.m_ppid, int64_t);
	GET_PARAM_BUFFER(pgevent, 7, conn.m_pcomm, char*);
	GET_PARAM(pgevent, 8, conn.m_uid, uint32_t);

	procinfo = m_inspector->get_process(conn.m_pid, true);
	if (procinfo == NULL)
	{
		//
		// The process is already closed, just print the connection
		// and immediately its shutdown.
		//
		conn.print();
		conn.print_close(conn.m_time);
	}
	else
	{
		if (!procinfo->m_printed_exec)
			procinfo->print();

		conn.print();
		procinfo->add_connection(conn);
	}

cleanup:
	return;
}


void guardig_parser::parse_send_exit(guardig_evt *pgevent)
{
	guardig_evt_param *parinfo;
	int64_t fd, res;
	pid_t pid;
	process *proc;
	connection *conn;

	GET_PARAM(pgevent, 0, res, int64_t);
	GET_PARAM(pgevent, 2, fd, int64_t);
	GET_PARAM(pgevent, 3, pid, int64_t);

	proc = m_inspector->get_process(pid, true);
	if (proc == NULL)
	{
		// FIXME: just print the connection
		return;
	}

	conn = proc->get_connection(fd);
	if (conn == NULL)
	{
		// FIXME: add the connection?
		return;
	}

	if (res > 0)
		conn->m_sent_bytes += res;

cleanup:
	return;
}


void guardig_parser::parse_recv_exit(guardig_evt *pgevent)
{
	guardig_evt_param *parinfo;
	int64_t fd, res;
	pid_t pid;
	process *proc;
	connection *conn;

	GET_PARAM(pgevent, 0, res, int64_t);
	if (pgevent->m_pevt->type == PPME_SOCKET_RECVFROM_X)
	{
		GET_PARAM(pgevent, 3, fd, int64_t);
		GET_PARAM(pgevent, 4, pid, int64_t);
	}
	else
	{
		GET_PARAM(pgevent, 2, fd, int64_t);
		GET_PARAM(pgevent, 3, pid, int64_t);
	}

	proc = m_inspector->get_process(pid, true);
	if (proc == NULL)
	{
		// FIXME: just print the connection
		return;
	}

	conn = proc->get_connection(fd);
	if (conn == NULL)
	{
		// FIXME: add the connection?
		return;
	}

	if (res > 0)
		conn->m_recv_bytes += res;

cleanup:
	return;
}


void guardig_parser::parse_clone_exit(guardig_evt *pgevent)
{
	guardig_evt_param *parinfo;
	int64_t childtid, ppid, pid;
	process *parentproc;
	uint16_t etype = pgevent->get_type();
	uint32_t flags;

	if (etype != PPME_SYSCALL_CLONE_20_X &&
			etype != PPME_SYSCALL_FORK_20_X &&
			etype != PPME_SYSCALL_VFORK_20_X)
	{
		//
		// Other versions are not supported at the moment.
		//
		ASSERT(false);
		return;
	}

	GET_PARAM(pgevent, 0, childtid, int64_t);
	GET_PARAM(pgevent, 15, flags, uint32_t);

	if (childtid < 0 || childtid > 0)
	{
		//
		// This is either the father or clone() failed.
		// Do nothing and keep going.
		//
		return;
	}

	if (flags & PPM_CL_CLONE_THREAD)
	{
		//
		// This is a new thread, not a new process. Do nothing and continue.
		//
		return;
	}

	pid = pgevent->m_pevt->tid;
	GET_PARAM(pgevent, 20, ppid, int64_t);

	parentproc = m_inspector->get_process(ppid, true);
	if (parentproc == NULL)
	{
		//
		// FIXME: this case is ignored at the moment.
		// We need to get the information from the event in this case.
		//
		ASSERT(false);
		return;
	}
	else
	{
		process newproc("fork");
		newproc.m_pid = pid;
		newproc.m_ppid = ppid;
		newproc.m_comm = parentproc->m_comm;
		newproc.m_exe = parentproc->m_exe;
		newproc.m_pcomm = parentproc->m_comm; // FIXME: or maybe m_pcomm?
		newproc.m_args = parentproc->m_args;
		newproc.m_cmdline = parentproc->m_cmdline;
		newproc.m_cwd = parentproc->m_cwd;
		newproc.m_conntable = parentproc->m_conntable;

		switch(etype)
		{
			case PPME_SYSCALL_FORK_20_X:
			case PPME_SYSCALL_VFORK_20_X:
			case PPME_SYSCALL_CLONE_20_X:
				// Get EUID
				GET_PARAM(pgevent, 16, newproc.m_uid, uint32_t); // FIXME: should I get euid or uid?
				parinfo = pgevent->get_param(14);
				if (parinfo == NULL)
				{
					ASSERT(false);
					goto cleanup;
				}
				newproc.set_cgroups(parinfo->m_val, parinfo->m_len);
				break;
		}

		m_inspector->add_process(newproc);
	}

cleanup:
	return;
}


void guardig_parser::parse_execve_exit(guardig_evt *pgevent)
{
	guardig_evt_param *parinfo;
	int64_t retval;
	uint16_t etype = pgevent->get_type();
	process proc("execve");

	// Validate the return value
	GET_PARAM(pgevent, 0, retval, int64_t);

	if(retval < 0)
	{
		return;
	}

	// Get the exe
	GET_PARAM_BUFFER(pgevent, 1, proc.m_exe, char*);

	switch(etype)
	{
	case PPME_SYSCALL_EXECVE_8_X:
	case PPME_SYSCALL_EXECVE_13_X:
	case PPME_SYSCALL_EXECVE_14_X:
		// Old trace files didn't have comm, so just set it to exe
		proc.m_comm = proc.m_exe;
		break;
	case PPME_SYSCALL_EXECVE_15_X:
	case PPME_SYSCALL_EXECVE_16_X:
		// Get the comm
		GET_PARAM_BUFFER(pgevent, 13, proc.m_comm, char*);
		break;
	default:
		ASSERT(false);
	}

	// Get the command arguments
	parinfo = pgevent->get_param(2);
	if (parinfo == NULL)
		goto cleanup;

	proc.set_args(parinfo->m_val, parinfo->m_len);

	GET_PARAM(pgevent, 4, proc.m_pid, int64_t);
	GET_PARAM_BUFFER(pgevent, 6, proc.m_cwd, char*);
	//evt->m_tinfo->set_cwd(parinfo->m_val, parinfo->m_len);
	GET_PARAM(pgevent, 16, proc.m_ppid, int64_t);
	GET_PARAM_BUFFER(pgevent, 17, proc.m_pcomm, char*);
	// FIXME: this is the uid, not the effective uid. should I change it?
	GET_PARAM(pgevent, 18, proc.m_uid, uint32_t);

	if (etype == PPME_SYSCALL_EXECVE_16_X)
	{
		parinfo = pgevent->get_param(14);
		if (parinfo == NULL)
			goto cleanup;

		proc.set_cgroups(parinfo->m_val, parinfo->m_len);
	}

	//
	// execve starts with a clean fd list, so we get rid of the fd list that clone
	// copied from the parent
	// XXX validate this
	//
	// scap_fd_free_table(handle, tinfo);

	//
	// Recompute the program hash
	//
	// FIXME: why do we need to hash the program?
	// evt->m_tinfo->compute_program_hash();

	m_inspector->add_process(proc);

cleanup:
	return;
}


void guardig_parser::parse_thread_exit(guardig_evt *pgevent)
{
	process *procinfo = NULL;
	uint64_t tid = pgevent->m_pevt->tid;

	procinfo = m_inspector->get_process(tid, false);
	if (procinfo == NULL)
	{
		// We should get here in 2 cases:
		// 1. this is a thread.
		// 2. we didn't see the creation of the process.
		return;
	}

	if (procinfo->m_had_connection)
	{
		procinfo->print_close();
	}

	// FIXME: maybe I can improve this line (because I'm querying
	// 2 times for the same tid.
	m_inspector->delete_process(tid);
	return;
}


void guardig_parser::parse_close_enter(guardig_evt *pgevent)
{
	guardig_evt_param *parinfo;
	int64_t fd, pid;
	process *proc;
	connection *conn;

	GET_PARAM(pgevent, 0, fd, int64_t);
	GET_PARAM(pgevent, 1, pid, int64_t);

	proc = m_inspector->get_process(pid, false);
	if (proc == NULL)
	{
		//TRACE_DEBUG("couldn't find process");
		return;
	}

	conn = proc->get_connection(fd);
	if (conn == NULL)
	{
		//TRACE_DEBUG("couldn't find connection");
		return;
	}

	conn->m_flags |= connection::FLAGS_CLOSE_IN_PROGRESS;

cleanup:
	return;
}


void guardig_parser::parse_close_exit(guardig_evt *pgevent)
{
	guardig_evt_param *parinfo;
	int64_t retval;
	int64_t fd, pid;
	process *proc;
	connection *conn;

	GET_PARAM(pgevent, 2, fd, int64_t);
	GET_PARAM(pgevent, 1, pid, int64_t);
	GET_PARAM(pgevent, 0, retval, int64_t);

	proc = m_inspector->get_process(pid, false);
	if (proc == NULL)
	{
		//TRACE_DEBUG("couldn't find process");
		return;
	}

	conn = proc->get_connection(fd);
	if (conn == NULL)
	{
		//TRACE_DEBUG("couldn't find connection");
		return;
	}

	if (conn->m_flags & connection::FLAGS_CLOSE_CANCELED)
	{
		TRACE_DEBUG("*** canceled close exit ***");
		conn->m_flags &= ~connection::FLAGS_CLOSE_CANCELED;
		return;
	}

	if (retval == 0)
	{
		conn->print_volume();
		conn->print_close(pgevent->m_pevt->ts);
		proc->delete_connection(conn->m_fd);
	}
	else
	{
		TRACE_DEBUG("close returned with: %ld", retval);
	}

cleanup:
	return;
}


void guardig_parser::process_event(guardig *inspector, guardig_evt *pgevent)
{
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
		parse_clone_exit(pgevent);
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

	case PPME_SYSCALL_PWRITE_X:
	case PPME_SYSCALL_WRITE_X:
	case PPME_SOCKET_SEND_X:
	case PPME_SOCKET_SENDTO_X:
		parse_send_exit(pgevent);
		break;

	case PPME_SYSCALL_PREAD_X:
	case PPME_SYSCALL_READ_X:
	case PPME_SOCKET_RECV_X:
	case PPME_SOCKET_RECVFROM_X:
		parse_recv_exit(pgevent);
		break;

	default:
		break;
	}

	return;
}
