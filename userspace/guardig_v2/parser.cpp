#include <netinet/in.h>
#include <string.h>
#include "defs.h"
#include "parser.h"
#include "trace.h"
#include "connection.h"
#include "process.h"
#include "utils.h"

extern stats g_stats;

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


bool parse_packed_tuple(unsigned char *packed_data, ipv4tuple *conntuple)
{
	// Validate the family
	uint8_t family = *packed_data;

	// Fill the fd with the socket info
	if(family == PPM_AF_INET)
	{
		conntuple->m_sip = *(uint32_t *)(packed_data + 1);
		conntuple->m_sport = *(uint16_t *)(packed_data + 5);
		conntuple->m_dip = *(uint32_t *)(packed_data + 7);
		conntuple->m_dport = *(uint16_t *)(packed_data + 11);
	}
	else if (family == PPM_AF_INET6)
	{
		uint8_t* sip = packed_data + 1;
		uint8_t* dip = packed_data + 19;

		if(guardig_utils::is_ipv4_mapped_ipv6(sip) && guardig_utils::is_ipv4_mapped_ipv6(dip))
		{
			conntuple->m_sip = *(uint32_t *)(packed_data + 13);
			conntuple->m_sport = *(uint16_t *)(packed_data + 17);
			conntuple->m_dip = *(uint32_t *)(packed_data + 31);
			conntuple->m_dport = *(uint16_t *)(packed_data + 35);
		}
		else
		{
			//TRACE_DEBUG("ipv6 is not supported yet");
			return false;
		}
	}
	else if (family == PPM_AF_UNIX)
	{
		return false;
	}
	else
	{
		// This should happen only in case of a bug in our code, because I'm assuming that the OS
		// causes a connect with the wrong socket type to fail.
		// Assert in debug mode and just keep going in release mode.
		ASSERT(false);
		return false;
	}

	return true;
}


connection *guardig_parser::add_connection_from_event(process *procinfo, guardig_evt *pgevent)
{
	guardig_evt_param *parinfo;
	uint8_t* packed_data;
	int64_t fd, res;
	uint16_t proto;
	filedescriptor *fdinfo;
	connection newconn;
	connection *conninfo;

	switch (pgevent->m_pevt->type)
	{
	case PPME_SOCKET_ACCEPT4_5_X:
	case PPME_SOCKET_ACCEPT_5_X:
		newconn.m_evt_name = "accept";
		GET_PARAM(pgevent, 0, fd, int64_t);
		GET_PARAM(pgevent, 5, proto, uint16_t);
		GET_PARAM_BUFFER(pgevent, 1, packed_data, uint8_t*);
		res = fd;
		break;
	case PPME_SOCKET_CONNECT_X:
		newconn.m_evt_name = "connect";
		GET_PARAM(pgevent, 2, fd, int64_t);
		GET_PARAM(pgevent, 3, proto, uint16_t);
		GET_PARAM_BUFFER(pgevent, 1, packed_data, uint8_t*);
		GET_PARAM(pgevent, 0, res, uint64_t);
		break;
	case PPME_SOCKET_RECVFROM_X:
		newconn.m_evt_name = "recvfrom";
		GET_PARAM(pgevent, 3, fd, int64_t);
		GET_PARAM(pgevent, 5, proto, uint16_t);
		GET_PARAM_BUFFER(pgevent, 2, packed_data, uint8_t*);
		GET_PARAM(pgevent, 0, res, int64_t);
		break;
	case PPME_SOCKET_SENDTO_X:
		newconn.m_evt_name = "sendto";
		GET_PARAM(pgevent, 3, fd, int64_t);
		GET_PARAM(pgevent, 5, proto, uint16_t);
		GET_PARAM_BUFFER(pgevent, 2, packed_data, uint8_t*);
		GET_PARAM(pgevent, 0, res, int64_t);
		break;
	default:
		ASSERT(false);
		break;
	}

	{
	filedescriptor newfd(proto);
	newfd.m_fd = fd;
	newfd.m_type = SCAP_FD_IPV4_SOCK;
	newfd.m_proto = proto;
	newfd.m_procinfo = procinfo;

	if (!parse_packed_tuple(packed_data, &newconn.m_conntuple))
		return NULL;

	//
	// Update addresses if one of then was empty
	//
	m_inspector->m_network_interfaces.update_tuple(&newconn.m_conntuple);

	fdinfo = procinfo->get_fd(fd);

	if (fdinfo == NULL ||
			fdinfo->m_proto == SOCK_STREAM ||
			fdinfo->m_proto != newfd.m_proto)
	{
		if (fdinfo != NULL)
		{
			//
			// There's an existing FD that wasn't closed (we probably missed the close
			// event). Print its connections and replace it by the new FD.
			//
			fdinfo->close_all_connections(pgevent->m_pevt->ts);
		}

		fdinfo = procinfo->add_fd(newfd);
	}

	if (fdinfo == NULL)
	{
		TRACE_DEBUG("fd table is full");
		return NULL;
	}

	newconn.set_time(pgevent->m_pevt->ts);
	newconn.m_errorcode = res;
	newconn.m_fdinfo = fdinfo;

	conninfo = fdinfo->add_connection(newconn);

#ifdef PRINT_REPORTS
	if (! ( (pgevent->m_pevt->type == PPME_SOCKET_CONNECT_X && res == -EINPROGRESS) ||
		    (pgevent->m_pevt->type == PPME_SOCKET_CONNECT_X && proto == SOCK_DGRAM) ) )
	{
		if (!procinfo->m_printed_exec)
			procinfo->print();

		conninfo->print();
	}
#endif

	return conninfo;
	}

cleanup:
	return NULL;
}


void guardig_parser::parse_accept_exit(guardig_evt *pgevent)
{
	guardig_evt_param *parinfo;
	process *procinfo;
	int64_t pid, fd;

	if (!(pgevent->m_pevt->type == PPME_SOCKET_ACCEPT4_5_X ||
		  pgevent->m_pevt->type == PPME_SOCKET_ACCEPT_5_X))
	{
		TRACE_DEBUG("accept variant not supported yet");
		return;
	}

	// Extract the pid
	GET_PARAM(pgevent, 6, pid, int64_t);

	// Extract the fd
	GET_PARAM(pgevent, 0, fd, int64_t);
	if(fd < 0)
	{
		// Accept failure. Do nothing.
		return;
	}

	procinfo = m_inspector->get_process(pid, true);
	if (procinfo == NULL)
	{
		TRACE_DEBUG("process table is full");
		return;
	}

	if (procinfo->m_uid == -1)
	{
		//
		// We didn't see the process creation and didn't find it in /proc as well.
		// Fill in the process details from the current event.
		//
		GET_PARAM_BUFFER(pgevent, 7, procinfo->m_comm, char*);
		GET_PARAM(pgevent, 8, procinfo->m_ppid, int64_t);
		GET_PARAM_BUFFER(pgevent, 9, procinfo->m_pcomm, char*);
		GET_PARAM(pgevent, 10, procinfo->m_uid, uint32_t);
	}

	add_connection_from_event(procinfo, pgevent);

cleanup:
	return;
}


void guardig_parser::parse_connect_exit(guardig_evt *pgevent)
{
	guardig_evt_param *parinfo;
	process *procinfo;
	int64_t pid, res;

	GET_PARAM(pgevent, 0, res, uint64_t);

	if (res < 0)
	{
		// connections that return with a SE_EINPROGRESS are totally legit.
		if(res != -EINPROGRESS)
		{
			return;
		}
	}

	GET_PARAM(pgevent, 4, pid, int64_t);

	procinfo = m_inspector->get_process(pid, true);
	if (procinfo == NULL)
	{
		//
		// The process table is full
		//
		TRACE_DEBUG("process table is full");
		return;
	}

	if (procinfo->m_uid == -1)
	{
		//
		// We didn't see the process creation and didn't find it in /proc as well.
		// Fill in the process details from the current event.
		//
		GET_PARAM_BUFFER(pgevent, 5, procinfo->m_comm, char*);
		GET_PARAM(pgevent, 6, procinfo->m_ppid, int64_t);
		GET_PARAM_BUFFER(pgevent, 7, procinfo->m_pcomm, char*);
		GET_PARAM(pgevent, 8, procinfo->m_uid, uint32_t);
	}

	add_connection_from_event(procinfo, pgevent);

cleanup:
	return;
}


void guardig_parser::parse_send_exit(guardig_evt *pgevent)
{
	guardig_evt_param *parinfo;
	int64_t fd, res;
	pid_t pid;
	process *procinfo;
	filedescriptor *fdinfo;
	connection *conninfo;
	uint8_t* packed_data;
	ipv4tuple conntuple, inverse_tuple;
	uint8_t is_connected = 1;

	GET_PARAM(pgevent, 0, res, int64_t);

	if (res < 0)
	{
		//
		// We don't care about failed send events. Just continue.
		//
		return;
	}

	GET_PARAM_BUFFER(pgevent, 2, packed_data, uint8_t*);
	GET_PARAM(pgevent, 3, fd, int64_t);
	GET_PARAM(pgevent, 4, pid, int64_t);

	if (pgevent->m_pevt->type == PPME_SOCKET_SENDTO_X)
	{
		GET_PARAM(pgevent, 10, is_connected, uint8_t);
	}

	procinfo = m_inspector->get_process(pid, true);
	if (procinfo == NULL)
	{
		TRACE_DEBUG("process table is full");
		return;
	}

	if (pgevent->m_pevt->type == PPME_SOCKET_SENDTO_X &&
		procinfo->m_uid == -1)
	{
		//
		// We didn't see the process creation and didn't find it in /proc as well.
		// Fill in the process details from the current event.
		// Note: ATM I'm only supporting recv_from, because in other events I should've
		// seen the connection before with connect / accept.
		//
		GET_PARAM_BUFFER(pgevent, 6, procinfo->m_comm, char*);
		GET_PARAM(pgevent, 7, procinfo->m_ppid, int64_t);
		GET_PARAM_BUFFER(pgevent, 8, procinfo->m_pcomm, char*);
		GET_PARAM(pgevent, 9, procinfo->m_uid, uint32_t);
	}

	if (!parse_packed_tuple(packed_data, &conntuple))
		return;

	//
	// Update addresses if one of then was empty
	//
	m_inspector->m_network_interfaces.update_tuple(&conntuple);
	conntuple.get_inverse_tuple(inverse_tuple);

	fdinfo = procinfo->get_fd(fd);
	if (fdinfo == NULL)
	{
		goto add_connection;
	}

	conninfo = fdinfo->get_connection(conntuple);
	if (conninfo == NULL)
		conninfo = fdinfo->get_connection(inverse_tuple);

	if (conninfo == NULL)
	{
		goto add_connection;
	}

#ifdef PRINT_REPORTS
	//
	// Check if delayed print is necessary
	//
	if (!conninfo->m_printed_creation)
	{
		if (!procinfo->m_printed_exec)
			procinfo->print();

		if (conninfo->m_errorcode == -EINPROGRESS)
			conninfo->m_errorcode = 0;

		conninfo->print();
	}
#endif

	conninfo->m_sent_bytes += res;
	return;

add_connection:
	if (!is_connected)
	{
		conninfo = add_connection_from_event(procinfo, pgevent);
		if (conninfo != NULL)
			conninfo->m_sent_bytes += res;
	}

cleanup:
	return;
}


void guardig_parser::parse_recv_exit(guardig_evt *pgevent)
{
	guardig_evt_param *parinfo;
	int64_t fd, res;
	int64_t pid;
	process *procinfo;
	filedescriptor *fdinfo;
	connection *conninfo;
	uint8_t* packed_data;
	ipv4tuple conntuple, inverse_tuple;
	uint8_t is_connected = 1;

	GET_PARAM(pgevent, 0, res, int64_t);

	if (res < 0)
	{
		//
		// We don't care about failed recv events. Just continue.
		//
		return;
	}

	GET_PARAM_BUFFER(pgevent, 2, packed_data, uint8_t*);
	GET_PARAM(pgevent, 3, fd, int64_t);
	GET_PARAM(pgevent, 4, pid, int64_t);

	if (pgevent->m_pevt->type == PPME_SOCKET_RECVFROM_X)
	{
		GET_PARAM(pgevent, 10, is_connected, uint8_t);
	}

	procinfo = m_inspector->get_process(pid, true);
	if (procinfo == NULL)
	{
		TRACE_DEBUG("process table is full");
		return;
	}

	if (pgevent->m_pevt->type == PPME_SOCKET_RECVFROM_X &&
		procinfo->m_uid == -1)
	{
		//
		// We didn't see the process creation and didn't find it in /proc as well.
		// Fill in the process details from the current event.
		// Note: ATM I'm only supporting recv_from, because in other events I should've
		// seen the connection before with connect / accept.
		//
		GET_PARAM_BUFFER(pgevent, 6, procinfo->m_comm, char*);
		GET_PARAM(pgevent, 7, procinfo->m_ppid, int64_t);
		GET_PARAM_BUFFER(pgevent, 8, procinfo->m_pcomm, char*);
		GET_PARAM(pgevent, 9, procinfo->m_uid, uint32_t);
	}

	if (!parse_packed_tuple(packed_data, &conntuple))
		return;

	//
	// Update addresses if one of then was empty
	//
	m_inspector->m_network_interfaces.update_tuple(&conntuple);
	conntuple.get_inverse_tuple(inverse_tuple);

	fdinfo = procinfo->get_fd(fd);
	if (fdinfo == NULL)
	{
		goto add_connection;
	}

	conninfo = fdinfo->get_connection(conntuple);
	if (conninfo == NULL)
		conninfo = fdinfo->get_connection(inverse_tuple);

	if (conninfo == NULL)
	{
		goto add_connection;
	}

#ifdef PRINT_REPORTS
	//
	// Check if delayed print is necessary
	//
	if (!conninfo->m_printed_creation)
	{
		if (!procinfo->m_printed_exec)
			procinfo->print();

		if (conninfo->m_errorcode == -EINPROGRESS)
			conninfo->m_errorcode = 0;

		conninfo->print();
	}
#endif

	conninfo->m_recv_bytes += res;
	return;

add_connection:
	if (!is_connected)
	{
		conninfo = add_connection_from_event(procinfo, pgevent);
		if (conninfo != NULL)
			conninfo->m_recv_bytes += res;
	}

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
		newproc.m_fdtable = parentproc->m_fdtable;

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

	for ( auto fdit = procinfo->m_fdtable.begin(); fdit != procinfo->m_fdtable.end(); ++fdit )
	{
		filedescriptor *fdinfo = &(fdit->second);
		fdinfo->close_all_connections(pgevent->m_pevt->ts);
	}

	if (procinfo->m_had_connection)
	{
#ifdef PRINT_REPORTS
		procinfo->print_close();
#endif
	}

	// FIXME: maybe I can improve this line (because I'm querying
	// 2 times for the same tid.
	m_inspector->delete_process(tid);
	return;
}


/*
 * Note: We parse only close_enter and not close_exit because then we are guaranteed
 * to be called before a new fd with the same number is created.
 * Otherwise there could be a race:
 * 		- close_enter
 * 		- socket_enter
 * 		- socket_exit
 * 		- close_exit
 * We assume that if the call to sockfd_lookup in the kernel succeeds then the fd is valid
 * and the close will be successful.
 */
void guardig_parser::parse_close_enter(guardig_evt *pgevent)
{
	guardig_evt_param *parinfo;
	int64_t retval;
	int64_t fd, pid;
	process *procinfo;
	filedescriptor *fdinfo;

	GET_PARAM(pgevent, 0, fd, int64_t);
	GET_PARAM(pgevent, 1, pid, int64_t);

	procinfo = m_inspector->get_process(pid, false);
	if (procinfo == NULL)
	{
		//TRACE_DEBUG("couldn't find process");
		return;
	}

	fdinfo = procinfo->get_fd(fd);
	if (fdinfo == NULL)
	{
		//TRACE_DEBUG("couldn't find connection");
		return;
	}

	//
	// Close all connections before deletion.
	//
	fdinfo->close_all_connections(pgevent->m_pevt->ts);

	//
	// Delete fd from the process.
	//
	procinfo->delete_fd(fd);

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
		g_stats.m_n_connect += 1;
		parse_connect_exit(pgevent);
		break;

	case PPME_SOCKET_ACCEPT_X:
	case PPME_SOCKET_ACCEPT_5_X:
	case PPME_SOCKET_ACCEPT4_X:
	case PPME_SOCKET_ACCEPT4_5_X:
		g_stats.m_n_accept += 1;
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
		g_stats.m_n_clone += 1;
		parse_clone_exit(pgevent);
		break;

	case PPME_SYSCALL_EXECVE_8_X:
	case PPME_SYSCALL_EXECVE_13_X:
	case PPME_SYSCALL_EXECVE_14_X:
	case PPME_SYSCALL_EXECVE_15_X:
	case PPME_SYSCALL_EXECVE_16_X:
		g_stats.m_n_execve += 1;
		parse_execve_exit(pgevent);
		break;

	case PPME_PROCEXIT_E:
	case PPME_PROCEXIT_1_E:
		g_stats.m_n_procexit += 1;
		parse_thread_exit(pgevent);
		break;

	case PPME_SYSCALL_CLOSE_E:
		g_stats.m_n_close_e += 1;
		parse_close_enter(pgevent);
		break;

	case PPME_SYSCALL_CLOSE_X:
		g_stats.m_n_close_x += 1;
		//parse_close_exit(pgevent);
		break;

	case PPME_SYSCALL_PWRITE_X:
	case PPME_SYSCALL_WRITE_X:
	case PPME_SYSCALL_WRITEV_X:
	case PPME_SYSCALL_PWRITEV_X:
	case PPME_SOCKET_SEND_X:
	case PPME_SOCKET_SENDTO_X:
		g_stats.m_n_send += 1;
		parse_send_exit(pgevent);
		break;

	case PPME_SYSCALL_PREAD_X:
	case PPME_SYSCALL_READ_X:
	case PPME_SYSCALL_READV_X:
	case PPME_SYSCALL_PREADV_X:
	case PPME_SOCKET_RECV_X:
	case PPME_SOCKET_RECVFROM_X:
		g_stats.m_n_recv += 1;
		parse_recv_exit(pgevent);
		break;

	default:
		break;
	}

	return;
}
