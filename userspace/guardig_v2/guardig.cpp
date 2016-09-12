#include <stdio.h>
#include "scap.h"
#include "guardig.h"
#include "event.h"
#include "parser.h"
#include "trace.h"
#include "defs.h"

struct guardig_evttables g_infotables;
struct stats g_stats = {};


uint32_t interesting_events[] =
{
		/* STATE CHANGERS START */
		//PPME_SOCKET_SOCKETPAIR_E,
		//PPME_SOCKET_SOCKETPAIR_X,
		//PPME_SYSCALL_DUP_E,
		//PPME_SYSCALL_DUP_X,
		//PPME_SYSCALL_FCNTL_E,
		//PPME_SYSCALL_FCNTL_X,
		////PPME_SYSCALL_FORK_E,
		PPME_SYSCALL_FORK_X,
		////PPME_SYSCALL_FORK_17_E,
		PPME_SYSCALL_FORK_17_X,
		////PPME_SYSCALL_FORK_20_E,
		PPME_SYSCALL_FORK_20_X,
		////PPME_SYSCALL_VFORK_E,
		PPME_SYSCALL_VFORK_X,
		////PPME_SYSCALL_VFORK_17_E,
		PPME_SYSCALL_VFORK_17_X,
		////PPME_SYSCALL_VFORK_20_E,
		PPME_SYSCALL_VFORK_20_X,
		/* STATE CHANGERS END */
		////PPME_SYSCALL_EXECVE_8_E,
		PPME_SYSCALL_EXECVE_8_X,
		////PPME_SYSCALL_EXECVE_13_E,
		PPME_SYSCALL_EXECVE_13_X,
		////PPME_SYSCALL_EXECVE_14_E,
		PPME_SYSCALL_EXECVE_14_X,
		////PPME_SYSCALL_EXECVE_15_E,
		PPME_SYSCALL_EXECVE_15_X,
		////PPME_SYSCALL_EXECVE_16_E,
		PPME_SYSCALL_EXECVE_16_X,
		////PPME_SYSCALL_CLONE_11_E,
		PPME_SYSCALL_CLONE_11_X,
		////PPME_SYSCALL_CLONE_16_E,
		PPME_SYSCALL_CLONE_16_X,
		////PPME_SYSCALL_CLONE_17_E,
		PPME_SYSCALL_CLONE_17_X,
		////PPME_SYSCALL_CLONE_20_E,
		PPME_SYSCALL_CLONE_20_X,
		PPME_PROCEXIT_E,
		//PPME_PROCEXIT_X,
		PPME_PROCEXIT_1_E,
		//PPME_PROCEXIT_1_X,

		////PPME_SOCKET_SOCKET_E,
		PPME_SOCKET_SOCKET_X,
		////PPME_SOCKET_SEND_E,
		PPME_SOCKET_SEND_X,
		////PPME_SOCKET_RECV_E,
		PPME_SOCKET_RECV_X,
		////PPME_SOCKET_SENDTO_E,
		PPME_SOCKET_SENDTO_X,
		////PPME_SOCKET_RECVFROM_E,
		PPME_SOCKET_RECVFROM_X,
		////PPME_SOCKET_CONNECT_E,
		PPME_SOCKET_CONNECT_X,
		////PPME_SOCKET_ACCEPT_E,
		PPME_SOCKET_ACCEPT_X,
		////PPME_SOCKET_ACCEPT4_E,
		PPME_SOCKET_ACCEPT4_X,
		////PPME_SOCKET_ACCEPT4_5_E,
		PPME_SOCKET_ACCEPT4_5_X,
		////PPME_SOCKET_ACCEPT_5_E,
		PPME_SOCKET_ACCEPT_5_X,
		PPME_SYSCALL_CLOSE_E,
		PPME_SYSCALL_CLOSE_X,
		////PPME_SOCKET_SHUTDOWN_E,
		////PPME_SOCKET_SHUTDOWN_X,
		////PPME_SYSCALL_WRITE_E,
		PPME_SYSCALL_WRITE_X,
		PPME_SYSCALL_PWRITE_X,
		PPME_SYSCALL_WRITEV_X,
		PPME_SYSCALL_PWRITEV_X,
		// FIXME: what about writev and readv?
		////PPME_SYSCALL_READ_E,
		PPME_SYSCALL_READ_X,
		PPME_SYSCALL_PREAD_X,
		PPME_SYSCALL_READV_X,
		PPME_SYSCALL_PREADV_X,
		//PPME_SOCKET_LISTEN_E,
		//PPME_SOCKET_LISTEN_X,
		//PPME_SOCKET_BIND_E,
		//PPME_SOCKET_BIND_X,
		//PPME_SOCKET_SENDMSG_E,
		//PPME_SOCKET_SENDMSG_X,
		//PPME_SOCKET_SENDMMSG_E,
		//PPME_SOCKET_SENDMMSG_X,
		//PPME_SOCKET_RECVMSG_E,
		//PPME_SOCKET_RECVMSG_X,
		//PPME_SOCKET_RECVMMSG_E,
		//PPME_SOCKET_RECVMMSG_X
};


void guardig::add_process(process &procinfo) //, bool from_scap_proctable)
{
	m_proctable.add(procinfo.m_pid, procinfo);
}


process *guardig::find_process(int64_t pid)
{
	return m_proctable.get(pid);
}


process *guardig::get_process(int64_t pid, bool query_os)
{
	process *procinfo = find_process(pid);

	if (procinfo == NULL && query_os)
	{
		scap_threadinfo* scap_proc = NULL;
		process newproc;

		scap_proc = scap_proc_get(m_capture, pid, false);

		if(scap_proc)
		{
			newproc.init(scap_proc);
			scap_proc_free(m_capture, scap_proc);
		}
		else
		{
			//
			// Add a fake entry to avoid a continuous lookup
			//
			newproc.m_pid = pid;
			newproc.m_is_fake = true;
		}

		add_process(newproc);
		procinfo = find_process(pid);
	}

	return procinfo;
}


void guardig::delete_process(int64_t pid)
{
	m_proctable.remove(pid);
}


void init_info_tables()
{
	g_infotables.m_event_info = scap_get_event_info_table();
	g_infotables.m_syscall_info_table = scap_get_syscall_info_table();
}


void init_event_mask(scap_t *handle)
{
	uint32_t i;
	scap_clear_eventmask(handle);

	for (i = 0; i < sizeof(interesting_events) / sizeof(uint32_t); i++)
	{
		if (scap_set_eventmask(handle, interesting_events[i]) != SCAP_SUCCESS)
		{
			fprintf(stderr, "ERROR setting event mask\n");
		}
	}
}


void print_drop_statistics(scap_t* capture)
{
	static uint64_t nevts = -1;
	static time_t last_time = 0;
	static uint64_t last_devts = 0, last_dropped_devts = 0;
	uint32_t last_drop_prctg = 0, total_drop_prctg = 0;
	scap_stats cstats;

	nevts++;

	if (last_time == 0)
	{
		last_time = time(NULL);
	}

	if (time(NULL) - last_time > DROP_REPORT_SECONDS)
	{
		last_time = time(NULL);

		if (scap_get_stats(capture, &cstats) != SCAP_SUCCESS)
			return;

		total_drop_prctg = (cstats.n_drops / (cstats.n_evts * 1.0)) * 100;
		last_drop_prctg = ((cstats.n_drops - last_dropped_devts) / ((cstats.n_evts - last_devts) * 1.0)) * 100;

		last_devts = cstats.n_evts;
		last_dropped_devts = cstats.n_drops;

		fprintf(stderr, "S Driver Events:%lu Usermode Events:%lu Driver Drops:%lu Total Dropped: %u%% Last Dropped: %u%%\n",
					cstats.n_evts, nevts, cstats.n_drops, total_drop_prctg, last_drop_prctg);

#ifdef GATHER_INTERNAL_STATS
		fprintf(stderr, "S Cached Proc: %lu, Non Cached Proc: %lu, Cached FD: %lu, Non Cached FD: %lu\n",
				g_stats.m_n_cached_proc_lookups, g_stats.m_n_noncached_proc_lookups,
				g_stats.m_n_cached_fd_lookups, g_stats.m_n_noncached_fd_lookups);
#endif
	}
}


int32_t main()
{
	scap_t	*capture = NULL;
	scap_evt *event;
	scap_open_args oargs = {0};
	char error[SCAP_LASTERR_SIZE];
	uint16_t cpuid;
	int32_t retval;
	guardig inspector;
	guardig_evt gevent;
	guardig_parser parser;

	// FIXME: do I need to define this callback?
	/*
	if(!m_filter_proc_table_when_saving)
	{
		oargs.proc_callback = ::on_new_entry_from_proc;
		oargs.proc_callback_context = this;
	}
	oargs.import_users = m_import_users;
	*/

	capture = scap_open(oargs, error);
	if (capture == NULL)
	{
		fprintf(stderr, "SCAP capture open failed: %s\n", error);
		goto cleanup;
	}

	inspector.m_capture = capture;
	parser.m_inspector = &inspector;

	// Reduce the data passed from kernel with i/o commands like write/read to minimum
	if(scap_set_snaplen(capture, 1) != SCAP_SUCCESS)
		ASSERT(false);

	init_event_mask(capture);
	init_info_tables();
	// FIXME: this is hacky, fix it.
	gevent.m_event_info_table = g_infotables.m_event_info;
	parser.m_tmp_evt.m_event_info_table = g_infotables.m_event_info;

	while (1)
	{
		retval = scap_next(capture, &event, &cpuid);
		if (retval != SCAP_SUCCESS)
			continue;

		print_drop_statistics(capture);

		gevent.m_pevt = event;
		gevent.m_cpuid = cpuid;
		parser.process_event(&inspector, &gevent);
	}

cleanup:
	return 0;
}
