#include <stdio.h>
#include "guardig.h"
#include "event.h"
#include "parser.h"
#include "trace.h"

struct guardig_evttables g_infotables;

void guardig::add_thread(guardig_threadinfo& threadinfo) //, bool from_scap_proctable)
{
#ifdef GATHER_INTERNAL_STATS
	m_added_threads->increment();
#endif

	//m_last_tinfo = NULL;

	if (m_threadinfo_map.size() >= m_max_thread_table_size
/*
#if defined(HAS_CAPTURE)
		&& threadinfo.m_pid != m_inspector->m_sysdig_pid
#endif
*/
		)
	{
		TRACE_DEBUG("thread table full");
		//m_n_drops++;
		return;
	}

	/*
	if(!from_scap_proctable)
	{
		increment_mainthread_childcount(&threadinfo);
	}
	*/

	//threadinfo.compute_program_hash();

	guardig_threadinfo& newentry = (m_threadinfo_map[threadinfo.m_tid] = threadinfo);

	//newentry.allocate_private_state();

	/*
	if(m_listener)
	{
		m_listener->on_thread_created(&newentry);
	}
	*/
}


guardig_threadinfo *guardig::find_thread(int64_t tid, bool lookup_only)
{
	threadinfo_map_iterator_t it;

	it = m_threadinfo_map.find(tid);
	if (it != m_threadinfo_map.end())
	{
		return &(it->second);
	}
	else
	{
		return NULL;

		// FIXME: they have a cache of the last used threadinfo.
		// I should add that eventually.

	}
}


guardig_threadinfo *guardig::get_thread(int64_t tid, bool query_os, bool lookup_only)
{
	guardig_threadinfo* guardig_proc = find_thread(tid, lookup_only);

	if(guardig_proc == NULL && query_os &&
	   (m_threadinfo_map.size() < m_max_thread_table_size))
	{
		scap_threadinfo* scap_proc = NULL;
		guardig_threadinfo newti(this);

		scap_proc = scap_proc_get(m_capture, tid, true);

		if(scap_proc)
		{
			newti.init(scap_proc);
			scap_proc_free(m_capture, scap_proc);
		}
		else
		{
			//
			// Add a fake entry to avoid a continuous lookup
			//
			newti.m_tid = tid;
			newti.m_pid = tid;
			//newti.m_ptid = -1;
			newti.m_comm = "<NA>";
			newti.m_exe = "<NA>";
			newti.m_uid = 0xffffffff;
			newti.m_gid = 0xffffffff;
			//newti.m_nchilds = 0;
		}

		//
		// Since this thread is created out of thin air, we need to
		// properly set its reference count, by scanning the table
		//
		/*
		threadinfo_map_t* pttable = &m_thread_manager->m_threadtable;
		threadinfo_map_iterator_t it;

		for(it = pttable->begin(); it != pttable->end(); ++it)
		{
			if(it->second.m_pid == tid)
			{
				newti.m_nchilds++;
			}
		}
		*/

		//
		// Done. Add the new thread to the list.
		//
		add_thread(newti);
		guardig_proc = find_thread(tid, lookup_only);
	}

	return guardig_proc;
}


void init_info_tables()
{
	g_infotables.m_event_info = scap_get_event_info_table();
	g_infotables.m_syscall_info_table = scap_get_syscall_info_table();
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

	TRACE_DEBUG("Guardig starting..");

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

	init_info_tables();
	// FIXME: this is hacky, fix it.
	gevent.m_event_info_table = g_infotables.m_event_info;
	parser.m_tmp_evt.m_event_info_table = g_infotables.m_event_info;

	while (1)
	{
		retval = scap_next(capture, &event, &cpuid);
		if (retval != SCAP_SUCCESS)
			continue;

		gevent.m_pevt = event;
		gevent.m_cpuid = cpuid;
		parser.process_event(&inspector, &gevent);
	}

cleanup:
	return 0;
}
