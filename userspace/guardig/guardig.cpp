#include <stdio.h>
#include "guardig.h"
#include "event.h"
#include "parser.h"
#include "trace.h"

struct guardig_evttables g_infotables;

guardig_threadinfo *guardig::get_threadinfo(int64_t tid)
{
	threadinfo_map_iterator_t it;

	it = m_threadinfo_map.find(tid);
	if (it != m_threadinfo_map.end())
	{
		return &(it->second);
	}
	else
	{
		//return NULL;
		if (m_threadinfo_map.size() > MAX_THREAD_TABLE_SIZE)
		{
			TRACE_DEBUG("thread table reached max size");
			return NULL;
		}

		guardig_threadinfo *tinfo = new guardig_threadinfo(this);
		m_threadinfo_map[tid] = *tinfo;

		it = m_threadinfo_map.find(tid);
		if (it != m_threadinfo_map.end())
		{
			return &(it->second);
		}
		else
		{
			return NULL;
		}
	}
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

	printf("Guardig starting..\n");

	capture = scap_open(oargs, error);
	if (capture == NULL)
	{
		fprintf(stderr, "SCAP capture open failed: %s\n", error);
		goto cleanup;
	}

	init_info_tables();

	while (1)
	{
		retval = scap_next(capture, &event, &cpuid);
		if (retval != SCAP_SUCCESS)
			continue;

		gevent.init();
		gevent.m_pevt = event;
		gevent.m_cpuid = cpuid;
		parser.process_event(&inspector, &gevent);
	}

cleanup:
	return 0;
}
