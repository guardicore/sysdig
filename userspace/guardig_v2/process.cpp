/*
 * process.cpp
 *
 *  Created on: Sep 5, 2016
 *      Author: user
 */

#include "process.h"
#include "settings.h"
#include "trace.h"

void process::print()
{
	m_printed_exec = true;

	printf("P %s %d \"%s\" \"%s\" %d \"%s\" %u \"%s\" \"%s\" \"%s\"\n",
			m_evt_name.c_str(), m_pid, m_proc_path.c_str(), m_proc_name.c_str(),
			m_ppid, m_pproc_name.c_str(), m_uid, m_cwd.c_str(), m_cgroups.c_str(),
			m_cmdline.c_str());
}


void process::add_connection(connection &conninfo)
{
	if (m_conntable.size() >= MAX_CONN_TABLE_SIZE)
	{
		TRACE_DEBUG("thread table full");
		return;
	}

	//threadinfo.compute_program_hash();

	connection &newentry = (m_conntable[conninfo.m_fd] = conninfo);
	m_had_connection = true;
}


connection *process::get_connection(int64_t fd)
{
	connection_map_iterator_t it;

	it = m_conntable.find(fd);
	if (it != m_conntable.end())
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


void process::delete_connection(int64_t fd)
{
	connection_map_iterator_t it;

	it = m_conntable.find(fd);
	if (it != m_conntable.end())
	{
		m_conntable.erase(it);
	}
	else
	{
		return;

		// FIXME: clear last process cache
	}
}

