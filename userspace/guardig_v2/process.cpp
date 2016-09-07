/*
 * process.cpp
 *
 *  Created on: Sep 5, 2016
 *      Author: user
 */

#include "process.h"
#include "settings.h"
#include "trace.h"
#include "defs.h"

void process::print()
{
	m_printed_exec = true;

	printf("P %s %ld \"%s\" \"%s\" %ld \"%s\" %u \"%s\" \"%s\" \"%s\"\n",
			m_evt_name.c_str(), m_pid, m_exe.c_str(), m_comm.c_str(),
			m_ppid, m_pcomm.c_str(), m_uid, m_cwd.c_str(), m_cgroups_str.c_str(),
			m_cmdline.c_str());
}


void process::print_close()
{
	m_evt_name = "procexit";

	print();
}


void process::create_cmdline()
{
	m_cmdline = m_comm + " ";
	for (size_t i = 0; i < m_args.size(); i++)
	{
		m_cmdline += m_args[i] + " ";
	}

	if (m_cmdline.size() > 0)
		m_cmdline.pop_back(); // remove the last space
}


void process::set_args(const char* args, size_t len)
{
	m_args.clear();

	size_t offset = 0;
	while(offset < len)
	{
		m_args.push_back(args + offset);
		offset += m_args.back().length() + 1;
	}

	create_cmdline();
}


void process::create_cgroups_str()
{
	uint32_t j;
	uint32_t nargs = (uint32_t)m_cgroups.size();

	if(nargs == 0)
		return;

	m_cgroups_str.clear();
	for(j = 0; j < nargs; j++)
	{
		m_cgroups_str += m_cgroups[j].first;
		m_cgroups_str += "=";
		m_cgroups_str += m_cgroups[j].second;
		if(j < nargs - 1)
		{
			m_cgroups_str += ' ';
		}
	}
}


void process::set_cgroups(const char* cgroups, size_t len)
{
	m_cgroups.clear();

	size_t offset = 0;
	while(offset < len)
	{
		const char* str = cgroups + offset;
		const char* sep = strchr(str, '=');
		if(sep == NULL)
		{
			ASSERT(false);
			return;
		}

		string subsys(str, sep - str);
		string cgroup(sep + 1);

		size_t subsys_length = subsys.length();
		size_t pos = subsys.find("_cgroup");
		if(pos != string::npos)
		{
			subsys.erase(pos, sizeof("_cgroup") - 1);
		}

		if(subsys == "perf")
		{
			subsys = "perf_event";
		}
		else if(subsys == "mem")
		{
			subsys = "memory";
		}

		m_cgroups.push_back(std::make_pair(subsys, cgroup));
		offset += subsys_length + 1 + cgroup.length() + 1;
	}

	create_cgroups_str();
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

