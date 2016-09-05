/*
 * process.h
 *
 *  Created on: Sep 5, 2016
 *      Author: user
 */

#ifndef USERSPACE_GUARDIG_V2_PROCESS_H_
#define USERSPACE_GUARDIG_V2_PROCESS_H_

#include <string>
#include <unordered_map>
#include "connection.h"

using namespace std;

typedef unordered_map<int64_t, connection> connection_map_t;
typedef connection_map_t::iterator connection_map_iterator_t;

class process
{

public:
	process()
	{
		init();
	}

	process(const char *name)
	{
		init();
		m_evt_name = name;
	}

	void init()
	{
		m_evt_name = "unknown";
		m_pid = -1;
		m_ppid = -1;
		m_comm = "unknown";
		m_proc_path = "unknown";
		m_proc_name = "unknown";
		m_pproc_name = "unknown";
		m_cwd = "unknown";
		m_cgroups = "unknown";
		m_cmdline = "unknown";
		m_uid = -1;
		m_printed_exec = false;
		m_had_connection = false;
	}

	void print();
	void add_connection(connection &conninfo);
	connection *get_connection(int64_t fd);
	void delete_connection(int64_t fd);

	string m_evt_name;
	pid_t m_pid;
	pid_t m_ppid;
	string m_comm;
	string m_proc_path;
	string m_proc_name;
	string m_pproc_name;
	string m_cwd;
	string m_cgroups;
	string m_cmdline;
	uint32_t m_uid;
	bool m_printed_exec;
	bool m_had_connection;

	connection_map_t m_conntable;
};


#endif /* USERSPACE_GUARDIG_V2_PROCESS_H_ */
