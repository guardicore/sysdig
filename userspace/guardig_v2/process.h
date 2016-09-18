/*
 * process.h
 *
 *  Created on: Sep 5, 2016
 *      Author: user
 */

#ifndef USERSPACE_GUARDIG_V2_PROCESS_H_
#define USERSPACE_GUARDIG_V2_PROCESS_H_

#include <string>
#include <vector>
#include "cache_map.h"
#include "connection.h"
#include "settings.h"

using namespace std;

class process
{

public:
	process() : m_fdtable(MAX_CONN_TABLE_SIZE)
	{
		init();
	}

	process(const char *name) : m_fdtable(MAX_CONN_TABLE_SIZE)
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
		m_exe = "unknown";
		m_pcomm = "unknown";
		m_cwd = "unknown";
		m_cgroups_str = "unknown";
		m_cmdline = "unknown";
		m_uid = -1;
		m_printed_exec = false;
		m_had_connection = false;
	}

	void init(scap_threadinfo *pi)
	{
		m_evt_name = "execve";
		m_pid = pi->pid;
		m_comm = pi->comm;
		m_exe = pi->exe;
		m_cwd = pi->cwd;
		set_cgroups(pi->cgroups, pi->cgroups_len);
		set_args(pi->args, pi->args_len);
		m_uid = pi->uid;
		m_printed_exec = false;
		m_had_connection = false;
	}

	void print();
	void print_close();
	void set_args(const char* args, size_t len);
	void set_cgroups(const char* cgroups, size_t len);

	filedescriptor *add_fd(filedescriptor &fdinfo);
	filedescriptor *get_fd(int64_t fd);
	void delete_fd(int64_t fd);

	string m_evt_name;
	int64_t m_pid;
	int64_t m_ppid;
	string m_comm;
	string m_exe;
	string m_pcomm;
	string m_cwd;
	string m_cmdline;
	string m_cgroups_str;
	uint32_t m_uid;
	bool m_printed_exec;
	bool m_had_connection;
	vector<string> m_args;
	vector<pair<string, string>> m_cgroups;

	cache_map<int64_t, filedescriptor> m_fdtable;

private:
	void create_cgroups_str();
	void create_cmdline();
};


#endif /* USERSPACE_GUARDIG_V2_PROCESS_H_ */