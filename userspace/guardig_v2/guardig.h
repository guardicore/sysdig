#ifndef __GUARDIG_H__
#define __GUARDIG_H__

#include <stdint.h>
#include <unordered_map>
#include "scap.h"
#include "settings.h"
#include "process.h"

using namespace std;

typedef unordered_map<int64_t, process> process_map_t;
typedef process_map_t::iterator process_map_iterator_t;


class stats {
public:
	uint64_t m_n_cached_fd_lookups;
	uint64_t m_n_noncached_fd_lookups;
	uint64_t m_n_cached_proc_lookups;
	uint64_t m_n_noncached_proc_lookups;
};


class guardig {

public:

	guardig()
	{
		m_max_conntable_size = MAX_CONN_TABLE_SIZE;
		m_max_proc_table_size = MAX_PROC_TABLE_SIZE;
		m_capture = NULL;
		m_last_procinfo = NULL;
		m_last_pid = 0;
	}

	process *find_process(int64_t pid);
	process *get_process(int64_t pid, bool query_os);
	void delete_process(int64_t pid);
	void add_process(process &proc);

	uint32_t m_max_conntable_size;
	uint32_t m_max_proc_table_size;

	process_map_t m_proctable;
	int64_t m_last_pid;
	process *m_last_procinfo;

	scap_t *m_capture;
};

#endif // __GUARDIG_H__
