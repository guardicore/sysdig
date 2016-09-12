#ifndef __GUARDIG_H__
#define __GUARDIG_H__

#include <stdint.h>
#include <unordered_map>
#include "scap.h"
#include "settings.h"
#include "process.h"
#include "cache_map.h"

using namespace std;

class stats {
public:
	uint64_t m_n_cached_fd_lookups;
	uint64_t m_n_noncached_fd_lookups;
	uint64_t m_n_cached_proc_lookups;
	uint64_t m_n_noncached_proc_lookups;
};


class guardig {

public:

	guardig() : m_proctable(MAX_PROC_TABLE_SIZE)
	{
		m_capture = NULL;
	}

	process *find_process(int64_t pid);
	process *get_process(int64_t pid, bool query_os);
	void delete_process(int64_t pid);
	void add_process(process &proc);

	cache_map<int64_t, process> m_proctable;
	scap_t *m_capture;
};

#endif // __GUARDIG_H__
