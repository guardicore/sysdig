#ifndef __GUARDIG_H__
#define __GUARDIG_H__

#include <stdint.h>
#include <unordered_map>
#include "scap.h"
#include "settings.h"
#include "threadinfo.h"

using namespace std;

typedef unordered_map<int64_t, guardig_threadinfo> threadinfo_map_t;
typedef threadinfo_map_t::iterator threadinfo_map_iterator_t;

class guardig {

public:

	guardig()
	{
		m_max_fdtable_size = MAX_FD_TABLE_SIZE;
		m_max_thread_table_size = MAX_THREAD_TABLE_SIZE;
		m_capture = NULL;
	}

	guardig_threadinfo *find_thread(int64_t tid, bool lookup_only);
	guardig_threadinfo *get_thread(int64_t tid, bool query_os, bool lookup_only);
	void add_thread(guardig_threadinfo& threadinfo); //, bool from_scap_proctable);

	uint32_t m_max_fdtable_size;
	uint32_t m_max_thread_table_size;

	threadinfo_map_t m_threadinfo_map;
	scap_t *m_capture;
};

#endif // __GUARDIG_H__
