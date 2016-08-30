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
	}

	guardig_threadinfo *get_threadinfo(int64_t tid);

	uint32_t m_max_fdtable_size;
	threadinfo_map_t m_threadinfo_map;
};

#endif // __GUARDIG_H__
