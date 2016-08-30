/*
 * parser.h
 *
 *  Created on: Aug 29, 2016
 *      Author: user
 */

#ifndef USERSPACE_GUARDIG_PARSER_H_
#define USERSPACE_GUARDIG_PARSER_H_

#include "scap.h"
#include "guardig.h"
#include "event.h"
#include <vector>
#include <unordered_map>
#include <stack>
using namespace std;

//
// Memory storage size for an entry in the event storage LIFO.
// Events bigger than SP_EVT_BUF_SIZE won't be be stored in the LIFO.
//
#define SP_EVT_BUF_SIZE 4096

class guardig_threadinfo
{
public:

	uint8_t* m_lastevent_data; // Used by some event parsers to store the last enter event
	uint16_t m_lastevent_cpuid;

	inline guardig_threadinfo()
	{
		m_lastevent_data = NULL;
		m_lastevent_cpuid = -1;
	}

	inline bool is_lastevent_data_valid()
	{
		return (m_lastevent_cpuid != (uint16_t) - 1);
	}

	inline void set_lastevent_data_validity(bool isvalid)
	{
		if(isvalid)
		{
			m_lastevent_cpuid = (uint16_t)1;
		}
		else
		{
			m_lastevent_cpuid = (uint16_t) - 1;
		}
	}
};

typedef unordered_map<int64_t, guardig_threadinfo> threadinfo_map_t;
typedef threadinfo_map_t::iterator threadinfo_map_iterator_t;

class guardig_parser
{
public:

	guardig_parser() {};
	~guardig_parser() {};

	void process_event(guardig_evt *pgevent);

private:

	bool retrieve_enter_event(guardig_evt* enter_evt, guardig_evt* exit_evt);

	inline void store_event(guardig_evt* evt);

	guardig_threadinfo *get_threadinfo(guardig_evt *pgevent);
	uint8_t* reserve_event_buffer();

	void parse_socket_exit(guardig_evt *pgevent);
	//
	// Temporary storage to avoid memory allocation
	//
	guardig_evt m_tmp_evt;
	uint8_t m_fake_userevt_storage[4096];
	//scap_evt* m_fake_userevt;

	threadinfo_map_t m_threadinfo_map;
	stack<uint8_t*> m_tmp_events_buffer;
};


#endif /* USERSPACE_GUARDIG_PARSER_H_ */
