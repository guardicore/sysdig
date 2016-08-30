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


class guardig_parser
{
public:

	guardig_parser() {};
	~guardig_parser() {};

	void process_event(guardig *inspector, guardig_evt *pgevent);

private:

	inline void add_socket(guardig_evt *evt, int64_t fd, uint32_t domain, uint32_t type, uint32_t protocol);

	bool retrieve_enter_event(guardig_evt* enter_evt, guardig_evt* exit_evt);

	inline void store_event(guardig_evt* evt);

	uint8_t* reserve_event_buffer();

	void parse_socket_exit(guardig_evt *pgevent);
	//
	// Temporary storage to avoid memory allocation
	//
	guardig_evt m_tmp_evt;
	uint8_t m_fake_userevt_storage[4096];
	//scap_evt* m_fake_userevt;

	stack<uint8_t*> m_tmp_events_buffer;
};


#endif /* USERSPACE_GUARDIG_PARSER_H_ */
