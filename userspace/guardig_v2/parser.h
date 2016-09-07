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
	guardig *m_inspector;
	guardig_evt m_tmp_evt;

	guardig_parser() {
		m_inspector = NULL;
	};
	~guardig_parser() {
		// FIXME: meed to delete m_tmp_events_buffer?
	};

	void process_event(guardig *inspector, guardig_evt *pgevent);

private:

	bool reset(guardig_evt *evt);

	//bool set_ipv4_addresses_and_ports(guardig_fdinfo_t* fdinfo, uint8_t* packed_data);
	//inline void add_socket(guardig_evt *evt, int64_t fd, uint32_t domain, uint32_t type, uint32_t protocol);
	//void erase_fd(erase_fd_params* params);

	//bool retrieve_enter_event(guardig_evt* enter_evt, guardig_evt* exit_evt);

	//inline void store_event(guardig_evt* evt);

	//uint8_t* reserve_event_buffer();

	//void parse_socket_exit(guardig_evt *pgevent);
	//void parse_bind_exit(guardig_evt *pgevent);
	void parse_connect_exit(guardig_evt *pgevent);
	void parse_accept_exit(guardig_evt *pgevent);
	void parse_sendto_exit(guardig_evt *pgevent);
	void parse_recvfrom_exit(guardig_evt *pgevent);
	//void parse_clone_exit(guardig_evt *evt);
	void parse_execve_exit(guardig_evt *pgevent);
	void parse_thread_exit(guardig_evt *pgevent);
	void parse_close_enter(guardig_evt *pgevent);
	void parse_close_exit(guardig_evt *pgevent);
	//
	// Temporary storage to avoid memory allocation
	//
	uint8_t m_fake_userevt_storage[4096];
	//scap_evt* m_fake_userevt;

	stack<uint8_t*> m_tmp_events_buffer;
};


#endif /* USERSPACE_GUARDIG_PARSER_H_ */
