/*
 * connection.h
 *
 *  Created on: Sep 4, 2016
 *      Author: user
 */

#ifndef USERSPACE_GUARDIG_V2_CONNECTION_H_
#define USERSPACE_GUARDIG_V2_CONNECTION_H_

#include <string>
#include "scap.h"
#include "tuples.h"
#include "cache_map.h"
#include "settings.h"

using namespace std;

class process;
class filedescriptor;


class connection
{
public:
	connection()
	{
		init();
	}

	connection(const char *name)
	{
		init();
		m_evt_name = name;
	};

	void init()
	{
		m_evt_name = "unknown";
		m_time = 0;
		m_time_s = 0;
		m_time_ns = 0;
		m_errorcode = -1;
		m_conntuple.m_sip = 0;
		m_conntuple.m_sport = 0;
		m_conntuple.m_dip = 0;
		m_conntuple.m_dport = 0;
		m_sent_bytes = 0;
		m_recv_bytes = 0;
		m_fdinfo = NULL;
		m_printed_creation = false;
	}

	void print(bool with_volume=false);
	void print_close(uint64_t time);
	void print_volume();

	void set_time(uint64_t ts)
	{
		m_time = ts;
		m_time_s = ts / 1000000000;
		m_time_ns = ts % 1000000000;
	}

	string m_evt_name;
	uint64_t m_time;
	uint32_t m_time_s;
	uint32_t m_time_ns;
	int64_t m_errorcode;
	ipv4tuple m_conntuple;
	uint64_t m_sent_bytes;
	uint64_t m_recv_bytes;
	bool m_printed_creation;

	filedescriptor *m_fdinfo;
};


class filedescriptor
{
public:
	filedescriptor() : m_conntable(MAX_CONN_TABLE_SIZE)
	{
		m_fd = -1;
		m_type = SCAP_FD_UNINITIALIZED;
		m_proto = 0;
		m_flags = FLAGS_NONE;
		m_procinfo = NULL;
	}

	connection *add_connection(connection &conninfo);
	connection *get_connection(ipv4tuple &conntuple);
	void delete_connection(ipv4tuple &conntuple);

	int64_t m_fd;
	scap_fd_type m_type;
	uint32_t m_proto;
	uint32_t m_flags;
	process *m_procinfo;
	cache_map<ipv4tuple, connection, ipv4tupleHash> m_conntable;

	enum flags
	{
		FLAGS_NONE = 0,
		FLAGS_CLOSE_IN_PROGRESS = (1 << 4),
		FLAGS_CLOSE_CANCELED = (1 << 5)
	};
};

#endif /* USERSPACE_GUARDIG_V2_CONNECTION_H_ */
