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

#ifdef PRINT_COLORS
		m_color = 0;
#endif
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

#ifdef PRINT_COLORS
	static uint32_t color_idx;
	uint32_t m_color;
#endif
};


class filedescriptor
{
public:
	filedescriptor(uint32_t proto) : m_conntable(MAX_CONN_TABLE_SIZE)
	{
		m_fd = -1;
		m_type = SCAP_FD_UNINITIALIZED;
		m_proto = proto;
		m_procinfo = NULL;
		m_tcp_conn_valid = false;
	}

	connection *add_connection(connection &conninfo);
	connection *get_connection(ipv4tuple &conntuple);
	void delete_connection(ipv4tuple &conntuple);
	void close_all_connections(uint64_t timestamp);

	int64_t m_fd;
	scap_fd_type m_type;
	uint32_t m_proto;
	process *m_procinfo;

	connection m_tcp_conn;
	bool m_tcp_conn_valid;
	cache_map<ipv4tuple, connection, ipv4tupleHash> m_conntable;
};

#endif /* USERSPACE_GUARDIG_V2_CONNECTION_H_ */
