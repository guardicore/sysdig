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

using namespace std;

class guardig_evt;

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
		m_pid = -1;
		m_ppid = -1;
		m_time = 0;
		m_time_s = 0;
		m_time_ns = 0;
		m_errorcode = -1;
		m_fd = -1;
		m_type = SCAP_FD_UNINITIALIZED;
		m_proto = 0;
		m_exe = "unknown";
		m_comm = "unknown";
		m_pcomm = "unknown";
		m_sip = 0;
		m_sport = 0;
		m_dip = 0;
		m_dport = 0;
		m_uid = -1;
		m_flags = FLAGS_NONE;
	}

	void print();
	void print_close(uint64_t time);

	void set_time(uint64_t ts)
	{
		m_time = ts;
		m_time_s = ts / 1000000000;
		m_time_ns = ts % 1000000000;
	}

	enum flags
	{
		FLAGS_NONE = 0,
		FLAGS_CLOSE_IN_PROGRESS = (1 << 4),
		FLAGS_CLOSE_CANCELED = (1 << 5)
	};

	string m_evt_name;
	pid_t m_pid;
	pid_t m_ppid;
	uint64_t m_time;
	uint32_t m_time_s;
	uint32_t m_time_ns;
	int64_t m_errorcode;
	int64_t m_fd;
	scap_fd_type m_type;
	uint32_t m_proto;
	string m_exe;
	string m_comm;
	string m_pcomm;
	uint32_t m_sip;
	uint16_t m_sport;
	uint32_t m_dip;
	uint16_t m_dport;
	uint32_t m_uid;
	uint32_t m_flags;
};


#endif /* USERSPACE_GUARDIG_V2_CONNECTION_H_ */
