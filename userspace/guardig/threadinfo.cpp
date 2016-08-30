/*
 * threadinfo.cpp
 *
 *  Created on: Aug 30, 2016
 *      Author: user
 */

#include "guardig.h"
#include "threadinfo.h"

guardig_fdinfo_t* guardig_threadinfo::add_fd(int64_t fd, guardig_fdinfo_t *fdinfo)
{
	guardig_fdinfo_t *res;
	guardig_fdtable *fdtable = get_fd_table();

	if (fdtable == NULL)
		return NULL;

	res = fdtable->add(fd, fdinfo);

	//
	// Update the last event fd. It's needed by the filtering engine
	//
	//m_lastevent_fd = fd;

	return res;
}

guardig_threadinfo* guardig_threadinfo::lookup_thread()
{
	return m_inspector->get_threadinfo(m_pid);
}

