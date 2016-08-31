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


void guardig_threadinfo::set_args(const char* args, size_t len)
{
	m_args.clear();

	size_t offset = 0;
	while(offset < len)
	{
		m_args.push_back(args + offset);
		offset += m_args.back().length() + 1;
	}
}

/*
void guardig_threadinfo::set_cwd(const char* cwd, uint32_t cwdlen)
{
	char tpath[SCAP_MAX_PATH_SIZE];
	sinsp_threadinfo* tinfo = get_cwd_root();

	if(tinfo)
	{
		sinsp_utils::concatenate_paths(tpath,
			SCAP_MAX_PATH_SIZE,
			(char*)tinfo->m_cwd.c_str(),
			(uint32_t)tinfo->m_cwd.size(),
			cwd,
			cwdlen);

		tinfo->m_cwd = tpath;

		if(tinfo->m_cwd[tinfo->m_cwd.size() - 1] != '/')
		{
			tinfo->m_cwd += '/';
		}
	}
	else
	{
		ASSERT(false);
	}
}
*/


void guardig_threadinfo::init()
{
	set_lastevent_data_validity(false);
	m_main_thread = NULL;
	m_lastevent_data = NULL;
	m_lastevent_cpuid = -1;
	m_pid = (uint64_t) - 1LL;
	m_tid = (uint64_t) - 1LL;
	m_lastevent_type = -1;
	m_lastevent_fd = (uint64_t) - 1LL;
	m_flags = PPM_CL_NAME_CHANGED;
	m_uid = -1;
	m_gid = -1;
}


void guardig_threadinfo::init(scap_threadinfo* pi)
{
	scap_fdinfo *fdi;
	scap_fdinfo *tfdi;

	init();

	m_tid = pi->tid;
	m_pid = pi->pid;
	//m_ptid = pi->ptid;
	//m_sid = pi->sid;

	m_comm = pi->comm;
	m_exe = pi->exe;
	set_args(pi->args, pi->args_len);
	//set_env(pi->env, pi->env_len);
	//set_cwd(pi->cwd, (uint32_t)strlen(pi->cwd));
	m_flags |= pi->flags;
	m_flags |= PPM_CL_ACTIVE; // Assume that all the threads coming from /proc are real, active threads
	m_fdtable.clear();
	//m_fdlimit = pi->fdlimit;
	m_uid = pi->uid;
	m_gid = pi->gid;
	//m_vmsize_kb = pi->vmsize_kb;
	//m_vmrss_kb = pi->vmrss_kb;
	//m_vmswap_kb = pi->vmswap_kb;
	//m_pfmajor = pi->pfmajor;
	//m_pfminor = pi->pfminor;
	//m_nchilds = 0;
	//m_vtid = pi->vtid;
	//m_vpid = pi->vpid;

	//set_cgroups(pi->cgroups, pi->cgroups_len);
	//m_root = pi->root;
	//ASSERT(m_inspector);
	//m_inspector->m_container_manager.resolve_container(this, m_inspector->m_islive);
	//
	// Prepare for filtering
	//
	guardig_fdinfo_t tfdinfo;
	//guardig_evt tevt;
	//scap_evt tscapevt;

	//
	// Initialize the fake events for filtering
	//
	// FIXME: do we need to send a fake event?
	/*
	tscapevt.ts = 0;
	tscapevt.type = PPME_SYSCALL_READ_X;
	tscapevt.len = 0;

	tevt.m_inspector = m_inspector;
	tevt.m_info = &(g_infotables.m_event_info[PPME_SYSCALL_READ_X]);
	tevt.m_pevt = NULL;
	tevt.m_cpuid = 0;
	tevt.m_evtnum = 0;
	tevt.m_pevt = &tscapevt;
	*/

	// FIXME: I'll probably have to uncomment this code to get existing FDs

	bool match = false;

	HASH_ITER(hh, pi->fdlist, fdi, tfdi)
	{
		add_fd_from_scap(fdi, &tfdinfo);

		if(m_inspector->m_filter != NULL && m_inspector->m_filter_proc_table_when_saving)
		{
			tevt.m_tinfo = this;
			tevt.m_fdinfo = &tfdinfo;
			tscapevt.tid = m_tid;
			int64_t tlefd = tevt.m_tinfo->m_lastevent_fd;
			tevt.m_tinfo->m_lastevent_fd = fdi->fd;

			if(m_inspector->m_filter->run(&tevt))
			{
				match = true;
			}
			else
			{
				//
				// This tells scap not to include this FD in the write file
				//
				fdi->type = SCAP_FD_UNINITIALIZED;
			}

			tevt.m_tinfo->m_lastevent_fd = tlefd;
		}
	}

	m_lastevent_data = NULL;

	if(m_inspector->m_filter != NULL && m_inspector->m_filter_proc_table_when_saving)
	{
		if(!match)
		{
			pi->filtered_out = 1;
		}
	}

}


guardig_threadinfo* guardig_threadinfo::lookup_thread()
{
	return m_inspector->get_thread(m_pid, true, false);
}

