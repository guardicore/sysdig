/*
 * threadinfo.h
 *
 *  Created on: Aug 30, 2016
 *      Author: user
 */

#ifndef USERSPACE_GUARDIG_THREADINFO_H_
#define USERSPACE_GUARDIG_THREADINFO_H_

#include "fdinfo.h"

class guardig_threadinfo
{
public:

	uint8_t *m_lastevent_data; // Used by some event parsers to store the last enter event
	uint16_t m_lastevent_cpuid;
	uint16_t m_lastevent_type;
	int64_t m_lastevent_fd;

	int64_t m_tid;
	int64_t m_pid;
	int64_t m_ptid;
	string m_comm; ///< Command name (e.g. "top")
	string m_exe; ///< argv[0] (e.g. "sshd: user@pts/4")
	vector<string> m_args; ///< Command line arguments (e.g. "-d1")
	vector<string> m_env; ///< Environment variables
	uint32_t m_flags; ///< The thread flags. See the PPM_CL_* declarations in ppm_events_public.h.
	uint32_t m_uid; ///< user id
	uint32_t m_gid; ///< group id

	guardig_threadinfo* m_main_thread;
	guardig *m_inspector;
	guardig_fdtable m_fdtable; // The fd table of this thread

	inline guardig_threadinfo() :
		m_fdtable(NULL)
	{
		m_inspector = NULL;
		init();
	}

	inline guardig_threadinfo(guardig *inspector) :
		m_fdtable(inspector)
	{
		m_inspector = inspector;
		init();
	}

	void init();
	void init(scap_threadinfo* pi);

	void add_fd_from_scap(scap_fdinfo *fdi, OUT guardig_fdinfo_t *res);
	guardig_fdinfo_t* add_fd(int64_t fd, guardig_fdinfo_t *fdinfo);
	guardig_threadinfo* lookup_thread();

	void set_cwd(const char* cwd, uint32_t cwdlen);
	void set_args(const char* args, size_t len);

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

	inline guardig_fdtable* get_fd_table()
	{
		guardig_threadinfo* root;

		// FIXME: why do we need this?
		/*
		if(!(m_flags & PPM_CL_CLONE_FILES))
		{
			root = this;
		}
		else
		*/
		{
			root = get_main_thread();
			if(NULL == root)
			{
				return NULL;
			}
		}

		return &(root->m_fdtable);
	}

	/*!
	  \brief Retrive information about one of this thread/process FDs.

	  \param fd The file descriptor number, e.g. 0 for stdin.

	  \return Pointer to the FD information, or NULL if the given FD doesn't
	   exist
	*/
	inline guardig_fdinfo_t* get_fd(int64_t fd)
	{
		if(fd < 0)
		{
			return NULL;
		}

		guardig_fdtable* fdt = get_fd_table();

		if(fdt)
		{
			return fdt->find(fd);
		}

		return NULL;
	}

	inline guardig_threadinfo* get_main_thread()
	{
		if(m_main_thread == NULL)
		{
			//
			// Is this a child thread?
			//
			if(m_pid == m_tid)
			{
				//
				// No, this is either a single thread process or the root thread of a
				// multithread process.
				// Note: we don't set m_main_thread because there are cases in which this is
				//       invoked for a threadinfo that is in the stack. Caching the this pointer
				//       would cause future mess.
				//
				return this;
			}
			else
			{
				//
				// Yes, this is a child thread. Find the process root thread.
				//
				guardig_threadinfo* ptinfo = lookup_thread();
				if(NULL == ptinfo)
				{
					return NULL;
				}

				m_main_thread = ptinfo;
			}
		}

		return m_main_thread;
	}
};

#endif /* USERSPACE_GUARDIG_THREADINFO_H_ */
