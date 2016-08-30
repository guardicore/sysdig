#ifndef __EVENT_H__
#define __EVENT_H__

#include <stdio.h>
#include <stdint.h>
#include <vector>
#include "scap.h"
#include "../../driver/ppm_events_public.h"
using namespace std;

extern struct guardig_evttables g_infotables;


/*!
  \brief Wrapper that exports the libscap event tables.
*/
class guardig_evttables
{
public:
	const struct ppm_event_info* m_event_info; ///< List of events supported by the capture and analysis subsystems. Each entry fully documents an event and its parameters.
	const struct ppm_syscall_desc* m_syscall_info_table; ///< List of system calls that the capture subsystem recognizes, including the ones that are not decoded yet.
};


/*!
  \brief Event parameter wrapper.
  This class describes a raw event coming from the driver.
*/
class guardig_evt_param
{
public:
	char *m_val;	///< Pointer to the event parameter data.
	uint16_t m_len; ///< Lenght os the parameter pointed by m_val.

private:
	inline void init(char* valptr, uint16_t len)
	{
		m_val = valptr;
		m_len = len;
	}

	friend class guardig_evt;
};


class guardig_evt
{
public:
	scap_evt* m_pevt;
	uint16_t m_cpuid;
	uint64_t m_evtnum;

private:
	vector<guardig_evt_param> m_params;
	uint32_t m_flags;

public:
	guardig_evt_param *get_param(uint32_t id);

	inline uint16_t get_type()
	{
		return m_pevt->type;
	}

	inline int16_t get_cpuid()
	{
		return m_cpuid;
	}

	inline void init()
	{
		m_flags = EF_NONE;
		m_evtnum = 0;
	}

	inline void init(uint8_t* evdata, uint16_t cpuid)
	{
		m_flags = EF_NONE;
		m_pevt = (scap_evt *)evdata;
		m_cpuid = cpuid;
		m_evtnum = 0;
	}

private:

	inline void load_params()
	{
		uint32_t j;
		uint32_t nparams;
		guardig_evt_param par;

		nparams = g_infotables.m_event_info[m_pevt->type].nparams;
		uint16_t *lens = (uint16_t *)((char *)m_pevt + sizeof(struct ppm_evt_hdr));
		char *valptr = (char *)lens + nparams * sizeof(uint16_t);
		m_params.clear();

		for(j = 0; j < nparams; j++)
		{
			par.init(valptr, lens[j]);
			m_params.push_back(par);
			valptr += lens[j];
		}
	}

	enum flags
	{
		SINSP_EF_NONE = 0,
		SINSP_EF_PARAMS_LOADED = 1,
	};
};


#endif // __EVENT_H__
