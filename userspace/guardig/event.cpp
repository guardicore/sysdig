#include "event.h"

guardig_evt_param *guardig_evt::get_param(uint32_t id)
{
	if((m_flags & guardig_evt::SINSP_EF_PARAMS_LOADED) == 0)
	{
		load_params();
		m_flags |= (uint32_t)guardig_evt::SINSP_EF_PARAMS_LOADED;
	}

	return &(m_params[id]);
}

