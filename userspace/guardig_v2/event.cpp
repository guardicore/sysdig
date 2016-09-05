#include "event.h"
#include "defs.h"

guardig_evt_param *guardig_evt::get_param(uint32_t id)
{
	if((m_flags & guardig_evt::SINSP_EF_PARAMS_LOADED) == 0)
	{
		load_params();
		m_flags |= (uint32_t)guardig_evt::SINSP_EF_PARAMS_LOADED;
	}

	if (id < m_params.size())
		return &(m_params[id]);
	else
		return NULL;
}

const struct ppm_param_info* guardig_evt::get_param_info(uint32_t id)
{
	if((m_flags & guardig_evt::SINSP_EF_PARAMS_LOADED) == 0)
	{
		load_params();
		m_flags |= (uint32_t)guardig_evt::SINSP_EF_PARAMS_LOADED;
	}

	ASSERT(id < m_info->nparams);

	return &(m_info->params[id]);
}

