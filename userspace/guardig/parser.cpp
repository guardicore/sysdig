#include "parser.h"
#include "trace.h"

uint8_t* guardig_parser::reserve_event_buffer()
{
	if(m_tmp_events_buffer.empty())
	{
		return (uint8_t*)malloc(sizeof(uint8_t)*SP_EVT_BUF_SIZE);
	}
	else
	{
		auto ptr = m_tmp_events_buffer.top();
		m_tmp_events_buffer.pop();
		return ptr;
	}
}


void guardig_parser::store_event(guardig_evt *evt)
{
	guardig_threadinfo *tinfo;
	bool update_tinfo = false;

	tinfo = get_threadinfo(evt);
	if (tinfo == NULL)
	{
		tinfo = new guardig_threadinfo;
		update_tinfo = true;
	}

	uint32_t elen;

	//
	// Make sure the event data is going to fit
	//
	elen = scap_event_getlen(evt->m_pevt);

	if(elen > SP_EVT_BUF_SIZE)
	{
		TRACE_DEBUG("event data is too big");
		ASSERT(false);
		return;
	}

	if(tinfo->m_lastevent_data == NULL)
	{
		tinfo->m_lastevent_data = reserve_event_buffer();
	}
	memcpy(tinfo->m_lastevent_data, evt->m_pevt, elen);
	tinfo->m_lastevent_cpuid = evt->get_cpuid();

	if (update_tinfo)
		m_threadinfo_map[evt->m_pevt->tid] = *tinfo;
}


bool guardig_parser::retrieve_enter_event(guardig_evt *enter_evt, guardig_evt *exit_evt)
{
	//
	// Make sure there's a valid thread info
	//
	guardig_threadinfo *tinfo;

	tinfo = get_threadinfo(exit_evt);
	if (tinfo == NULL)
		return false;

	//
	// Retrieve the copy of the enter event and initialize it
	//
	if(!(tinfo->is_lastevent_data_valid() && tinfo->m_lastevent_data))
	{
		//
		// This happen especially at the beginning of trace files, where events
		// can be truncated
		//
		return false;
	}

	enter_evt->init(tinfo->m_lastevent_data, tinfo->m_lastevent_cpuid);

	//
	// Make sure that we're using the right enter event, to prevent inconsistencies when events
	// are dropped
	//
	if(enter_evt->get_type() != (exit_evt->get_type() - 1))
	{
		tinfo->set_lastevent_data_validity(false);
		return false;
	}

	return true;
}


void guardig_parser::parse_socket_exit(guardig_evt *pgevent)
{
	guardig_evt_param *parinfo;
	int64_t fd;
	uint32_t domain;
	uint32_t type;
	uint32_t protocol;
	guardig_evt *enter_evt = &m_tmp_evt;

	//
	// NOTE: we don't check the return value of get_param() because we know the arguments we need are there.
	// XXX this extraction would be much faster if we parsed the event mnaually to extract the
	// parameters in one scan. We don't care too much because we assume that we get here
	// seldom enough that saving few tens of CPU cycles is not important.
	//
	parinfo = pgevent->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd = *(int64_t *)parinfo->m_val;

	if(fd < 0)
	{
		//
		// socket() failed. Nothing to add to the table.
		//
		TRACE_DEBUG("socket failed");
		return;
	}

	//
	// Load the enter event so we can access its arguments
	//
	if(!retrieve_enter_event(enter_evt, pgevent))
	{
		TRACE_DEBUG("couldn't retrieve enter event");
		return;
	}

	//
	// Extract the arguments
	//
	parinfo = enter_evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	domain = *(uint32_t *)parinfo->m_val;

	parinfo = enter_evt->get_param(1);
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	type = *(uint32_t *)parinfo->m_val;

	parinfo = enter_evt->get_param(2);
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	protocol = *(uint32_t *)parinfo->m_val;

	TRACE_DEBUG("new socket: tid: %lu, fd: %ld, domain: %u, type: %u, protocol: %u",
			pgevent->m_pevt->tid, fd, domain, type, protocol);
	//
	// Allocate a new fd descriptor, populate it and add it to the thread fd table
	//
	//add_socket(evt, fd, domain, type, protocol);
	return;
}


guardig_threadinfo *guardig_parser::get_threadinfo(guardig_evt *pgevent)
{
	threadinfo_map_iterator_t it;

	it = m_threadinfo_map.find(pgevent->m_pevt->tid);
	if (it != m_threadinfo_map.end())
	{
		return &(it->second);
	}
	else
	{
		return NULL;
	}
}


void guardig_parser::process_event(guardig_evt *pgevent)
{

	switch(pgevent->m_pevt->type)
	{
	case PPME_SOCKET_CONNECT_E:
	case PPME_SOCKET_CONNECT_X:
		TRACE_DEBUG("New connect event");
		break;

	case PPME_SOCKET_SOCKET_E:
		store_event(pgevent);
		break;

	case PPME_SOCKET_SOCKET_X:
		parse_socket_exit(pgevent);
		break;

	default:
		break;
	}

	return;
}
