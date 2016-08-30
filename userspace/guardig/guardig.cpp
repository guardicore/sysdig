#include <stdio.h>
#include "guardig.h"
#include "event.h"
#include "parser.h"

struct guardig_evttables g_infotables;

void init_info_tables()
{
	g_infotables.m_event_info = scap_get_event_info_table();
	g_infotables.m_syscall_info_table = scap_get_syscall_info_table();
}


int32_t main()
{
	scap_t	*capture = NULL;
	scap_evt *event;
	scap_open_args oargs = {0};
	char error[SCAP_LASTERR_SIZE];
	uint16_t cpuid;
	int32_t retval;
	guardig_evt gevent;
	guardig_parser parser;

	printf("Guardig starting..\n");

	capture = scap_open(oargs, error);
	if (capture == NULL)
	{
		fprintf(stderr, "SCAP capture open failed: %s\n", error);
		goto cleanup;
	}

	init_info_tables();

	while (1)
	{
		retval = scap_next(capture, &event, &cpuid);
		if (retval != SCAP_SUCCESS)
			continue;

		gevent.init();
		gevent.m_pevt = event;
		gevent.m_cpuid = cpuid;
		parser.process_event(&gevent);
	}

cleanup:
	return 0;
}
