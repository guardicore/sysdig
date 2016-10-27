/*
 * settings.h
 *
 *  Created on: Aug 30, 2016
 *      Author: user
 */

#ifndef USERSPACE_GUARDIG_SETTINGS_H_
#define USERSPACE_GUARDIG_SETTINGS_H_

//
// Max size that the thread table can reach
//
#define MAX_PROC_TABLE_SIZE 32768

//
// Max size that the FD table of a process can reach
//
#define MAX_CONN_TABLE_SIZE 4096

//
// Period for reporting drop events statistics
//
#define DROP_REPORT_SECONDS 10

//
// Time for checking for inactive processes
//
#define INACTIVE_PROC_CHECK_SECONDS (5 * 60)

//
// Time for checking for inactive connections
//
#define INACTIVE_CONN_CHECK_SECONDS 30

//
// Time for removing inactive connections  
//
#define INACTIVE_CONN_REMOVE_SECONDS (60)

#endif /* USERSPACE_GUARDIG_SETTINGS_H_ */
