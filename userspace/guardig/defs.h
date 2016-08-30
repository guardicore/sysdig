/*
 * defs.h
 *
 *  Created on: Aug 30, 2016
 *      Author: user
 */

#ifndef USERSPACE_GUARDIG_DEFS_H_
#define USERSPACE_GUARDIG_DEFS_H_

//
// ASSERT implementation
//
#ifdef _DEBUG
#define ASSERT(X) assert(X)
#else // _DEBUG
#define ASSERT(X)
#endif // _DEBUG


#endif /* USERSPACE_GUARDIG_DEFS_H_ */
