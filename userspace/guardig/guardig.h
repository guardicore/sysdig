#ifndef __GUARDIG_H__
#define __GUARDIG_H__

#include <stdint.h>
#include "scap.h"

//
// ASSERT implementation
//
#ifdef _DEBUG
#define ASSERT(X) assert(X)
#else // _DEBUG
#define ASSERT(X)
#endif // _DEBUG

#endif // __GUARDIG_H__
