#pragma once

#include <assert.h>

#define CheckBool(result, message)						\
if(!(result)) throw(exception(message));

#define CheckNAPI(status)								\
if((status)!=napi_ok) assert(false);

#define CheckPTR(ptr)									\
if((ptr)==0) assert(false);

#define CheckERR(code)									\
if((code)!=0) assert(false);