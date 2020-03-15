#pragma once

#define CheckBool(result, message)						\
if(!(result)) throw(exception(message));