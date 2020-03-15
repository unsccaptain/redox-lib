
#include "framework.h"
#include "module_pecoff.h"

NAPI_MODULE_INIT() {
	napi_value value = 0;
	CheckNAPI(napi_create_object(env, &value));
	CheckNAPI(napi_set_named_property(env, value, "pecoff", pecoff::CreatePecoffRootObject(env)));
	return value;
}