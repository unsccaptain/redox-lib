
#include "napi_handler.h"
#include "napi_extend.h"

namespace redox {

#define NUMBER_CONSTRUCTOR(type)										\
	NapiArray::NapiArray(napi_env env, type ary, unsigned len)					\
		:NapiBase(env) {											\
		CheckNAPI(napi_create_array(env, &value_));					\
		for (unsigned i = 0;i < len;i++) {							\
			Push(NapiOriginal(env, ary[i]).GetValue());				\
		}															\
	}

	NUMBER_CONSTRUCTOR(uint8_t*)
	NUMBER_CONSTRUCTOR(uint16_t*)
	NUMBER_CONSTRUCTOR(uint32_t*)
	NUMBER_CONSTRUCTOR(unsigned long*)

	NapiFunction::NapiFunction(napi_env env, napi_callback callback, void* data)
		:NapiBase(env) {
		CheckNAPI(napi_create_function(env, nullptr, NAPI_AUTO_LENGTH, callback, data, &value_));
	}

	NapiObject::NapiPropertyAccessor NapiObject::operator[](const string& prop_name) {
		bool result;
		CheckNAPI(napi_has_named_property(env_, value_, prop_name.c_str(), &result));
		if (result) {
			napi_value prop;
			CheckNAPI(napi_get_named_property(env_, value_, prop_name.c_str(), &prop));
			return NapiPropertyAccessor(env_, value_, prop_name, prop);
		}
		else {
			return NapiPropertyAccessor(env_, value_, prop_name, nullptr);
		}
	}

}