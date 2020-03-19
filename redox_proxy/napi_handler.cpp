
#include "napi_handler.h"
#include "napi_extend.h"

namespace redox {

	NapiObject::NapiPropertyAccessor NapiObject::NapiPropertyAccessor::MakePropertyAccessor(
			napi_env env, napi_value holder, const string& prop_name) {
		bool result;
		CheckNAPI(napi_has_named_property(env, holder, prop_name.c_str(), &result));
		if (result) {
			napi_value prop;
			CheckNAPI(napi_get_named_property(env, holder, prop_name.c_str(), &prop));
			return NapiPropertyAccessor(env, holder, prop_name, prop);
		}
		else {
			return NapiPropertyAccessor(env, holder, prop_name, nullptr);
		}
	}

#define NUMBER_CONSTRUCTOR(type)										\
	NapiArray::NapiArray(napi_env env, type ary, unsigned len)					\
		:NapiBase(env) {											\
		CheckNAPI(napi_create_array(env, &value_));					\
		for (unsigned i = 0;i < len;i++) {							\
			Push(NapiNative(env, ary[i]).GetValue());				\
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

}