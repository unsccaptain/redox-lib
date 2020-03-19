#pragma once

#include "napi_handler.h"

namespace redox {

	class NapiNative :public NapiBase {
	public:
		NapiNative(napi_env env, uint8_t value);

		NapiNative(napi_env env, uint16_t value);

		NapiNative(napi_env env, uint32_t value);

		NapiNative(napi_env env, unsigned long value);

		NapiNative(napi_env env, uint64_t value);

		NapiNative(napi_env env, int32_t value);

		NapiNative(napi_env env, long value);
	};

	class NapiNamedField :public NapiBase {
	public:
		NapiNamedField(napi_env env, const char* name, uint8_t v, void* ptr);

		NapiNamedField(napi_env env, const char* name, uint16_t v, void* ptr);

		NapiNamedField(napi_env env, const char* name, uint32_t v, void* ptr);

		NapiNamedField(napi_env env, const char* name, unsigned long v, void* ptr);

		NapiNamedField(napi_env env, const char* name, uint64_t v, void* ptr);

		NapiNamedField(napi_env env, const char* name, int32_t v, void* ptr);

		NapiNamedField(napi_env env, const char* name, long v, void* ptr);

		NapiNamedField(napi_env env, const char* name, const char* arr, void* ptr);

		NapiNamedField(napi_env env, const char* name, uint8_t* arr, unsigned len);

		NapiNamedField(napi_env env, const char* name, uint16_t* arr, unsigned len);

		NapiNamedField(napi_env env, const char* name, uint32_t* arr, unsigned len);

		NapiNamedField(napi_env env, const char* name, unsigned long* arr, unsigned len);
	};

#define MAKE_PRIMITIVE_FIELD(ptr, field)	NapiNamedField(env, #field, ptr->field, &ptr->field).GetValue()
#define MAKE_ARRAY_FIELD(ptr, field, size)	NapiNamedField(env, #field, ptr->field, size).GetValue()

}