
#include "napi_extend.h"
#include <string>
#include <stdlib.h>
#include <sstream>

namespace redox {

	static napi_value TrivalRewriteCallback(napi_env env, napi_callback_info info) {
		return nullptr;
	}

	static napi_value OriginalToStringCallback(napi_env env, napi_callback_info info) {
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 1);
		int radix = 16;
		if (cbi.GetArgCount() == 1) {
			CheckNAPI(napi_get_value_int32(env, cbi.GetArgIdx(0), &radix));
		}

		NapiObject object = NapiObject(env, cbi.GetHolder());
		int64_t field_value = NapiPrimitive(env, object["value"]).GetPrimitive();
		int32_t byte_size = NapiPrimitive(env, object["byte_size"]).GetPrimitive();
		field_value = field_value & ((1LL << (byte_size * 8)) - 1);
		stringstream stream;
		string output;

		stream.fill('0');
		switch (radix) {
		case 8:
			stream << std::oct << field_value;
			break;
		case 10:
			stream << std::dec << field_value;
			break;
		case 16:
			stream.width(byte_size * 2);
			stream << std::hex << std::uppercase << field_value;
			break;
		default:
			assert(false);
		}
		stream >> output;

		return NapiString(env, output).GetValue();
	}

	NapiOriginal::NapiOriginal(napi_env env, uint8_t value)
		:NapiBase(env) {
		CheckNAPI(napi_create_object(env, &value_));
		CheckNAPI(napi_set_named_property(env, value_, "value", NapiPrimitive(env, value).GetValue()));
		CheckNAPI(napi_set_named_property(
			env, value_, "byte_size", NapiPrimitive(env, 1).GetValue()));
		CheckNAPI(napi_set_named_property(
			env, value_, "toString", NapiFunction(env, OriginalToStringCallback).GetValue()));
	}

	NapiOriginal::NapiOriginal(napi_env env, uint16_t value)
		:NapiBase(env) {
		CheckNAPI(napi_create_object(env, &value_));
		CheckNAPI(napi_set_named_property(env, value_, "value", NapiPrimitive(env, value).GetValue()));
		CheckNAPI(napi_set_named_property(
			env, value_, "byte_size", NapiPrimitive(env, 2).GetValue()));
		CheckNAPI(napi_set_named_property(
			env, value_, "toString", NapiFunction(env, OriginalToStringCallback).GetValue()));
	}

	NapiOriginal::NapiOriginal(napi_env env, uint32_t value)
		:NapiBase(env) {
		CheckNAPI(napi_create_object(env, &value_));
		CheckNAPI(napi_set_named_property(env, value_, "value", NapiPrimitive(env, (int64_t)value).GetValue()));
		CheckNAPI(napi_set_named_property(
			env, value_, "byte_size", NapiPrimitive(env, 4).GetValue()));
		CheckNAPI(napi_set_named_property(
			env, value_, "toString", NapiFunction(env, OriginalToStringCallback).GetValue()));
	}

	NapiOriginal::NapiOriginal(napi_env env, unsigned long value)
		:NapiBase(env) {
		CheckNAPI(napi_create_object(env, &value_));
		CheckNAPI(napi_set_named_property(env, value_, "value", NapiPrimitive(env, (int64_t)value).GetValue()));
		CheckNAPI(napi_set_named_property(
			env, value_, "byte_size", NapiPrimitive(env, 4).GetValue()));
		CheckNAPI(napi_set_named_property(
			env, value_, "toString", NapiFunction(env, OriginalToStringCallback).GetValue()));
	}

	NapiOriginal::NapiOriginal(napi_env env, int32_t value)
		:NapiBase(env) {
		CheckNAPI(napi_create_object(env, &value_));
		CheckNAPI(napi_set_named_property(env, value_, "value", NapiPrimitive(env, value).GetValue()));
		CheckNAPI(napi_set_named_property(
			env, value_, "byte_size", NapiPrimitive(env, 4).GetValue()));
		CheckNAPI(napi_set_named_property(
			env, value_, "toString", NapiFunction(env, OriginalToStringCallback).GetValue()));
	}

	NapiOriginal::NapiOriginal(napi_env env, long value)
		:NapiBase(env) {
		CheckNAPI(napi_create_object(env, &value_));
		CheckNAPI(napi_set_named_property(env, value_, "value", NapiPrimitive(env, value).GetValue()));
		CheckNAPI(napi_set_named_property(
			env, value_, "byte_size", NapiPrimitive(env, 4).GetValue()));
		CheckNAPI(napi_set_named_property(
			env, value_, "toString", NapiFunction(env, OriginalToStringCallback).GetValue()));
	}

	static napi_value ArrayToStringCallback(napi_env env, napi_callback_info info) {
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 0);


	}

	NapiNamedField::NapiNamedField(napi_env env, const char* name, uint8_t v, void* ptr)
		:NapiBase(env) {
		CheckNAPI(napi_create_object(env, &value_));
		CheckNAPI(napi_set_named_property(env, value_, "field_name", redox::NapiString(env, name).GetValue()));
		CheckNAPI(napi_set_named_property(env, value_, "field_value", redox::NapiOriginal(env, v).GetValue()));
		CheckNAPI(napi_set_named_property(env, value_, "rewrite",
			redox::NapiFunction(env, TrivalRewriteCallback, ptr).GetValue()));
	}

	NapiNamedField::NapiNamedField(napi_env env, const char* name, uint16_t v, void* ptr)
		:NapiBase(env) {
		CheckNAPI(napi_create_object(env, &value_));
		CheckNAPI(napi_set_named_property(env, value_, "field_name", redox::NapiString(env, name).GetValue()));
		CheckNAPI(napi_set_named_property(env, value_, "field_value", redox::NapiOriginal(env, v).GetValue()));
		CheckNAPI(napi_set_named_property(env, value_, "rewrite",
			redox::NapiFunction(env, TrivalRewriteCallback, ptr).GetValue()));
	}

	NapiNamedField::NapiNamedField(napi_env env, const char* name, uint32_t v, void* ptr)
		:NapiBase(env) {
		CheckNAPI(napi_create_object(env, &value_));
		CheckNAPI(napi_set_named_property(env, value_, "field_name", redox::NapiString(env, name).GetValue()));
		CheckNAPI(napi_set_named_property(env, value_, "field_value", redox::NapiOriginal(env, v).GetValue()));
		CheckNAPI(napi_set_named_property(env, value_, "rewrite",
			redox::NapiFunction(env, TrivalRewriteCallback, ptr).GetValue()));
	}

	NapiNamedField::NapiNamedField(napi_env env, const char* name, unsigned long v, void* ptr)
		:NapiBase(env) {
		CheckNAPI(napi_create_object(env, &value_));
		CheckNAPI(napi_set_named_property(env, value_, "field_name", redox::NapiString(env, name).GetValue()));
		CheckNAPI(napi_set_named_property(env, value_, "field_value", redox::NapiOriginal(env, v).GetValue()));
		CheckNAPI(napi_set_named_property(env, value_, "rewrite",
			redox::NapiFunction(env, TrivalRewriteCallback, ptr).GetValue()));
	}

	NapiNamedField::NapiNamedField(napi_env env, const char* name, int32_t v, void* ptr)
		:NapiBase(env) {
		CheckNAPI(napi_create_object(env, &value_));
		CheckNAPI(napi_set_named_property(env, value_, "field_name", redox::NapiString(env, name).GetValue()));
		CheckNAPI(napi_set_named_property(env, value_, "field_value", redox::NapiOriginal(env, v).GetValue()));
		CheckNAPI(napi_set_named_property(env, value_, "rewrite",
			redox::NapiFunction(env, TrivalRewriteCallback, ptr).GetValue()));
	}

	NapiNamedField::NapiNamedField(napi_env env, const char* name, long v, void* ptr)
		:NapiBase(env) {
		CheckNAPI(napi_create_object(env, &value_));
		CheckNAPI(napi_set_named_property(env, value_, "field_name", redox::NapiString(env, name).GetValue()));
		CheckNAPI(napi_set_named_property(env, value_, "field_value", redox::NapiOriginal(env, v).GetValue()));
		CheckNAPI(napi_set_named_property(env, value_, "rewrite",
			redox::NapiFunction(env, TrivalRewriteCallback, ptr).GetValue()));
	}

	NapiNamedField::NapiNamedField(napi_env env, const char* name, const char* arr, void* ptr)
		:NapiBase(env) {
		CheckNAPI(napi_create_object(env, &value_));
		CheckNAPI(napi_set_named_property(env, value_, "field_name", redox::NapiString(env, name).GetValue()));
		CheckNAPI(napi_set_named_property(env, value_, "field_value", redox::NapiString(env, arr).GetValue()));
		CheckNAPI(napi_set_named_property(env, value_, "rewrite",
			redox::NapiFunction(env, TrivalRewriteCallback, ptr).GetValue()));
	}

	NapiNamedField::NapiNamedField(napi_env env, const char* name, uint8_t* arr, unsigned len)
		:NapiBase(env) {
		CheckNAPI(napi_create_object(env, &value_));
		CheckNAPI(napi_set_named_property(env, value_, "field_name", redox::NapiString(env, name).GetValue()));
		CheckNAPI(napi_set_named_property(env, value_, "field_value", redox::NapiArray(env, arr, len).GetValue()));
		CheckNAPI(napi_set_named_property(env, value_, "rewrite",
			redox::NapiFunction(env, TrivalRewriteCallback, arr).GetValue()));
	}

	NapiNamedField::NapiNamedField(napi_env env, const char* name, uint16_t* arr, unsigned len)
		:NapiBase(env) {
		CheckNAPI(napi_create_object(env, &value_));
		CheckNAPI(napi_set_named_property(env, value_, "field_name", redox::NapiString(env, name).GetValue()));
		CheckNAPI(napi_set_named_property(env, value_, "field_value", redox::NapiArray(env, arr, len).GetValue()));
		CheckNAPI(napi_set_named_property(env, value_, "rewrite",
			redox::NapiFunction(env, TrivalRewriteCallback, arr).GetValue()));
	}

	NapiNamedField::NapiNamedField(napi_env env, const char* name, uint32_t* arr, unsigned len)
		:NapiBase(env) {
		CheckNAPI(napi_create_object(env, &value_));
		CheckNAPI(napi_set_named_property(env, value_, "field_name", redox::NapiString(env, name).GetValue()));
		CheckNAPI(napi_set_named_property(env, value_, "field_value", redox::NapiArray(env, arr, len).GetValue()));
		CheckNAPI(napi_set_named_property(env, value_, "rewrite",
			redox::NapiFunction(env, TrivalRewriteCallback, arr).GetValue()));
	}

	NapiNamedField::NapiNamedField(napi_env env, const char* name, unsigned long* arr, unsigned len)
		:NapiBase(env) {
		CheckNAPI(napi_create_object(env, &value_));
		CheckNAPI(napi_set_named_property(env, value_, "field_name", redox::NapiString(env, name).GetValue()));
		CheckNAPI(napi_set_named_property(env, value_, "field_value", redox::NapiArray(env, arr, len).GetValue()));
		CheckNAPI(napi_set_named_property(env, value_, "rewrite",
			redox::NapiFunction(env, TrivalRewriteCallback, arr).GetValue()));
	}
}