#pragma once
#include <node_api.h>
#include "framework.h"
#include <vector>
#include <string>

namespace redox {
	using namespace std;

	class NapiBase {
	public:
		NapiBase(napi_env env)
			:env_(env), value_(nullptr) {
		}

		NapiBase(napi_env env, napi_value value)
			:env_(env), value_(value) {
		}

		napi_value GetValue() { return value_; }

	protected:
		napi_value value_;
		napi_env env_;
	};

	class NapiPrimitive :public NapiBase {
	public:
		NapiPrimitive(napi_env env, int32_t value)
			:NapiBase(env) {
			CheckNAPI(napi_create_int32(env, value, &value_));
		}

		NapiPrimitive(napi_env env, uint32_t value)
			:NapiBase(env) {
			CheckNAPI(napi_create_uint32(env, value, &value_));
		}

		NapiPrimitive(napi_env env, int64_t value)
			:NapiBase(env) {
			CheckNAPI(napi_create_int64(env, value, &value_));
		}

		NapiPrimitive(napi_env env, bool value)
			:NapiBase(env) {
			CheckNAPI(napi_get_boolean(env, value, &value_));
		}

		NapiPrimitive(napi_env env, napi_value value)
			:NapiBase(env, value) {
		}

		int64_t GetPrimitive() {
			int64_t number;
			CheckNAPI(napi_get_value_int64(env_, value_, &number));
			return number;
		}
	};

	class NapiString :public NapiBase {
	public:
		NapiString(napi_env env, const string& str)
			:NapiBase(env) {
			CheckNAPI(napi_create_string_utf8(env, str.c_str(), NAPI_AUTO_LENGTH, &value_));
		}

		NapiString(napi_env env, const wstring& str)
			:NapiBase(env) {
			CheckNAPI(napi_create_string_utf16(env, (const char16_t*)str.c_str(), NAPI_AUTO_LENGTH, &value_));
		}
	};

	class NapiArray :public NapiBase {
	public:
		NapiArray(napi_env env)
			:NapiBase(env) {
			CheckNAPI(napi_create_array(env, &value_));
		}

		NapiArray(napi_env env, napi_value value)
			:NapiBase(env, value) {
		}

#define NUMBER_CONSTRUCTOR_DECL(type)										\
		NapiArray(napi_env env, type ary, unsigned len);

		NUMBER_CONSTRUCTOR_DECL(uint8_t*)
			NUMBER_CONSTRUCTOR_DECL(uint16_t*)
			NUMBER_CONSTRUCTOR_DECL(uint32_t*)
			NUMBER_CONSTRUCTOR_DECL(unsigned long*)

			void Push(napi_value element) {
			napi_value push_method = GetProperty("push");
			napi_value result;
			CheckNAPI(napi_call_function(env_, value_, push_method, 1, &element, &result));
		}

		unsigned Length() {
			int32_t len;
			napi_value length_prop = GetProperty("length");
			CheckNAPI(napi_get_value_int32(env_, length_prop, &len));
			return len;
		}

	private:
		napi_value GetProperty(const char* prop_name) {
			napi_value prop;
			CheckNAPI(napi_get_named_property(env_, value_, prop_name, &prop));
			return prop;
		}
	};

	class NapiFunction :public NapiBase {
	public:
		NapiFunction(napi_env env, napi_callback callback, void* data = nullptr);
	};

	class NapiObject :public NapiBase {
	public:
		class NapiPropertyAccessor {
		public:
			NapiPropertyAccessor(napi_env env, napi_value holder, const string& name, napi_value value)
				:env_(env), holder_(holder), prop_name_(name), prop_value_(value) {
			}

			// property setter
			NapiPropertyAccessor& operator=(napi_value prop_value) {
				CheckNAPI(napi_set_named_property(env_, holder_, prop_name_.c_str(), prop_value));
				prop_value_ = prop_value;
				return *this;
			}

			// property getter
			operator napi_value() const {
				return prop_value_;
			}

		private:
			napi_env env_;
			napi_value holder_;
			string prop_name_;
			napi_value prop_value_;
		};

		NapiObject(napi_env env, napi_value value)
			:NapiBase(env, value) {
		}

		NapiObject(napi_env env)
			:NapiBase(env) {
			CheckNAPI(napi_create_object(env, &value_));
		}

		NapiPropertyAccessor operator[](const string& prop_name);
	};

	class ExtractCallbackInfo {
	public:
		ExtractCallbackInfo(napi_env env, napi_callback_info info, size_t args)
			:env_(env), info_(info), argc_(args) {
			argv_.resize(argc_);
			CheckNAPI(napi_get_cb_info(env_, info_, &argc_, argv_.data(), &this_, &data_));
		}

		napi_value GetHolder() {
			return this_;
		}

		napi_value GetArgIdx(unsigned index) { return argv_[index]; }

		size_t GetArgCount() { return argc_; }

		void* GetData() { return data_; }

	private:
		napi_env env_;
		napi_callback_info info_;
		napi_value this_;
		size_t argc_;
		vector<napi_value> argv_;
		void* data_;
	};
}

