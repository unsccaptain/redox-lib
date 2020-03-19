#pragma once
#include <node_api.h>
#include <string>
#include <check.h>

namespace redox {
	using namespace std;

	class Formatter {
	public:

	private:
		static string NativeValueFormattedOutput(napi_env env, napi_value native, uint32_t radix);

	private:
		napi_value value_;
	};

}