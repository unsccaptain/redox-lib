#include "formatter.h"
#include "napi_handler.h"
#include "napi_extend.h"
#include <sstream>

namespace redox {

	string Formatter::NativeValueFormattedOutput(napi_env env, napi_value native, uint32_t radix) {
		NapiObject object = NapiObject(env, native);
		int64_t field_value;
		uint64_t field_value_u;
		stringstream stream;
		string output;
		stream.fill('0');

		int32_t byte_size = NapiPrimitive(env, object["byte_size"]).GetPrimitive();
		if (byte_size != 8) {
			field_value = NapiPrimitive(env, object["value"]).GetPrimitive();
			field_value = field_value & ((1LL << (byte_size * 8)) - 1);
		}
		else {
			field_value_u = NapiPrimitive(env, object["value_high"]).GetPrimitive();
			field_value_u = ((uint64_t)field_value_u << 32) | NapiPrimitive(env, object["value_low"]).GetPrimitive();
			stream.width(byte_size * 2);
			stream << std::hex << std::uppercase << field_value_u;
			stream >> output;
			return output;
		}

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

		return output;
	}

}