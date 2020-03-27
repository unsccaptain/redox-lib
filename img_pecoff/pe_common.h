#pragma once

#include <stdint.h>
#include <string>

namespace pecoff {
	using namespace std;

	typedef uint32_t pecoff_rva_t;
	typedef uint32_t pecoff_off_t;
	typedef uint16_t pecoff_ordinal_t;
	// spec描述32位但定义是16位的
	typedef uint16_t pecoff_res_id_t;
	typedef uint32_t pecoff_offset_t;
	typedef uint16_t pecoff_reloc_t;
	typedef wstring pecoff_res_name_t;

	typedef const char* pecoff_str_t;

}