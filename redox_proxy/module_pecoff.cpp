
#include "framework.h"
#include "module_pecoff.h"
#include "napi_handler.h"
#include "napi_extend.h"

#include <pe_coff.h>
#include <pe_import.h>
#include <pe_export.h>
#include <redox_utils.h>
#include <sstream>

namespace pecoff {
	using namespace redox;

	static void AnalysisFinalize(napi_env env, void* finalize_data, void* finalize_hint) {

	}

	static PECoffAnalysis* GetWrappedAnalysis(napi_env env, napi_value value) {
		void* wrapped;
		CheckNAPI(napi_unwrap(env, value, &wrapped));
		return static_cast<PECoffAnalysis*>(wrapped);
	}

	static napi_value GetImageDosHeader(napi_env env, napi_callback_info info) {
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 0);
		PECoffAnalysis* analysis = GetWrappedAnalysis(env, cbi.GetHolder());
		PIMAGE_DOS_HEADER dos_header = analysis->GetDosHeader();

		NapiObject dos_header_object = NapiObject(env);
#define NDH(f)		dos_header_object[#f] = MAKE_PRIMITIVE_FIELD(dos_header, f);
#define NDHA(f,l)	dos_header_object[#f] = MAKE_ARRAY_FIELD(dos_header, f, l);
#include "pe_spec.def"
#define NDH(f)
#define NDHA(f,l)
		return dos_header_object.GetValue();
	}

	static napi_value GetImageFileHeader(napi_env env, napi_callback_info info) {
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 0);
		PECoffAnalysis* analysis = GetWrappedAnalysis(env, cbi.GetHolder());
		PIMAGE_FILE_HEADER file_header = analysis->GetFileHeader();

		NapiArray field_ary = NapiArray(env);
#define NFH(f)		field_ary.Push(MAKE_PRIMITIVE_FIELD(file_header, f));
#include "pe_spec.def"
#define NFH(f)
		return field_ary.GetValue();
	}

	static napi_value GetImageOptionalHeaderX86(napi_env env, ExtractCallbackInfo& cbi) {
		PECoffAnalysis* analysis = GetWrappedAnalysis(env, cbi.GetHolder());
		PIMAGE_OPTIONAL_HEADER32 optional_header =
			reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(analysis->GetOptionalHeader());

		NapiArray field_ary = NapiArray(env);
#define NOH32(f)		field_ary.Push(MAKE_PRIMITIVE_FIELD(optional_header, f));
#include "pe_spec.def"
#define NOH32(f)
		return field_ary.GetValue();
	}

	static napi_value GetImageOptionalHeader(napi_env env, napi_callback_info info) {
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 0);
		PECoffAnalysis* analysis = GetWrappedAnalysis(env, cbi.GetHolder());
		if (!analysis->IsX64()) {
			return GetImageOptionalHeaderX86(env, cbi);
		}
	}

	static napi_value GetImageSectionTable(napi_env env, napi_callback_info info) {
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 0);
		PECoffAnalysis* analysis = GetWrappedAnalysis(env, cbi.GetHolder());
		PESectionTable sec_table = analysis->GetSectionTable();

		NapiArray table_value = NapiArray(env);
		for (auto iter = sec_table.begin();iter != sec_table.end();iter++) {
			PIMAGE_SECTION_HEADER sec_header = *iter;
			char sec_name[9] = { 0 };
			memcpy(sec_name, sec_header->Name, 8);

			NapiObject sec_value = NapiObject(env);
#define NSH(f)		sec_value[#f] = MAKE_PRIMITIVE_FIELD(sec_header, f);
#define NSHA(f, l)	sec_value[#f] = MAKE_ARRAY_FIELD(sec_header, f, l);
#include "pe_spec.def"
#define NSH(f)
#define NSHA(f, l)

			NapiObject(env, sec_value["Name"])["field_value"] = NapiString(env, sec_name).GetValue();
			table_value.Push(sec_value.GetValue());
		}
		return table_value.GetValue();
	}

	static napi_value GetImageImportDirectory(napi_env env, napi_callback_info info) {
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 0);
		PECoffAnalysis* analysis = GetWrappedAnalysis(env, cbi.GetHolder());

		try {
			NapiArray import_table_value = NapiArray(env);
			PECoffImport imports = analysis->GetImportDirectory();
			for (auto import : imports) {
				PIMAGE_IMPORT_DESCRIPTOR import_desc = import.GetNative();
				NapiObject import_value = NapiObject(env);
				import_value["ModuleName"] = NapiString(env, import.GetImportName()).GetValue();
#define NID(f)		import_value[#f] = (MAKE_PRIMITIVE_FIELD(import_desc, f));
#include "pe_spec.def"
#define NID(f)
				import_table_value.Push(import_value.GetValue());
			}
			return import_table_value.GetValue();
		}
		//catch (exception & e) {
		//	NapiObject err = NapiObject(env);
		//	err["errMessage"] = NapiString(env, e.what()).GetValue();
		//	return err.GetValue();
		//}
		catch (...) {
			napi_value null_value;
			CheckNAPI(napi_get_null(env, &null_value));
			return null_value;
		}
	}

	static napi_value TranslateSystemTime(napi_env env, SYSTEMTIME st) {
		NapiObject st_object = NapiObject(env);
		st_object["year"] = NapiPrimitive(env, st.wYear).GetValue();
		st_object["month"] = NapiPrimitive(env, st.wMonth).GetValue();
		st_object["day"] = NapiPrimitive(env, st.wDay).GetValue();
		st_object["hour"] = NapiPrimitive(env, st.wHour).GetValue();
		st_object["minute"] = NapiPrimitive(env, st.wMinute).GetValue();
		st_object["second"] = NapiPrimitive(env, st.wSecond).GetValue();
		return st_object.GetValue();
	}

	static napi_value GetImagePEAttributes(napi_env env, napi_callback_info info) {
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 0);
		PECoffAnalysis* analysis = GetWrappedAnalysis(env, cbi.GetHolder());

		NapiObject attr_object = NapiObject(env);
		attr_object["x64"] = NapiPrimitive(env, analysis->IsX64()).GetValue();
		attr_object["file_align"] = NapiOriginal(env, analysis->GetFileAlignment()).GetValue();
		attr_object["sec_align"] = NapiOriginal(env, analysis->GetSectionAlignment()).GetValue();
		attr_object["machine"] = NapiOriginal(env, analysis->GetFileHeader()->Machine).GetValue();
		attr_object["size_of_image"] = NapiOriginal(env, analysis->GetSizeOfImage()).GetValue();
		attr_object["image_base"] = NapiOriginal(env, analysis->GetImageBase()).GetValue();
		attr_object["entry_point"] = NapiOriginal(env, analysis->GetAddressOfEntryPoint()).GetValue();
		return attr_object.GetValue();
	}

	static napi_value GetImageFileAttributes(napi_env env, napi_callback_info info) {
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 0);
		PECoffAnalysis* analysis = GetWrappedAnalysis(env, cbi.GetHolder());
		FileAttr attr = FileAttr(analysis->GetFileHanlde());

		NapiObject attr_object = NapiObject(env);
		attr_object["name"] = NapiString(env, attr.GetFileName()).GetValue();
		attr_object["creation_time"] = TranslateSystemTime(env, attr.GetCreationTime<SYSTEMTIME>());
		attr_object["last_read"] = TranslateSystemTime(env, attr.GetLastAccessTime<SYSTEMTIME>());
		attr_object["last_write"] = TranslateSystemTime(env, attr.GetLastWriteTime<SYSTEMTIME>());
		// FIXME: 用native
		attr_object["allocation_size"] = NapiPrimitive(
			env, (int64_t)(attr.GetAllocationSize().QuadPart / 1024)).GetValue();
		attr_object["file_size"] = NapiPrimitive(
			env, (int64_t)(attr.GetEndOfFile().QuadPart / 1024)).GetValue();

		return attr_object.GetValue();
	}

	static napi_value GetImageExportDirectory(napi_env env, napi_callback_info info) {
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 0);
		PECoffAnalysis* analysis = GetWrappedAnalysis(env, cbi.GetHolder());
		
		try {
			PECoffExport export_dir = analysis->GetExportDirectory();
			NapiObject export_object = NapiObject(env);

			// 创建native对象
			NapiObject native_object = NapiObject(env);
#define NED(f)		native_object[#f] = (MAKE_PRIMITIVE_FIELD(export_dir.GetNative(), f));
#include "pe_spec.def"
#define NED(f)
			export_object["native"] = native_object.GetValue();

			// 导出名
			export_object["name"] = NapiString(env, string(export_dir.GetExportName())).GetValue();

			// 创建导出列表数组对象
			NapiArray export_items = NapiArray(env);
			for (auto item : export_dir) {
				NapiObject item_object = NapiObject(env);
				item_object["Address"] = NapiOriginal(env, item.Rva()).GetValue();
				item_object["Ordinal"] = NapiOriginal(env, item.Ordinal()).GetValue();
				bool hasName = item.Name() != nullptr;
				if (item.IsForwarder()) {
					item_object["Name"] = NapiString(env, string(item.Forwarder())).GetValue();
				}
				else {
					item_object["Name"] = hasName ?
						NapiString(env, item.Name()).GetValue() :
						NapiString(env, string(export_dir.GetExportName()) + ":" + to_string(item.Ordinal())).GetValue();
				}
				export_items.Push(item_object.GetValue());
			}
			export_object["items"] = export_items.GetValue();

			return export_object.GetValue();
		}
		//catch (exception& e) {
		//	NapiObject err = NapiObject(env);
		//	err["errMessage"] = NapiString(env, e.what()).GetValue();
		//	return err.GetValue();
		//}
		catch (...) {
			napi_value null_value;
			CheckNAPI(napi_get_null(env, &null_value));
			return null_value;
		}
	}

	static napi_value CreateAnalysis(napi_env env, napi_callback_info info) {
		char filename_str[256];
		size_t filename_size = 256;
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 1);
		napi_value filename_value = cbi.GetArgIdx(0);
		CheckNAPI(napi_get_value_string_utf8(
			env, filename_value, filename_str, filename_size, &filename_size));

		PECoffAnalysis* analysis = PECoffAnalysis::CreateAnalysis(filename_str);
		CheckPTR(analysis);
		analysis->RunAnalysis();

		napi_value analysis_object;
		CheckNAPI(napi_create_object(env, &analysis_object));
		CheckNAPI(napi_wrap(env, analysis_object, analysis, AnalysisFinalize, nullptr, nullptr));
		CheckNAPI(napi_set_named_property(env, analysis_object,
			"get_dos_header", NapiFunction(env, GetImageDosHeader).GetValue()));
		CheckNAPI(napi_set_named_property(env, analysis_object,
			"get_file_header", NapiFunction(env, GetImageFileHeader).GetValue()));
		CheckNAPI(napi_set_named_property(env, analysis_object,
			"get_section_table", NapiFunction(env, GetImageSectionTable).GetValue()));
		CheckNAPI(napi_set_named_property(env, analysis_object,
			"get_optional_header", NapiFunction(env, GetImageOptionalHeader).GetValue()));
		CheckNAPI(napi_set_named_property(env, analysis_object,
			"get_import_directory", NapiFunction(env, GetImageImportDirectory).GetValue()));
		CheckNAPI(napi_set_named_property(env, analysis_object,
			"get_export_directory", NapiFunction(env, GetImageExportDirectory).GetValue()));
		CheckNAPI(napi_set_named_property(env, analysis_object,
			"get_file_attr", NapiFunction(env, GetImageFileAttributes).GetValue()));
		CheckNAPI(napi_set_named_property(env, analysis_object,
			"get_pe_attr", NapiFunction(env, GetImagePEAttributes).GetValue()));

		return analysis_object;
	}

	napi_value CreatePecoffRootObject(napi_env env) {
		napi_value root;
		CheckNAPI(napi_create_object(env, &root));
		CheckNAPI(napi_set_named_property(
			env, root, "create_analysis", NapiFunction(env, CreateAnalysis).GetValue()));
		return root;
	}

}