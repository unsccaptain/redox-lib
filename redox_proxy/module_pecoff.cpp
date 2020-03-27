
#include "framework.h"
#include "module_pecoff.h"
#include "attribute_mgr.h"
#include "napi_handler.h"
#include "napi_extend.h"

#include <pe_coff.h>
#include <pe_import.h>
#include <pe_export.h>
#include <pe_delay_import.h>
#include <pe_reloc.h>
#include <pe_resource.h>
#include <redox_utils.h>
#include <sstream>
#include <time.h>
#include <functional>

namespace pecoff {
	using namespace redox;

	class RedoxPeInstance {
	public:
		RedoxPeInstance(PECoffAnalysis* analysis)
			:analysis_(analysis) {
		}

		PECoffAnalysis* GetAnalysis() { return analysis_; }

		AttributeManager& GetAttrManager() { return attr_mgr_; }

		AttributeDomain::composite_attr_list GetCompositeAttr(const string& domain, uint64_t attr, bool all = true) {
			return attr_mgr_.GetCompositeAttr(domain, attr, all);
		}

		AttributeDomain::exclusive_attr_item GetExclusiveAttr(const string& domain, uint64_t attr) {
			return attr_mgr_.GetExclusiveAttr(domain, attr);
		}

	private:
		PECoffAnalysis* analysis_;
		AttributeManager attr_mgr_;
	};

	/**
	 * @brief 释放文件映射和文件句柄
	 */
	static void AnalysisFinalize(napi_env env, void* finalize_data, void* finalize_hint) {
		RedoxPeInstance* inst = force_cast<RedoxPeInstance*>(finalize_data);
		delete inst->GetAnalysis();
		delete inst;
	}

	static RedoxPeInstance* GetInstance(napi_env env, napi_value value) {
		void* wrapped;
		CheckNAPI(napi_unwrap(env, value, &wrapped));
		return static_cast<RedoxPeInstance*>(wrapped);
	}

	static napi_value CreateSystemTimeReadableObject(napi_env env, const SYSTEMTIME& st) {
		NapiObject st_object = NapiObject(env);
		st_object["year"] = NapiPrimitive(env, st.wYear).GetValue();
		st_object["month"] = NapiPrimitive(env, st.wMonth).GetValue();
		st_object["day"] = NapiPrimitive(env, st.wDay).GetValue();
		st_object["hour"] = NapiPrimitive(env, st.wHour).GetValue();
		st_object["minute"] = NapiPrimitive(env, st.wMinute).GetValue();
		st_object["second"] = NapiPrimitive(env, st.wSecond).GetValue();
		return st_object.GetValue();
	}

	static napi_value CreateTimestampReadableObject(napi_env env, uint32_t ts) {
		tm time;
		errno_t no = (_localtime32_s(&time, (const __time32_t*)&ts));
		NapiObject st_object = NapiObject(env);
		st_object["year"] = NapiPrimitive(env, time.tm_year).GetValue();
		st_object["month"] = NapiPrimitive(env, time.tm_mon).GetValue();
		st_object["day"] = NapiPrimitive(env, time.tm_mday).GetValue();
		st_object["hour"] = NapiPrimitive(env, time.tm_hour).GetValue();
		st_object["minute"] = NapiPrimitive(env, time.tm_min).GetValue();
		st_object["second"] = NapiPrimitive(env, time.tm_sec).GetValue();
		return st_object.GetValue();
	}

	static napi_value CreateAttrListObject(napi_env env, const AttributeList& list) {
		NapiArray attr_list = NapiArray(env);
		for (auto attr : list) {
			NapiObject attr_entry = NapiObject(env);
			attr_entry["name"] = NapiString(env, attr.AttrName).GetValue();
			// 在PE的场景中，不会有64位的常量
			attr_entry["value"] = NapiPrimitive(env, (uint32_t)attr.AttrValue).GetValue();
			attr_entry["enabled"] = NapiPrimitive(env, attr.Enabled).GetValue();
			attr_list.Push(attr_entry.GetValue());
		}
		return attr_list.GetValue();
	}

	static napi_value GetImageDosHeader(napi_env env, napi_callback_info info) {
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 0);
		RedoxPeInstance* inst = GetInstance(env, cbi.GetHolder());
		PIMAGE_DOS_HEADER dos_header = inst->GetAnalysis()->GetDosHeader();
		CheckPTR(dos_header);

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
		RedoxPeInstance* inst = GetInstance(env, cbi.GetHolder());
		PIMAGE_FILE_HEADER file_header = inst->GetAnalysis()->GetFileHeader();
		CheckPTR(file_header);

		NapiObject object = NapiObject(env);
#define NFH(f)		object[#f] = MAKE_PRIMITIVE_FIELD(file_header, f);
#include "pe_spec.def"
#define NFH(f)
		auto attr = inst->GetExclusiveAttr("FileHeaderMachine", file_header->Machine);
		object["Machine"]["additional"] = NapiString(env, attr.second).GetValue();
		object["TimeDateStamp"]["additional"] = CreateTimestampReadableObject(
			env, file_header->TimeDateStamp);

		NapiObject characteristics = NapiObject(env, MAKE_PRIMITIVE_FIELD(file_header, Characteristics));
		characteristics["attr_list"] = CreateAttrListObject(env,
			inst->GetCompositeAttr("FileHeaderCharacteristics", file_header->Characteristics, false));

		object["Characteristics"] = characteristics.GetValue();
		return object.GetValue();
	}

	static napi_value CreateDataDirObject(napi_env env, IMAGE_DATA_DIRECTORY* first) {
		auto entry_object = [env](IMAGE_DATA_DIRECTORY* entry)->napi_value {
			NapiObject object = NapiObject(env);
			object["VirtualAddress"] = MAKE_PRIMITIVE_FIELD(entry, VirtualAddress);
			object["Size"] = MAKE_PRIMITIVE_FIELD(entry, Size);
			return object.GetValue();
		};

		NapiObject data_dirs = NapiObject(env);
		data_dirs["IMAGE_DIRECTORY_ENTRY_EXPORT"] = entry_object(first);
		data_dirs["IMAGE_DIRECTORY_ENTRY_IMPORT"] = entry_object(first + 1);
		data_dirs["IMAGE_DIRECTORY_ENTRY_RESOURCE"] = entry_object(first + 2);
		data_dirs["IMAGE_DIRECTORY_ENTRY_EXCEPTION"] = entry_object(first + 3);
		data_dirs["IMAGE_DIRECTORY_ENTRY_SECURITY"] = entry_object(first + 4);
		data_dirs["IMAGE_DIRECTORY_ENTRY_BASERELOC"] = entry_object(first + 5);
		data_dirs["IMAGE_DIRECTORY_ENTRY_DEBUG"] = entry_object(first + 6);
		data_dirs["IMAGE_DIRECTORY_ENTRY_ARCHITECTURE"] = entry_object(first + 7);
		data_dirs["IMAGE_DIRECTORY_ENTRY_GLOBALPTR"] = entry_object(first + 8);
		data_dirs["IMAGE_DIRECTORY_ENTRY_TLS"] = entry_object(first + 9);
		data_dirs["IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"] = entry_object(first + 10);
		data_dirs["IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT"] = entry_object(first + 11);
		data_dirs["IMAGE_DIRECTORY_ENTRY_IAT"] = entry_object(first + 12);
		data_dirs["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"] = entry_object(first + 13);
		data_dirs["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"] = entry_object(first + 14);

		return data_dirs.GetValue();
	}

	static napi_value GetImageOptionalHeaderX86(napi_env env, ExtractCallbackInfo& cbi) {
		RedoxPeInstance* inst = GetInstance(env, cbi.GetHolder());
		PIMAGE_OPTIONAL_HEADER32 optional_header =
			reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(inst->GetAnalysis()->GetOptionalHeader());

		NapiObject object = NapiObject(env);
		NapiObject native_object = NapiObject(env);
#define NOH32(f)		native_object[#f] = (MAKE_PRIMITIVE_FIELD(optional_header, f));
#include "pe_spec.def"
#define NOH32(f)

		native_object["Subsystem"]["additional_text"] = NapiString(env,
			inst->GetExclusiveAttr("OptSubsystem", optional_header->Subsystem).second).GetValue();
		native_object["DllCharacteristics"]["additional_attr"] = CreateAttrListObject(env,
			inst->GetCompositeAttr("OptCharacteristics", optional_header->DllCharacteristics, false));

		object["native"] = native_object.GetValue();
		object["data_dirs"] = CreateDataDirObject(env, optional_header->DataDirectory);
		return object.GetValue();
	}

	static napi_value GetImageOptionalHeaderAmd64(napi_env env, ExtractCallbackInfo& cbi) {
		RedoxPeInstance* inst = GetInstance(env, cbi.GetHolder());
		PIMAGE_OPTIONAL_HEADER64 optional_header =
			reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(inst->GetAnalysis()->GetOptionalHeader());

		NapiObject object = NapiObject(env);
		NapiObject native_object = NapiObject(env);
#define NOH64(f)		native_object[#f] = (MAKE_PRIMITIVE_FIELD(optional_header, f));
#include "pe_spec.def"
#define NOH64(f)

		native_object["Subsystem"]["additional"] = NapiString(env,
			inst->GetExclusiveAttr("OptSubsystem", optional_header->Subsystem).second).GetValue();
		native_object["DllCharacteristics"]["additional"] = CreateAttrListObject(env,
			inst->GetCompositeAttr("OptCharacteristics", optional_header->DllCharacteristics, false));

		object["native"] = native_object.GetValue();
		object["data_dirs"] = CreateDataDirObject(env, optional_header->DataDirectory);
		return object.GetValue();
	}

	static napi_value GetImageOptionalHeader(napi_env env, napi_callback_info info) {
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 0);
		RedoxPeInstance* inst = GetInstance(env, cbi.GetHolder());
		if (!inst->GetAnalysis()->IsX64())
			return GetImageOptionalHeaderX86(env, cbi);
		else
			return GetImageOptionalHeaderAmd64(env, cbi);
	}

	/**
	 * @brief 将叶结点转换为JS对象，进入这个函数后，kind始终是leaf
	 */
	napi_value CreateResourceLeafObject(napi_env env, const PECoffResourceNode& node) {
		NapiObject leaf_object = NapiObject(env);
		PECoffResourceNode::NodeIdentifier identifier = node.GetIdentifier();
		leaf_object["is_name"] = NapiPrimitive(env, identifier.is_name).GetValue();

		if (identifier.is_name)
			leaf_object["name"] = NapiString(env, identifier.name).GetValue();
		else
			leaf_object["id"] = NapiPrimitive(env, identifier.id).GetValue();

		leaf_object["kind"] = NapiString(env, "leaf").GetValue();

		leaf_object["data_rva"] = NapiPrimitive(env, node.GetResourceData().GetData()).GetValue();
		leaf_object["data_size"] = NapiPrimitive(env, node.GetResourceData().GetSize()).GetValue();
		leaf_object["code_page"] = NapiPrimitive(env, node.GetResourceData().GetCodePage()).GetValue();

		return leaf_object.GetValue();
	}

	/**
	 * @brief 将非叶结点转换为JS对象，进入这个函数后，kind始终是branch
	 */
	napi_value CreateResourceLevelObject(napi_env env, const PECoffResourceNode& node) {
		NapiObject level_object = NapiObject(env);
		PECoffResourceNode::NodeIdentifier identifier = node.GetIdentifier();
		level_object["is_name"] = NapiPrimitive(env, identifier.is_name).GetValue();

		if (identifier.is_name)
			level_object["name"] = NapiString(env, identifier.name).GetValue();
		else
			level_object["id"] = NapiPrimitive(env, identifier.id).GetValue();

		level_object["kind"] = NapiString(env, "branch").GetValue();

		NapiArray child_object = NapiArray(env);
		for (auto& child : node) {
			if (child.IsLeaf())
				child_object.Push(CreateResourceLeafObject(env, child));
			else
				child_object.Push(CreateResourceLevelObject(env, child));
		}
		level_object["children"] = child_object.GetValue();

		return level_object.GetValue();
	}

	/**
	 * @brief 生成资源目录对象，其中包含了一个N叉树
	 */
	static napi_value GetImageResourceDirectory(napi_env env, napi_callback_info info) {
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 0);
		RedoxPeInstance* inst = GetInstance(env, cbi.GetHolder());

		try {
			PECoffResource res = inst->GetAnalysis()->GetResourceDirectory();
			return CreateResourceLevelObject(env, res.GetTreeRoot());
		}
		catch (...) {
			napi_value null_object;
			CheckNAPI(napi_get_null(env, &null_object));
			return null_object;
		}
	}

	static napi_value GetImageSectionTable(napi_env env, napi_callback_info info) {
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 0);
		RedoxPeInstance* inst = GetInstance(env, cbi.GetHolder());
		PESectionTable sec_table = inst->GetAnalysis()->GetSectionTable();

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
			sec_value["Characteristics"]["attr_list"] = CreateAttrListObject(env,
				inst->GetAttrManager().GetCompositeAttr("SectionHeaderCharacteristics", sec_header->Characteristics));
			sec_value["Name"]["field_value"] = NapiString(env, sec_name).GetValue();
			table_value.Push(sec_value.GetValue());
		}
		return table_value.GetValue();
	}

	static napi_value GetImageImportListByIndex(napi_env env, napi_callback_info info) {
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 1);
		RedoxPeInstance* inst = GetInstance(env, cbi.GetHolder());

		uint32_t index = NapiPrimitive(env, cbi.GetArgIdx(0)).GetPrimitive();
		try {
			NapiObject return_object = NapiObject(env);
			NapiArray import_list = NapiArray(env);

			PECoffImport imports = inst->GetAnalysis()->GetImportDirectory();
			PECoffImportEntry entry = imports[index];
			for (auto thunk : entry) {
				NapiObject thunk_object = NapiObject(env);
				if (thunk.GetKind() == PECoffImportThunk::ThunkKind::Ordinal) {
					thunk_object["kind"] = NapiString(env, "Ordinal").GetValue();
					thunk_object["ordinal"] = NapiPrimitive(env, (uint32_t)thunk.GetOrdinal()).GetValue();
				}
				else if (thunk.GetKind() == PECoffImportThunk::ThunkKind::NameDescriptor) {
					thunk_object["kind"] = NapiString(env, "Name").GetValue();
					thunk_object["hint"] = NapiNative(env, thunk.GetNameDescriptor()->Hint).GetValue();
					thunk_object["name"] = NapiString(env, thunk.GetNameDescriptor()->Name).GetValue();
				}
				import_list.Push(thunk_object.GetValue());
			}
			return_object["thunk_list"] = import_list.GetValue();
			return_object["import_name"] = NapiString(env, entry.GetImportName()).GetValue();
			return return_object.GetValue();
		}
		catch (...) {
			napi_value null_object;
			CheckNAPI(napi_get_null(env, &null_object));
			return null_object;
		}
	}

	static void ExternalFinalize(napi_env env, void* finalize_data, void* finalize_hint) {
	}

	static napi_value ReadMappedBinaryDataOffset(napi_env env, napi_callback_info info) {
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 2);
		RedoxPeInstance* inst = GetInstance(env, cbi.GetHolder());

		try {
			uint32_t offset = NapiPrimitive(env, cbi.GetArgIdx(0)).GetPrimitive();
			uint32_t size = NapiPrimitive(env, cbi.GetArgIdx(1)).GetPrimitive();
			BYTE* read_start = (BYTE*)inst->GetAnalysis()->GetMapBase() + offset;
			napi_value value;
			CheckNAPI(napi_create_external_arraybuffer(env, read_start, size, ExternalFinalize, inst, &value));
			return value;
		}
		catch (...) {
			napi_value null_object;
			CheckNAPI(napi_get_null(env, &null_object));
			return null_object;
		}
	}

	static napi_value ReadMappedBinaryDataRva(napi_env env, napi_callback_info info) {
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 2);
		RedoxPeInstance* inst = GetInstance(env, cbi.GetHolder());
		napi_value value;

		try {
			pecoff_rva_t rva = NapiPrimitive(env, cbi.GetArgIdx(0)).GetPrimitive();
			uint32_t size = NapiPrimitive(env, cbi.GetArgIdx(1)).GetPrimitive();
			if (inst->GetAnalysis()->TranslateRvaToOffset(rva) == 0) {
				BYTE* buffer;
				CheckNAPI(napi_create_arraybuffer(env, size, (void**)&buffer, &value));
				//** 用?填充不可映射的区域 */
				memset(buffer, 0, size);
				return value;
			}
			BYTE* read_start = (BYTE*)inst->GetAnalysis()->GetMapBase() +
				inst->GetAnalysis()->TranslateRvaToOffset(rva);
			CheckNAPI(napi_create_external_arraybuffer(env, read_start, size, ExternalFinalize, inst, &value));
			return value;
		}
		catch (...) {
			napi_value null_object;
			CheckNAPI(napi_get_null(env, &null_object));
			return null_object;
		}
	}

	static napi_value GetImageDelayImportListByIndex(napi_env env, napi_callback_info info) {
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 1);
		RedoxPeInstance* inst = GetInstance(env, cbi.GetHolder());

		uint32_t index = NapiPrimitive(env, cbi.GetArgIdx(0)).GetPrimitive();
		try {
			NapiObject return_object = NapiObject(env);
			NapiArray import_list = NapiArray(env);

			PECoffDelayImport imports = inst->GetAnalysis()->GetDelayImportDirectory();
			PECoffDelayImportEntry entry = imports[index];
			for (auto thunk : entry) {
				NapiObject thunk_object = NapiObject(env);
				if (thunk.GetKind() == PECoffImportThunk::ThunkKind::Ordinal) {
					thunk_object["kind"] = NapiString(env, "Ordinal").GetValue();
					thunk_object["ordinal"] = NapiPrimitive(env, (uint32_t)thunk.GetOrdinal()).GetValue();
				}
				else if (thunk.GetKind() == PECoffImportThunk::ThunkKind::NameDescriptor) {
					thunk_object["kind"] = NapiString(env, "Name").GetValue();
					thunk_object["hint"] = NapiNative(env, thunk.GetNameDescriptor()->Hint).GetValue();
					thunk_object["name"] = NapiString(env, thunk.GetNameDescriptor()->Name).GetValue();
				}
				thunk_object["address_rva"] = NapiNative(env, thunk.GetAddressRva()).GetValue();
				import_list.Push(thunk_object.GetValue());
			}
			return_object["thunk_list"] = import_list.GetValue();
			return_object["import_name"] = NapiString(env, entry.GetName()).GetValue();
			return return_object.GetValue();
		}
		catch (...) {
			napi_value null_object;
			CheckNAPI(napi_get_null(env, &null_object));
			return null_object;
		}
	}

	static napi_value GeImageDelayImportDirectory(napi_env env, napi_callback_info info) {
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 0);
		RedoxPeInstance* inst = GetInstance(env, cbi.GetHolder());

		try {
			NapiArray import_table_value = NapiArray(env);
			PECoffDelayImport imports = inst->GetAnalysis()->GetDelayImportDirectory();
			for (auto import : imports) {
				PIMAGE_DELAYLOAD_DESCRIPTOR import_desc = import.GetNative();
				NapiObject import_value = NapiObject(env);
				import_value["ModuleName"] = NapiString(env, import.GetName()).GetValue();
#define NDID(f)		import_value[#f] = (MAKE_PRIMITIVE_FIELD(import_desc, f));
#include "pe_spec.def"
#define NDID(f)
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

	static napi_value GetImageImportDirectory(napi_env env, napi_callback_info info) {
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 0);
		RedoxPeInstance* inst = GetInstance(env, cbi.GetHolder());

		try {
			NapiArray import_table_value = NapiArray(env);
			PECoffImport imports = inst->GetAnalysis()->GetImportDirectory();
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

	static napi_value GetImageDebugDirectory(napi_env env, napi_callback_info info) {
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 0);
		RedoxPeInstance* inst = GetInstance(env, cbi.GetHolder());

		try {
			NapiArray debug_array = NapiArray(env);
			PECoffDebug debug = inst->GetAnalysis()->GetDebugDirectory();

			for (const PIMAGE_DEBUG_DIRECTORY& dir : debug) {
				NapiObject debug_value = NapiObject(env);
#define NDD(f)		debug_value[#f] = (MAKE_PRIMITIVE_FIELD(dir, f));
#include "pe_spec.def"
#define NDD(f)
				debug_array.Push(debug_value.GetValue());
			}
			return debug_array.GetValue();
		}
		catch (...) {
			napi_value null_value;
			CheckNAPI(napi_get_null(env, &null_value));
			return null_value;
		}
	}

	static napi_value GetImageRelocDirectory(napi_env env, napi_callback_info info) {
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 0);
		RedoxPeInstance* inst = GetInstance(env, cbi.GetHolder());

		try {
			NapiArray reloc_array = NapiArray(env);
			PECoffReloc reloc = inst->GetAnalysis()->GetRelocDirectory();

			for (const PECoffReloc4KThunk& thunk : reloc) {
				NapiObject thunk_object = NapiObject(env);
				thunk_object["base"] = NapiNative(env, thunk.GetNative()->VirtualAddress).GetValue();
				thunk_object["count"] = NapiPrimitive(env, (uint32_t)thunk.size()).GetValue();

				NapiArray item_array = NapiArray(env);
				for (auto& item : thunk) {
					NapiObject item_object = NapiObject(env);
					item_object["address_rva"] = NapiNative(env, item.rva).GetValue();

					auto attr = inst->GetExclusiveAttr("BaseReloc", item.flags);
					item_object["flag"] = NapiString(env, attr.second).GetValue();
					item_array.Push(item_object.GetValue());
				}
				thunk_object["list"] = item_array.GetValue();

				reloc_array.Push(thunk_object.GetValue());
			}
			return reloc_array.GetValue();
		}
		catch (...) {
			napi_value null_value;
			CheckNAPI(napi_get_null(env, &null_value));
			return null_value;
		}
	}

	/** 将一个RVA转换为FileOffset */
	static napi_value ImageRvaToFileOffset(napi_env env, napi_callback_info info) {
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 0);
		RedoxPeInstance* inst = GetInstance(env, cbi.GetHolder());

		try {
			pecoff_rva_t rva = NapiPrimitive(env, cbi.GetArgIdx(0)).GetPrimitive();
			return NapiPrimitive(env, inst->GetAnalysis()->TranslateRvaToOffset(rva)).GetValue();
		}
		catch (...) {
			assert(false);
			return 0;
		}
	}

	static napi_value GetImagePEAttributes(napi_env env, napi_callback_info info) {
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 0);
		RedoxPeInstance* inst = GetInstance(env, cbi.GetHolder());
		PECoffAnalysis* analysis = inst->GetAnalysis();

		NapiObject attr_object = NapiObject(env);
		attr_object["x64"] = NapiPrimitive(env, analysis->IsX64()).GetValue();
		attr_object["file_align"] = NapiNative(env, analysis->GetFileAlignment()).GetValue();
		attr_object["sec_align"] = NapiNative(env, analysis->GetSectionAlignment()).GetValue();
		attr_object["machine"] = NapiNative(env, analysis->GetFileHeader()->Machine).GetValue();
		attr_object["size_of_image"] = NapiNative(env, analysis->GetSizeOfImage()).GetValue();
		attr_object["image_base"] = NapiNative(env, analysis->GetImageBase()).GetValue();
		attr_object["entry_point"] = NapiNative(env, analysis->GetAddressOfEntryPoint()).GetValue();
		return attr_object.GetValue();
	}

	static napi_value GetImageFileAttributes(napi_env env, napi_callback_info info) {
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 0);
		RedoxPeInstance* inst = GetInstance(env, cbi.GetHolder());
		FileAttr attr = FileAttr(inst->GetAnalysis()->GetFileHanlde());

		NapiObject attr_object = NapiObject(env);
		attr_object["name"] = NapiString(env, attr.GetFileName()).GetValue();
		attr_object["creation_time"] = CreateSystemTimeReadableObject(env, attr.GetCreationTime<SYSTEMTIME>());
		attr_object["last_read"] = CreateSystemTimeReadableObject(env, attr.GetLastAccessTime<SYSTEMTIME>());
		attr_object["last_write"] = CreateSystemTimeReadableObject(env, attr.GetLastWriteTime<SYSTEMTIME>());
		// FIXME: 用native
		attr_object["allocation_size"] = NapiPrimitive(
			env, (int64_t)(attr.GetAllocationSize().QuadPart / 1024)).GetValue();
		attr_object["file_size"] = NapiPrimitive(
			env, (int64_t)(attr.GetEndOfFile().QuadPart / 1024)).GetValue();

		return attr_object.GetValue();
	}

	/**
	 * @brief 获取rva所属的section名
	 * @return 包含section名称字符串的napi_value
	 */
	static napi_value GetRvaOwnerSection(napi_env env, napi_callback_info info) {
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 1);
		RedoxPeInstance* inst = GetInstance(env, cbi.GetHolder());

		try {
			pecoff_rva_t rva = NapiPrimitive(env, cbi.GetArgIdx(0)).GetPrimitive();
			PIMAGE_SECTION_HEADER sec_header = inst->GetAnalysis()->WhichSection(rva);
			if (sec_header == nullptr) {
				return NapiString(env, "").GetValue();
			}
			char sec_name[9] = { 0 };
			memcpy(sec_name, sec_header->Name, 8);
			return NapiString(env, sec_name).GetValue();
		}
		catch (...) {
			return NapiString(env, "").GetValue();
		}
	}

	static napi_value GetImageExportDirectory(napi_env env, napi_callback_info info) {
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 0);
		RedoxPeInstance* inst = GetInstance(env, cbi.GetHolder());
		PECoffAnalysis* analysis = inst->GetAnalysis();

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
				item_object["Address"] = NapiNative(env, item.Rva()).GetValue();
				item_object["Ordinal"] = NapiNative(env, item.Ordinal()).GetValue();
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

	struct root_binding {
		const char* name;
		napi_callback function;
	};

	static const root_binding bindings[] = {
		{"get_dos_header",						GetImageDosHeader},
		{"get_file_header",						GetImageFileHeader},
		{"get_section_table",					GetImageSectionTable},
		{"get_optional_header",					GetImageOptionalHeader},
		{"get_export_directory",				GetImageExportDirectory},
		{"get_file_attr",						GetImageFileAttributes },
		{"get_pe_attr",							GetImagePEAttributes},
		{"get_import_directory",				GetImageImportDirectory},
		{"get_import_list_by_index",			GetImageImportListByIndex},
		{"get_delay_import_directory",			GeImageDelayImportDirectory},
		{"get_delay_import_list_by_index",		GetImageDelayImportListByIndex},
		{"get_reloc_directory",					GetImageRelocDirectory},
		{"get_resource_directory",				GetImageResourceDirectory},
		{"read_buffer_off",						ReadMappedBinaryDataOffset},
		{"read_buffer_rva",						ReadMappedBinaryDataRva},
		{"rva_to_off",							ImageRvaToFileOffset },
		{"get_debug_directory",					GetImageDebugDirectory},
		{"get_rva_owner",						GetRvaOwnerSection}
	};

	static napi_value CreateAnalysis(napi_env env, napi_callback_info info) {
		char filename_str[256];
		size_t filename_size = 256;
		ExtractCallbackInfo cbi = ExtractCallbackInfo(env, info, 1);
		napi_value filename_value = cbi.GetArgIdx(0);
		napi_status ss = napi_get_value_string_utf8(
			env, filename_value, filename_str, filename_size, &filename_size);

		if (ss != napi_ok) {
			assert(false);
		}

		PECoffAnalysis* analysis = PECoffAnalysis::CreateAnalysis(filename_str);
		CheckPTR(analysis);
		analysis->RunAnalysis();

		RedoxPeInstance* inst = new RedoxPeInstance(analysis);

		napi_value analysis_object;
		CheckNAPI(napi_create_object(env, &analysis_object));
		CheckNAPI(napi_wrap(env, analysis_object, inst, AnalysisFinalize, inst, nullptr));

		for (auto& binding : bindings) {
			CheckNAPI(napi_set_named_property(env, analysis_object,
				binding.name, NapiFunction(env, binding.function).GetValue()));
		}

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