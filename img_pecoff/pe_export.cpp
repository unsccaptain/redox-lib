
#include "pe_export.h"
#include "pe_coff.h"

namespace pecoff {

	pecoff_str_t PECoffExport::GetExportName() {
		return force_cast<pecoff_str_t>(analysis_->TranslateRvaToVa(export_dir_->Name));
	}

	PECoffExport::PECoffExport(PECoffAnalysis* analysis, PIMAGE_EXPORT_DIRECTORY export_dir)
		:analysis_(analysis), export_dir_(export_dir) {
		PDWORD addr_table = force_cast<PDWORD>(analysis_->TranslateRvaToVa(export_dir_->AddressOfFunctions));
		PDWORD name_table = force_cast<PDWORD>(analysis_->TranslateRvaToVa(export_dir_->AddressOfNames));
		PWORD ordinal_table = force_cast<PWORD>(analysis_->TranslateRvaToVa(export_dir_->AddressOfNameOrdinals));
		// 第一遍扫描，将所有函数地址保存起来
		for (uint16_t i = 0;i < export_dir_->NumberOfFunctions;i++) {
			// pecoff_v83: If the address specified is not within the export section, the
			// field is an export AVA, which is an actual address in code or data.
			DWORD data_dir = analysis_->WhichDirectory(addr_table[i]);
			export_entries_.push_back(PECoffExportEntry(
				addr_table[i],
				analysis_->TranslateRvaToVa(addr_table[i]),
				(uint16_t)(export_dir_->Base + i),
				data_dir == IMAGE_DIRECTORY_ENTRY_EXPORT));
		}
		// 第二遍扫描，将函数名字赋给地址
		for (unsigned i = 0;i < export_dir_->NumberOfNames;i++) {
			pecoff_ordinal_t ordinal = ordinal_table[i];
			pecoff_str_t name = force_cast<const char*>(analysis_->TranslateRvaToVa(name_table[i]));
			// TODO：需要考虑下是否需要上报这种异常情况
			if (ordinal < export_dir_->Base) continue;
			export_entries_[ordinal - export_dir_->Base].name_ = name;
		}
	}

}