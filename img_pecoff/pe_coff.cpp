// libpecoff.cpp : 定义静态库的函数。
//

#include <pe_coff.h>
#include <pe_import.h>
#include <pe_export.h>

namespace pecoff {

	PESectionTable PECoffAnalysis::GetSectionTable() {
		return PESectionTable(section_header_, file_header_->NumberOfSections);
	}

	PECoffAnalysis* PECoffAnalysis::CreateAnalysis(const string& file) {
		PECoffAnalysisX86* analysis = new PECoffAnalysisX86(file);
		return analysis;
	}

	void PECoffAnalysis::GenerateAnalysis() {
		void* base = osdep_.GetMapBase();
		dos_header_ = force_cast<PIMAGE_DOS_HEADER>(base);
		pe_magic_ = force_cast<PULONG>((BYTE*)base + dos_header_->e_lfanew);
		file_header_ = force_cast<PIMAGE_FILE_HEADER>((BYTE*)base + 4 + dos_header_->e_lfanew);
		HandleOptionalHeader();
		section_header_ =
			force_cast<PIMAGE_SECTION_HEADER>((BYTE*)(file_header_ + 1) + file_header_->SizeOfOptionalHeader);
	}

	PECoffImport PECoffAnalysis::GetImportDirectory() {
		DWORD import_rva = GetDataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT)->VirtualAddress;
		if (import_rva == 0) {
			throw(exception("No export directory found!"));
		}
		return PECoffImport(this, force_cast<PIMAGE_IMPORT_DESCRIPTOR>(TranslateRvaToVa(import_rva)));
	}

	PECoffExport PECoffAnalysis::GetExportDirectory() {
		DWORD export_rva = GetDataDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT)->VirtualAddress;
		if (export_rva == 0) {
			throw(exception("No export directory found!"));
		}
		return PECoffExport(this, force_cast<PIMAGE_EXPORT_DIRECTORY>(TranslateRvaToVa(export_rva)));
	}

	DWORD PECoffAnalysis::TranslateRvaToOffset(uint32_t rva) {
		PESectionTable sec_table = GetSectionTable();
		for (auto sec_header : sec_table) {
			if (sec_header->VirtualAddress <= rva &&
				(rva <= (sec_header->VirtualAddress + sec_header->Misc.VirtualSize))) {
				return rva - sec_header->VirtualAddress + sec_header->PointerToRawData;
			}
		}
		return 0;
	}

	PVOID PECoffAnalysis::TranslateRvaToVa(uint32_t rva) {
		return force_cast<void*>((BYTE*)osdep_.GetMapBase() + TranslateRvaToOffset(rva));
	}

	DWORD PECoffAnalysis::WhichDirectory(uint32_t rva) {
		PIMAGE_DATA_DIRECTORY data_dir = GetDataDirectory(0);
		for (unsigned i = 0;i < GetNumberOfDirectories();i++) {
			if (data_dir->VirtualAddress == 0)
				continue;
			if (rva >= data_dir->VirtualAddress && rva <= data_dir->VirtualAddress + data_dir->Size)
				return i;
			data_dir++;
		}
		return (DWORD)-1;
	}

	DWORD PECoffAnalysisX86::GetThunkCount(void* thunk_array) {
		DWORD count = 0;
		PIMAGE_THUNK_DATA32 thunk = force_cast<PIMAGE_THUNK_DATA32>(thunk_array);
		while (thunk[count].u1.Ordinal != 0) {
			count++;
		}
		return count;
	}

}