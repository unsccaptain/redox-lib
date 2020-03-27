// libpecoff.cpp : 定义静态库的函数。
//

#include <pe_coff.h>

namespace pecoff {

	PESectionTable PECoffAnalysis::GetSectionTable() {
		return PESectionTable(section_header_, file_header_->NumberOfSections);
	}

	PECoffAnalysis* PECoffAnalysis::CreateAnalysis(const string& file) {
		HANDLE file_handle = CreateFile(file.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
		if (file_handle == INVALID_HANDLE_VALUE)
			return nullptr;
		DWORD read_size;
		WORD pe_magic;
		IMAGE_DOS_HEADER dos_header;
		try {
			if (!ReadFile(file_handle, &dos_header, sizeof(IMAGE_DOS_HEADER), &read_size, nullptr))
				throw(exception("read file failed!"));
			if (SetFilePointer(file_handle, dos_header.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER), nullptr, FILE_BEGIN) <= 0)
				throw(exception("read file failed!"));
			if (!ReadFile(file_handle, &pe_magic, 2, &read_size, nullptr))
				throw(exception("read_file_failed"));
		}
		catch (...) {
			CloseHandle(file_handle);
			return nullptr;
		}
		CloseHandle(file_handle);
		if (pe_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
			return new PECoffAnalysisX86(file);
		else if (pe_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			return new PECoffAnalysisAmd64(file);
		else
			return nullptr;
	}

	HANDLE PECoffAnalysis::GetFileHanlde() {
		return osdep_.GetFileHandle();
	}

	PVOID PECoffAnalysis::GetMapBase() {
		return osdep_.GetMapBase();
	}

	DWORD PECoffAnalysis::GetMapSize() {
		return osdep_.GetMappedSize();
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
		pecoff_rva_t import_rva = GetDataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT)->VirtualAddress;
		if (import_rva == 0) {
			throw(exception("No export directory found!"));
		}
		return PECoffImport(
			this, force_cast<PIMAGE_IMPORT_DESCRIPTOR>(TranslateRvaToVa(import_rva)));
	}

	PECoffExport PECoffAnalysis::GetExportDirectory() {
		pecoff_rva_t export_rva = GetDataDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT)->VirtualAddress;
		if (export_rva == 0) {
			throw(exception("No export directory found!"));
		}
		return PECoffExport(
			this, force_cast<PIMAGE_EXPORT_DIRECTORY>(TranslateRvaToVa(export_rva)));
	}

	PECoffDelayImport PECoffAnalysis::GetDelayImportDirectory() {
		pecoff_rva_t delay_import_rva = GetDataDirectory(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)->VirtualAddress;
		if (delay_import_rva == 0) {
			throw(exception("No delay import directory found!"));
		}
		return PECoffDelayImport(
			this, force_cast<PIMAGE_DELAYLOAD_DESCRIPTOR>(TranslateRvaToVa(delay_import_rva)));
	}

	PECoffResource PECoffAnalysis::GetResourceDirectory() {
		pecoff_rva_t res_rva = GetDataDirectory(IMAGE_DIRECTORY_ENTRY_RESOURCE)->VirtualAddress;
		if (res_rva == 0) {
			throw(exception("No delay import directory found!"));
		}
		return PECoffResource(
			this, force_cast<PIMAGE_RESOURCE_DIRECTORY>(TranslateRvaToVa(res_rva)));
	}

	PECoffDebug PECoffAnalysis::GetDebugDirectory() {
		pecoff_rva_t res_rva = GetDataDirectory(IMAGE_DIRECTORY_ENTRY_DEBUG)->VirtualAddress;
		if (res_rva == 0) {
			throw(exception("No debug directory found!"));
		}
		return PECoffDebug(
			GetDataDirectory(IMAGE_DIRECTORY_ENTRY_DEBUG),
			force_cast<PIMAGE_DEBUG_DIRECTORY>(TranslateRvaToVa(res_rva))
		);
	}

	PECoffReloc PECoffAnalysis::GetRelocDirectory() {
		PIMAGE_DATA_DIRECTORY reloc_dir = GetDataDirectory(IMAGE_DIRECTORY_ENTRY_BASERELOC);
		if (reloc_dir->VirtualAddress == 0) {
			throw(exception("No reloc directory found!"));
		}
		return PECoffReloc(this, reloc_dir);
	}

	pecoff_off_t PECoffAnalysis::TranslateRvaToOffset(pecoff_rva_t rva) {
		assert(rva <= GetSizeOfImage());
		PESectionTable sec_table = GetSectionTable();
		for (auto sec_header : sec_table) {
			if (sec_header->VirtualAddress <= rva &&
				(rva <= (sec_header->VirtualAddress + sec_header->Misc.VirtualSize))) {
				return rva - sec_header->VirtualAddress + sec_header->PointerToRawData;
			}
		}
		return 0;
	}

	PVOID PECoffAnalysis::TranslateRvaToVa(pecoff_rva_t rva) {
		return force_cast<void*>((BYTE*)osdep_.GetMapBase() + TranslateRvaToOffset(rva));
	}

	DWORD PECoffAnalysis::WhichDirectory(pecoff_rva_t rva) {
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

	/**
	 * @brief 根据RVA获取对应的节
	 * @return rva在某个节中，返回PIMAGE_SECTION_HEADER
	 * @return 如果rva不会被map，返回nullptr 
	 */
	PIMAGE_SECTION_HEADER PECoffAnalysis::WhichSection(pecoff_rva_t rva) {
		assert(rva <= GetSizeOfImage());
		PESectionTable sec_table = GetSectionTable();
		for (auto sec_header : sec_table) {
			if (sec_header->VirtualAddress <= rva &&
				(rva <= (sec_header->VirtualAddress + sec_header->Misc.VirtualSize))) {
				return sec_header;
			}
		}
		return nullptr;
	}

	DWORD PECoffAnalysisX86::GetThunkCount(PVOID thunk_array) {
		DWORD count = 0;
		PIMAGE_THUNK_DATA32 thunk = force_cast<PIMAGE_THUNK_DATA32>(thunk_array);
		while (thunk[count].u1.Ordinal != 0) count++;
		return count;
	}

	DWORD PECoffAnalysisAmd64::GetThunkCount(PVOID thunk_array) {
		DWORD count = 0;
		PIMAGE_THUNK_DATA64 thunk = force_cast<PIMAGE_THUNK_DATA64>(thunk_array);
		while (thunk[count].u1.Ordinal != 0) count++;
		return count;
	}

}