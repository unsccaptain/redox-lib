#pragma once

#include <vector>
#include <map>
#include <assert.h>
#include <string>
#include <cast.h>
#include <pe_common.h>
#include <pe_import.h>
#include <pe_export.h>
#include <pe_delay_import.h>
#include <pe_reloc.h>
#include <pe_resource.h>
#include <os_dep.h>
#include <pe_debug.h>

namespace pecoff {
	using namespace std;

	class PECoffAnalysis;
	class PECoffExport;
	class PECoffImport;
	class PECoffImportEntry;
	class PECoffImportThunk;
	class PECoffDelayImport;
	class PECoffReloc;
	class PECoffResource;
	class PECoffDebug;

	class PESectionTable {
	public:
		using sec_iterator = vector<PIMAGE_SECTION_HEADER>::iterator;

		PESectionTable(PIMAGE_SECTION_HEADER sec, unsigned count) {
			for (unsigned i = 0;i < count;i++) {
				section_table_.push_back(sec + i);
			}
		}

		sec_iterator begin() {
			return section_table_.begin();
		}

		sec_iterator end() {
			return section_table_.end();
		}

		size_t size() {
			return section_table_.size();
		}

	private:
		vector<PIMAGE_SECTION_HEADER> section_table_;
	};

	class PECoffAnalysis {
	public:
		PIMAGE_DOS_HEADER GetDosHeader() { return dos_header_; }

		PIMAGE_FILE_HEADER GetFileHeader() { return file_header_; }

		PVOID GetOptionalHeader() { return file_header_ + 1; }

		virtual PIMAGE_DATA_DIRECTORY GetDataDirectory(unsigned idx) = 0;

		virtual DWORD GetNumberOfDirectories() = 0;
		virtual DWORD GetFileAlignment() = 0;
		virtual DWORD GetSectionAlignment() = 0;
		virtual ULONGLONG GetImageBase() = 0;
		virtual DWORD GetSizeOfImage() = 0;
		virtual DWORD GetAddressOfEntryPoint() = 0;

		PESectionTable GetSectionTable();

		PECoffImport GetImportDirectory();

		PECoffExport GetExportDirectory();

		PECoffDelayImport GetDelayImportDirectory();

		PECoffReloc GetRelocDirectory();

		PECoffResource GetResourceDirectory();

		PECoffDebug GetDebugDirectory();

		DWORD WhichDirectory(pecoff_rva_t rva);

		/**
		 * @brief 根据RVA获取对应的节
		 * @return rva在某个节中，返回PIMAGE_SECTION_HEADER
		 * @return 如果rva不会被map，返回nullptr
		 */
		PIMAGE_SECTION_HEADER WhichSection(pecoff_rva_t rva);

		void RunAnalysis() { GenerateAnalysis(); }

		PVOID GetMapBase();

		DWORD GetMapSize();

		//uint32_t ReadBufferFileOffset(uint32_t offset, uint32_t size, PVOID buffer) {
		//	uint32_t real_size = size;
		//	if (offset + size > osdep_.GetMappedSize()) {
		//		real_size = osdep_.GetMappedSize() - offset;
		//	}
		//	memcpy(buffer,)
		//}

		HANDLE GetFileHanlde();

		bool IsX64() { return x64_; }

		PVOID TranslateRvaToVa(pecoff_rva_t rva);

		pecoff_off_t TranslateRvaToOffset(pecoff_rva_t rva);

		template<class T>
		T* As() {
			dynamic_cast<T*>(this);
		}

		static PECoffAnalysis* CreateAnalysis(const string& file);

	protected:
		OsDependance osdep_;

		bool x64_;

		PECoffAnalysis(const string& file, bool is_x64)
			:x64_(is_x64) {
			osdep_.CreateImageMap(file);
		}

		virtual void HandleOptionalHeader() = 0;

		friend class PECoffImport;
		friend class PECoffExport;
		friend class PECoffImportEntry;
		friend class PECoffImportThunk;
		friend class PECoffDelayImportEntry;
		friend class PECoffReloc4KThunk;
		friend class PECoffReloc;

	private:
		void GenerateAnalysis();

		virtual DWORD GetThunkCount(void* thunk_array) = 0;

	private:
		PULONG pe_magic_ = nullptr;
		PIMAGE_DOS_HEADER dos_header_ = nullptr;
		PIMAGE_FILE_HEADER file_header_ = nullptr;
		PIMAGE_SECTION_HEADER section_header_ = nullptr;
		PIMAGE_IMPORT_DESCRIPTOR import_desc_ = nullptr;
		PIMAGE_EXPORT_DIRECTORY export_dir_ = nullptr;
		PVOID optional_header_ = nullptr;
		DWORD size_of_headers_ = 0;
	};

	class PECoffAnalysisX86 :public PECoffAnalysis {
	public:
		PECoffAnalysisX86(const string& file)
			:PECoffAnalysis(file, false), optional_header_(nullptr) {
		}

		virtual PIMAGE_DATA_DIRECTORY GetDataDirectory(unsigned idx) {
			return optional_header_->DataDirectory + idx;
		}

		virtual DWORD GetNumberOfDirectories() { return optional_header_->NumberOfRvaAndSizes; }
		virtual DWORD GetAddressOfEntryPoint() { return optional_header_->AddressOfEntryPoint; }
		virtual DWORD GetFileAlignment() { return optional_header_->FileAlignment; }
		virtual DWORD GetSectionAlignment() { return optional_header_->SectionAlignment; }
		virtual ULONGLONG GetImageBase() { return optional_header_->ImageBase; }
		virtual DWORD GetSizeOfImage() { return optional_header_->SizeOfImage; }

		virtual void HandleOptionalHeader() {
			optional_header_ = (PIMAGE_OPTIONAL_HEADER32)GetOptionalHeader();
		}

		virtual DWORD GetThunkCount(PVOID thunk_array);

		PIMAGE_OPTIONAL_HEADER32 GetNative() {
			return optional_header_;
		}

	private:
		PIMAGE_OPTIONAL_HEADER32 optional_header_;
	};

	class PECoffAnalysisAmd64 :public PECoffAnalysis {
	public:
		PECoffAnalysisAmd64(const string& file)
			:PECoffAnalysis(file, true), optional_header_(nullptr) {
		}

		virtual PIMAGE_DATA_DIRECTORY GetDataDirectory(unsigned idx) {
			return optional_header_->DataDirectory + idx;
		}

		virtual DWORD GetNumberOfDirectories() { return optional_header_->NumberOfRvaAndSizes; }
		virtual DWORD GetAddressOfEntryPoint() { return optional_header_->AddressOfEntryPoint; }
		virtual DWORD GetFileAlignment() { return optional_header_->FileAlignment; }
		virtual DWORD GetSectionAlignment() { return optional_header_->SectionAlignment; }
		virtual ULONGLONG GetImageBase() { return optional_header_->ImageBase; }
		virtual DWORD GetSizeOfImage() { return optional_header_->SizeOfImage; }

		virtual void HandleOptionalHeader() {
			optional_header_ = (PIMAGE_OPTIONAL_HEADER64)GetOptionalHeader();
		}

		virtual DWORD GetThunkCount(PVOID thunk_array);

		PIMAGE_OPTIONAL_HEADER64 GetNative() {
			return optional_header_;
		}

	private:
		PIMAGE_OPTIONAL_HEADER64 optional_header_;
	};

}