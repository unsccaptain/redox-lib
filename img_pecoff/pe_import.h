#pragma once
#include <Windows.h>

namespace pecoff {

	class PECoffAnalysis;

	class PECoffImportThunk {
	public:
		enum class ThunkKind {
			BoundAddress,
			NameDescriptor,
			Ordinal
		};

		// Ordinal或者AddressOfData
		PECoffImportThunk(PECoffAnalysis* analysis, void* thunk);

		// Function或者ForwarderString
		PECoffImportThunk(PECoffAnalysis* analysis, void* thunk, ThunkKind kind);

		ThunkKind GetKind() { return kind_; }

		uint64_t GetOrdinal();

		PIMAGE_IMPORT_BY_NAME GetNameDescriptor();

	private:
		bool IsOrdinal();

	private:
		union {
			PIMAGE_THUNK_DATA32 thunk32_;
			PIMAGE_THUNK_DATA64 thunk64_;
		};
		ThunkKind kind_;
		PECoffAnalysis* analysis_;
	};

	class PECoffImportEntry {
	public:
		PECoffImportEntry(PECoffAnalysis* analysis, PIMAGE_IMPORT_DESCRIPTOR import);

		using thunk_iter = vector<PECoffImportThunk>::iterator;

		thunk_iter begin() { return thunks_.begin(); }

		thunk_iter end() { return thunks_.end(); }

		const char* GetImportName();

		bool IsBound() { return import_->TimeDateStamp == -1; }

		uint32_t GetThunkCount();

		PIMAGE_IMPORT_DESCRIPTOR GetNative() {
			return import_;
		}

	private:
		PECoffAnalysis* analysis_;
		PIMAGE_IMPORT_DESCRIPTOR import_;
		vector<PECoffImportThunk> thunks_;
	};

	class PECoffImport {
	public:
		using entry_iter = vector<PECoffImportEntry>::iterator;

	public:
		PECoffImport(PECoffAnalysis* analysis, PIMAGE_IMPORT_DESCRIPTOR import) {
			// pecoff_v83:The last directory entry is empty(filled with null values)
			IMAGE_IMPORT_DESCRIPTOR null_import = { 0 };
			while (memcmp(import, &null_import, sizeof(IMAGE_IMPORT_DESCRIPTOR)) != 0) {
				import_entries_.push_back(PECoffImportEntry(analysis, import));
				import++;
			}
		}

		entry_iter begin() { return import_entries_.begin(); }

		entry_iter end() { return import_entries_.end(); }

	private:
		vector<PECoffImportEntry> import_entries_;
	};

}