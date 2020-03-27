#pragma once

#include <Windows.h>
#include <vector>
#include <pe_common.h>

namespace pecoff {
	using namespace std;

	class PECoffAnalysis;

	class PECoffReloc4KThunk {
	public:
		struct RelocItem {
			pecoff_rva_t rva;
			uint32_t flags;
		};

	public:
		PECoffReloc4KThunk(PECoffAnalysis* analysis, PIMAGE_BASE_RELOCATION reloc);

		using item_iter = vector<RelocItem>::const_iterator;

		item_iter begin() const { return items_.cbegin(); }

		item_iter end() const { return items_.cend(); }

		size_t size() const { return items_.size(); }

		PIMAGE_BASE_RELOCATION GetNative() const { return reloc_; }

	private:
		PECoffAnalysis* analysis_;
		PIMAGE_BASE_RELOCATION reloc_;
		vector<RelocItem> items_;
	};

	class PECoffReloc {
	public:
		using thunk_iter = vector<PECoffReloc4KThunk>::const_iterator;

	public:
		PECoffReloc(PECoffAnalysis* analysis, PIMAGE_DATA_DIRECTORY reloc_dir);

		thunk_iter begin() const { return thunks_.cbegin(); }

		thunk_iter end() const { return thunks_.cend(); }

		size_t size() const { return thunks_.size(); }

		pecoff_rva_t GetDirectoryRVA() { return reloc_dir_->VirtualAddress; }

	private:
		PECoffAnalysis* analysis_;
		PIMAGE_DATA_DIRECTORY reloc_dir_;
		vector<PECoffReloc4KThunk> thunks_;
	};

}