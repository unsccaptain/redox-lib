#pragma once

#include <Windows.h>
#include <cast.h>
#include <vector>

namespace pecoff {
	using namespace std;

	class PECoffAnalysis;
	class PECoffImportThunk;

	class PECoffDelayImportEntry {
	public:
		PECoffDelayImportEntry(PECoffAnalysis* analysis, PIMAGE_DELAYLOAD_DESCRIPTOR delay_import);

		using thunk_iter = vector<PECoffImportThunk>::const_iterator;

		thunk_iter begin() const { return thunks_.begin(); }

		thunk_iter end() const { return thunks_.end(); }

		size_t size() const { return thunks_.size(); }

		PECoffImportThunk& operator[](unsigned index) {
			return thunks_[index];
		}

		const char* GetName();

		bool IsBound() { return delay_import_->TimeDateStamp != 0; }

		PIMAGE_DELAYLOAD_DESCRIPTOR GetNative() {
			return delay_import_;
		}

	private:
		uint32_t GetThunkCount();

	private:
		PECoffAnalysis* analysis_;
		PIMAGE_DELAYLOAD_DESCRIPTOR delay_import_;
		vector<PECoffImportThunk> thunks_;
	};

	class PECoffDelayImport {
	public:
		using entry_iter = vector<PECoffDelayImportEntry>::const_iterator;

		PECoffDelayImport(PECoffAnalysis* analysis, PIMAGE_DELAYLOAD_DESCRIPTOR delay_import);

		entry_iter begin() const { return entries_.begin(); }

		entry_iter end() const { return entries_.end(); }

		size_t size() const { return entries_.size(); }

		PECoffDelayImportEntry& operator[](unsigned index) {
			return entries_[index];
		}

	private:
		PECoffAnalysis* analysis_;
		vector<PECoffDelayImportEntry> entries_;
	};

}