#pragma once

#include <Windows.h>
#include <cast.h>
#include <vector>
#include <pe_common.h>

namespace pecoff {
	using namespace std;

	class PECoffAnalysis;

	class PECoffExportEntry {
	public:
		PECoffExportEntry(pecoff_rva_t rva, PVOID address, pecoff_ordinal_t ordinal, bool forwarder)
			:rva_(rva), address_(address), ordinal_(ordinal),
			forwarder_(forwarder), name_(nullptr) {
		}

		pecoff_rva_t Rva() const { return rva_; }

		// Code case
		void* Address() const { return address_; }

		// Forwarder name case
		const char* Forwarder() const { return force_cast<const char*>(address_); }

		pecoff_ordinal_t Ordinal() const { return ordinal_; }
		
		const char* Name() const { return name_; }

		bool IsForwarder() const { return forwarder_; }

		friend class PECoffExport;

	private:
		PVOID address_;
		pecoff_rva_t rva_;
		const char* name_;
		pecoff_ordinal_t ordinal_;
		bool forwarder_;
	};

	class PECoffExport {
	public:
		using entry_iter = vector<PECoffExportEntry>::iterator;

	public:
		PECoffExport(PECoffAnalysis* analysis, PIMAGE_EXPORT_DIRECTORY export_dir);

		entry_iter begin() { return export_entries_.begin(); }

		entry_iter end() { return export_entries_.end(); }

		size_t size() { return export_entries_.size(); }

		pecoff_str_t GetExportName();

		PIMAGE_EXPORT_DIRECTORY GetNative() {
			return export_dir_;
		}

	private:
		PECoffAnalysis* analysis_;
		PIMAGE_EXPORT_DIRECTORY export_dir_;
		vector<PECoffExportEntry> export_entries_;
	};

}