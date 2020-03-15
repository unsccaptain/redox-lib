#pragma once

#include <Windows.h>
#include <cast.h>
#include <vector>

namespace pecoff {
	using namespace std;

	class PECoffAnalysis;

	class PECoffExportEntry {
	public:
		PECoffExportEntry(DWORD rva, PVOID address, USHORT ordinal, bool forwarder)
			:rva_(rva), address_(address), ordinal_(ordinal),
			forwarder_(forwarder), name_(nullptr) {
		}

		DWORD Rva() { return rva_; }

		// Code case
		void* Address() { return address_; }

		// Forwarder name case
		const char* Forwarder() { return force_cast<const char*>(address_); }

		USHORT Ordinal() { return ordinal_; }

		const char* Name() { return name_; }

		bool IsForwarder() { return forwarder_; }

		friend class PECoffExport;

	private:
		PVOID address_;
		DWORD rva_;
		const char* name_;
		USHORT ordinal_;
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

		PCSTR GetExportName();

		PIMAGE_EXPORT_DIRECTORY GetNative() {
			return export_dir_;
		}

	private:
		PECoffAnalysis* analysis_;
		PIMAGE_EXPORT_DIRECTORY export_dir_;
		vector<PECoffExportEntry> export_entries_;
	};

}