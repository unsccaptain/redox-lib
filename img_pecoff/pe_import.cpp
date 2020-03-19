  
#include "pe_coff.h"
#include "pe_import.h"

namespace pecoff {

	// OrdinalªÚ’ﬂAddressOfData
	PECoffImportThunk::PECoffImportThunk(PECoffAnalysis* analysis, void* thunk)
		:analysis_(analysis) {
		thunk32_ = force_cast<PIMAGE_THUNK_DATA32>(thunk);
		if (IsOrdinal())
			kind_ = ThunkKind::Ordinal;
		else
			kind_ = ThunkKind::NameDescriptor;
	}

	PECoffImportThunk::PECoffImportThunk(PECoffAnalysis* analysis, void* thunk, ThunkKind kind)
		:analysis_(analysis), kind_(kind) {
		thunk32_ = force_cast<PIMAGE_THUNK_DATA32>(thunk);
	}

	PIMAGE_IMPORT_BY_NAME PECoffImportThunk::GetNameDescriptor() {
		assert(kind_ == ThunkKind::NameDescriptor);
		PIMAGE_IMPORT_BY_NAME import_by_name;
		if (analysis_->IsX64())
			import_by_name = force_cast<PIMAGE_IMPORT_BY_NAME>(
				analysis_->TranslateRvaToVa(thunk32_->u1.AddressOfData));
		else
			import_by_name = force_cast<PIMAGE_IMPORT_BY_NAME>(
				analysis_->TranslateRvaToVa(thunk64_->u1.AddressOfData));
		return import_by_name;
	}

	uint64_t PECoffImportThunk::GetOrdinal() const {
		assert(kind_ == ThunkKind::Ordinal);
		// pecoff_v83: A 16-bit ordinal number. Bits 30-15 or 62-15 must be 0.
		if (analysis_->IsX64())
			return thunk64_->u1.Ordinal & 0xffff;
		else
			return thunk32_->u1.Ordinal & 0xffff;
	}

	bool PECoffImportThunk::IsOrdinal() {
		if (analysis_->IsX64())
			return thunk64_->u1.Ordinal & 0x8000000000000000;
		else
			return thunk32_->u1.Ordinal & 0x80000000;
	}

	PECoffImportEntry::PECoffImportEntry(PECoffAnalysis* analysis, PIMAGE_IMPORT_DESCRIPTOR import)
		:import_(import), analysis_(analysis) {
		PIMAGE_THUNK_DATA thunk_data;
		if (import->OriginalFirstThunk) {
			thunk_data = force_cast<PIMAGE_THUNK_DATA>(
				analysis_->TranslateRvaToVa(import->OriginalFirstThunk));
		}
		else {
			thunk_data = force_cast<PIMAGE_THUNK_DATA>(
				analysis_->TranslateRvaToVa(import->FirstThunk));
		}
		for (unsigned i = 0;i < GetThunkCount();i++) {
			thunks_.push_back(PECoffImportThunk(analysis_, thunk_data + i));
		}
	}

	const char* PECoffImportEntry::GetImportName() {
		return force_cast<const char*>(analysis_->TranslateRvaToVa(import_->Name));
	}
	
	uint32_t PECoffImportEntry::GetThunkCount() {
		return analysis_->GetThunkCount(analysis_->TranslateRvaToVa(import_->FirstThunk));
	}

}