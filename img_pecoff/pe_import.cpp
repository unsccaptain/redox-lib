
#include "pe_coff.h"
#include "pe_import.h"

namespace pecoff {

	pecoff_rva_t PECoffImportThunk::GetNameRvaIfExist() {
		assert(kind_ != ThunkKind::Ordinal);
		if (analysis_->IsX64())
			return (pecoff_rva_t)thunk64_->u1.AddressOfData;
		else
			return (pecoff_rva_t)thunk32_->u1.AddressOfData;
	}

	// Ordinal或者AddressOfData
	PECoffImportThunk::PECoffImportThunk(PECoffAnalysis* analysis, void* thunk)
		:analysis_(analysis) {
		thunk32_ = force_cast<PIMAGE_THUNK_DATA32>(thunk);
		if (IsOrdinal())
			kind_ = ThunkKind::Ordinal;
		else
			kind_ = ThunkKind::NameDescriptor;
	}

	// Function或者ForwarderString
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

	pecoff_ordinal_t PECoffImportThunk::GetOrdinal() const {
		assert(kind_ == ThunkKind::Ordinal);
		// pecoff_v83: A 16-bit ordinal number. Bits 30-15 or 62-15 must be 0.
		if (analysis_->IsX64())
			return (pecoff_ordinal_t)IMAGE_ORDINAL64(thunk64_->u1.Ordinal);
		else
			return (pecoff_ordinal_t)IMAGE_ORDINAL32(thunk64_->u1.Ordinal);
	}

	bool PECoffImportThunk::IsOrdinal() {
		if (analysis_->IsX64())
			return thunk64_->u1.Ordinal & IMAGE_ORDINAL_FLAG64;
		else
			return thunk32_->u1.Ordinal & IMAGE_ORDINAL_FLAG32;
	}

	PECoffImportEntry::PECoffImportEntry(PECoffAnalysis* analysis, PIMAGE_IMPORT_DESCRIPTOR import)
		:import_(import), analysis_(analysis) {
		bool updata_in_place = false;

		PIMAGE_THUNK_DATA thunk_data;
		if (import->OriginalFirstThunk) {
			thunk_data = force_cast<PIMAGE_THUNK_DATA>(
				analysis_->TranslateRvaToVa(import->OriginalFirstThunk));
			updata_in_place = false;
		}
		else {
			thunk_data = force_cast<PIMAGE_THUNK_DATA>(
				analysis_->TranslateRvaToVa(import->FirstThunk));
			updata_in_place = true;
		}
		
		unsigned count = GetThunkCount();
		if (analysis_->IsX64()) {
			PIMAGE_THUNK_DATA64 thunk_data_amd64 = (PIMAGE_THUNK_DATA64)thunk_data;
			for (unsigned i = 0;i < count;i++)
				thunks_.push_back(
					PECoffImportThunk(analysis_, thunk_data_amd64 + i));
		}
		else {
			PIMAGE_THUNK_DATA32 thunk_data_x86 = (PIMAGE_THUNK_DATA32)thunk_data;
			for (unsigned i = 0;i < count;i++)
				thunks_.push_back(
					PECoffImportThunk(analysis_, thunk_data_x86 + i));
		}
	}

	const char* PECoffImportEntry::GetImportName() {
		return force_cast<const char*>(analysis_->TranslateRvaToVa(import_->Name));
	}

	// FIXME：一般来说是OriginalFirstThunk但有时候只有FirstThunk一个表
	// 不过通过FirstThunk读取的表长度好像不太准。
	uint32_t PECoffImportEntry::GetThunkCount() {
		if (import_->OriginalFirstThunk) 
			return analysis_->GetThunkCount(
				analysis_->TranslateRvaToVa(import_->OriginalFirstThunk));
		else 
			return analysis_->GetThunkCount(
				analysis_->TranslateRvaToVa(import_->FirstThunk));
	}

}