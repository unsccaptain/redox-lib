
#include <pe_delay_import.h>
#include <pe_coff.h>
#include <pe_import.h>

namespace pecoff {

	PECoffDelayImportEntry::PECoffDelayImportEntry(PECoffAnalysis* analysis, PIMAGE_DELAYLOAD_DESCRIPTOR delay_import)
		:analysis_(analysis), delay_import_(delay_import) {
		PIMAGE_THUNK_DATA thunk_data = force_cast<PIMAGE_THUNK_DATA>(
			analysis_->TranslateRvaToVa(delay_import_->ImportNameTableRVA));

		unsigned count = GetThunkCount();
		if (analysis_->IsX64()) {
			PIMAGE_THUNK_DATA64 thunk_data_amd64 = (PIMAGE_THUNK_DATA64)thunk_data;
			for (unsigned i = 0;i < count;i++) 
				thunks_.push_back(
					PECoffImportThunk(analysis_, thunk_data_amd64 + i));
			thunk_data_amd64 = force_cast<PIMAGE_THUNK_DATA64>(
				analysis_->TranslateRvaToVa(delay_import_->ImportAddressTableRVA));
			for (unsigned i = 0;i < count;i++) 
				thunks_[i].address_rva_ = (uint32_t)thunk_data_amd64[i].u1.Function;
		}
		else {
			PIMAGE_THUNK_DATA32 thunk_data_x86 = (PIMAGE_THUNK_DATA32)thunk_data;
			for (unsigned i = 0;i < count;i++) 
				thunks_.push_back(
					PECoffImportThunk(analysis_, thunk_data_x86 + i));
			thunk_data_x86 = force_cast<PIMAGE_THUNK_DATA32>(
				analysis_->TranslateRvaToVa(delay_import_->ImportAddressTableRVA));
			for (unsigned i = 0;i < count;i++) 
				thunks_[i].address_rva_ = (uint32_t)thunk_data_x86[i].u1.Function;
		}

	}

	const char* PECoffDelayImportEntry::GetName() {
		return force_cast<const char*>(analysis_->TranslateRvaToVa(delay_import_->DllNameRVA));
	}

	uint32_t PECoffDelayImportEntry::GetThunkCount() {
		return analysis_->GetThunkCount(analysis_->TranslateRvaToVa(delay_import_->ImportNameTableRVA));
	}

	PECoffDelayImport::PECoffDelayImport(PECoffAnalysis* analysis, PIMAGE_DELAYLOAD_DESCRIPTOR delay_import)
		:analysis_(analysis) {
		while (delay_import->DllNameRVA != 0) {
			entries_.push_back(PECoffDelayImportEntry(analysis, delay_import));
			delay_import++;
		}
	}

}