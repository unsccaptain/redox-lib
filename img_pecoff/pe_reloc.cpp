#pragma once

#include <pe_reloc.h>
#include <pe_coff.h>

namespace pecoff {

	PECoffReloc4KThunk::PECoffReloc4KThunk(PECoffAnalysis* analysis, PIMAGE_BASE_RELOCATION reloc)
		:analysis_(analysis), reloc_(reloc) {
		pecoff_reloc_t* item_list = (pecoff_reloc_t*)(
			(BYTE*)reloc + sizeof(*reloc));
		pecoff_reloc_t item_size = reloc->SizeOfBlock - sizeof(*reloc);
		for (unsigned i = 0;i < item_size / 2;i++) {
			pecoff_reloc_t item = item_list[i];
			RelocItem reloc_item;
			reloc_item.flags = item & 0xf000;
			reloc_item.flags >>= 12;
			reloc_item.rva = reloc->VirtualAddress + (item & 0xfff);
			items_.emplace_back(reloc_item);
		}
	}

	PECoffReloc::PECoffReloc(PECoffAnalysis* analysis, PIMAGE_DATA_DIRECTORY reloc_dir)
		:analysis_(analysis), reloc_dir_(reloc_dir) {
		int32_t size = reloc_dir->Size;
		PIMAGE_BASE_RELOCATION reloc = force_cast<PIMAGE_BASE_RELOCATION>(
			analysis_->TranslateRvaToVa(reloc_dir->VirtualAddress));
		while (size > 0) {
			thunks_.emplace_back(PECoffReloc4KThunk(analysis, reloc));
			size -= reloc->SizeOfBlock;
			reloc = force_cast<PIMAGE_BASE_RELOCATION>((BYTE*)reloc + reloc->SizeOfBlock);
		}
	}

}