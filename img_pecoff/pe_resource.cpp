
#include <pe_resource.h>
#include <pe_coff.h>
#include <check.h>

namespace pecoff {

	PECoffResourceData::PECoffResourceData(
		PECoffAnalysis* analysis, pecoff_rva_t offset_base, PIMAGE_RESOURCE_DATA_ENTRY data)
		:data_(data) {
		data_rva_ = data->OffsetToData;
	}

	/**
	 * @brief 构造非叶节点，生成子节点数组
	 */
	PECoffResourceNode::PECoffResourceNode(
		PECoffAnalysis* analysis, PIMAGE_RESOURCE_DIRECTORY dir, const NodeIdentifier& id)
		:analysis_(analysis), native_dir_(dir), identifier_(id) {
		if (dir->NumberOfIdEntries + dir->NumberOfNamedEntries == 0) {
			assert(false);
		}
		pecoff_rva_t offset_base = analysis_->GetDataDirectory(IMAGE_DIRECTORY_ENTRY_RESOURCE)->VirtualAddress;
		PIMAGE_RESOURCE_DIRECTORY_ENTRY entry = force_cast<PIMAGE_RESOURCE_DIRECTORY_ENTRY>(dir + 1);
		PIMAGE_RESOURCE_DIRECTORY res_dir;
		PIMAGE_RESOURCE_DATA_ENTRY data_entry;
		for (unsigned i = 0;i < dir->NumberOfNamedEntries;i++) {
			PIMAGE_RESOURCE_DIR_STRING_U name = force_cast<PIMAGE_RESOURCE_DIR_STRING_U>(
				analysis_->TranslateRvaToVa(offset_base + entry->NameOffset));
			NodeIdentifier identifier = NodeIdentifier(wstring(name->NameString, name->Length));
			CreateChild(offset_base, entry, identifier);
			entry++;
		}
		for (unsigned i = 0;i < dir->NumberOfIdEntries;i++) {
			NodeIdentifier identifier = NodeIdentifier(entry->Id);
			CreateChild(offset_base, entry, identifier);
			entry++;
		}
	}

	/**
	 * @brief 构造叶节点，生成PECoffResourceData对象
	 */
	PECoffResourceNode::PECoffResourceNode(
		PECoffAnalysis* analysis, PIMAGE_RESOURCE_DATA_ENTRY data_entry, const NodeIdentifier& id)
		:analysis_(analysis), native_data_(data_entry), identifier_(id) {
		pecoff_rva_t offset_base = analysis_->GetDataDirectory(IMAGE_DIRECTORY_ENTRY_RESOURCE)->VirtualAddress;
		CheckPTR(offset_base);
		data_ = PECoffResourceData(analysis_, offset_base, data_entry);
	}

	void PECoffResourceNode::CreateChild(
		pecoff_rva_t offset_base, PIMAGE_RESOURCE_DIRECTORY_ENTRY entry, NodeIdentifier& identifier) {
		PIMAGE_RESOURCE_DIRECTORY res_dir;
		PIMAGE_RESOURCE_DATA_ENTRY data_entry;
		if (entry->DataIsDirectory) {
			res_dir = force_cast<PIMAGE_RESOURCE_DIRECTORY>(
				analysis_->TranslateRvaToVa(offset_base + entry->OffsetToDirectory));
			CheckPTR(res_dir);
			children_.emplace_back(analysis_, res_dir, identifier);
		}
		else {
			data_entry = force_cast<PIMAGE_RESOURCE_DATA_ENTRY>(
				analysis_->TranslateRvaToVa(offset_base + entry->OffsetToData));
			CheckPTR(data_entry);
			children_.emplace_back(analysis_, data_entry, identifier);
		}
	}

}