
#include "attribute_mgr.h"
#include <Windows.h>

namespace redox {

	AttributeDomain::composite_attr_list AttributeDomain::GetCompositeAttr(uint64_t attr, bool all) {
		AttributeList list;
		if (combine_) {
			for (auto& entry : entry_map_) {
				if ((attr & entry.first) != 0)
					list.Push(entry.second, entry.first, true);
				else if (all)
					list.Push(entry.second, entry.first, false);
			}
		}
		else {
			for (auto& entry : entry_map_)
				if (attr == entry.first)
					list.Push(entry.second, entry.first);
		}
		return list;
	}

	AttributeDomain::exclusive_attr_item AttributeDomain::GetExclusiveAttr(uint64_t attr) {
		assert(!combine_);
		for (auto& entry : entry_map_)
			if (attr == entry.first)
				return entry;
		return exclusive_attr_item(-1, "");
	}

	AttributeManager::AttributeManager() {
		domain_map_["FileHeaderCharacteristics"].SetCombine(true);
		domain_map_["FileHeaderMachine"].SetCombine(false);
		domain_map_["SectionHeaderCharacteristics"].SetCombine(true);
		domain_map_["BaseReloc"].SetCombine(false);
		domain_map_["OptSubsystem"].SetCombine(false);
		domain_map_["OptCharacteristics"].SetCombine(true);
#define DEF_CONST(domain, name, value) domain_map_[string(#domain)].CreateAttrEntry(#name, name);
#include "pe_constant.def" 
#undef DEF_CONST
	}

}