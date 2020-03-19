
#include "attribute_mgr.h"
#include <Windows.h>

namespace redox {

	AttributeList AttributeDomain::CreateAttrListFromValue(uint64_t attr, bool all) {
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

	AttributeManager::AttributeManager() {
		domain_map_["FileHeaderCharacteristics"].SetCombine(true);
		domain_map_["FileHeaderMachine"].SetCombine(false);
		domain_map_["SectionHeaderCharacteristics"].SetCombine(true);
#define DEF_CONST(domain, name, value) domain_map_[string(#domain)].CreateAttrEntry(#name, name);
#include "pe_constant.def" 
#undef DEF_CONST
	}

}