#pragma once

#include <vector>
#include <map>
#include <string>

namespace redox {
	using namespace std;

	class AttributeList {
	public:
		struct Attribute {
			string& AttrName;
			uint64_t AttrValue;
			bool Enabled;

			Attribute(string& name, uint64_t value, bool enable)
				:AttrName(name), AttrValue(value), Enabled(enable) {
			}
		};

		using attr_iter = vector<Attribute>::const_iterator;

		void Push(string& name, uint64_t value, bool enable = true) {
			attr_list_.push_back(Attribute(name, value, enable));
		}

		attr_iter begin() const { return attr_list_.cbegin(); }

		attr_iter end() const { return attr_list_.cend(); }

	private:
		vector<Attribute> attr_list_;
	};

	class AttributeDomain {
	public:
		explicit AttributeDomain()
			:combine_(false) {
		}

		void SetCombine(bool combine) {
			combine_ = combine;
		}

		void CreateAttrEntry(const string& name, uint64_t value) {
			entry_map_.push_back(pair<uint64_t, string>(value, name));
		}

		AttributeList CreateAttrListFromValue(uint64_t attr, bool all);

	private:
		bool combine_;
		vector<pair<uint64_t, string>> entry_map_;
	};

	class AttributeManager {
	public:
		explicit AttributeManager();

		AttributeList CreateAttrList(const string& domain, uint64_t attr, bool all = false) {
			return domain_map_[domain].CreateAttrListFromValue(attr, all);
		}

	private:
		map<string, AttributeDomain> domain_map_;
	};

}