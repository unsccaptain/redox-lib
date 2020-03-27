#pragma once

#include <vector>
#include <map>
#include <string>
#include <assert.h>

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

		size_t size() const { return attr_list_.size(); }

		Attribute& operator[](unsigned index) {
			assert(index < attr_list_.size());
			return attr_list_[index];
		}

	private:
		vector<Attribute> attr_list_;
	};

	class AttributeDomain {
	public:
		using exclusive_attr_item = pair<uint64_t, string>;
		using composite_attr_list = AttributeList;

	public:
		explicit AttributeDomain()
			:combine_(false) {
		}

		void SetCombine(bool combine) {
			combine_ = combine;
		}

		void CreateAttrEntry(const string& name, uint64_t value) {
			entry_map_.emplace_back(pair<uint64_t, string>(value, name));
		}

		AttributeList GetCompositeAttr(uint64_t attr, bool all);

		exclusive_attr_item GetExclusiveAttr(uint64_t attr);

	private:
		bool combine_;
		vector<pair<uint64_t, string>> entry_map_;
	};

	class AttributeManager {
	public:
		explicit AttributeManager();

		AttributeDomain::composite_attr_list GetCompositeAttr(const string& domain, uint64_t attr, bool all = false) {
			return domain_map_[domain].GetCompositeAttr(attr, all);
		}

		AttributeDomain::exclusive_attr_item GetExclusiveAttr(const string& domain, uint64_t attr) {
			return domain_map_[domain].GetExclusiveAttr(attr);
		}

	private:
		map<string, AttributeDomain> domain_map_;
	};

}