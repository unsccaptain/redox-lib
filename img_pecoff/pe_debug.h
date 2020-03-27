#pragma once

#include <vector>
#include <Windows.h>

namespace pecoff {
	using namespace std;

	class PECoffDebug {
	public:
		using debug_iter=vector<PIMAGE_DEBUG_DIRECTORY>::const_iterator;

	public:
		PECoffDebug(PIMAGE_DATA_DIRECTORY dir, PIMAGE_DEBUG_DIRECTORY entry) {
			uint32_t size = dir->Size;
			while (size > 0) {
				debug_entries_.push_back(entry);
				entry++;
				size -= sizeof(IMAGE_DEBUG_DIRECTORY);
			}
		}

		debug_iter begin() { return debug_entries_.begin(); }

		debug_iter end() { return debug_entries_.end(); }

		size_t size() { return debug_entries_.size(); }

	private:
		vector<PIMAGE_DEBUG_DIRECTORY> debug_entries_;
	};

}