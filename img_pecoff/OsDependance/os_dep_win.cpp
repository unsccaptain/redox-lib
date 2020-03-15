
#include "../os_dep.h"

namespace pecoff {

	bool OsDependance::CreateImageMap(const std::string& path) {
		try {
			image_file_ = CreateFile(path.c_str(), GENERIC_READ,
				FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
			if (image_file_ == INVALID_HANDLE_VALUE) {
				throw(std::exception("Open file failed! Error code:"));
			}

			DWORD size_high, size_low = GetFileSize(image_file_, &size_high);
			map_size_ = ((uint64_t)size_high << 32) + size_low;

			image_map_ = CreateFileMapping(image_file_, NULL, PAGE_READONLY, 0, 0, NULL);
			if (image_map_ == 0) {
				throw(std::exception("Create mapping failed! Error code:"));
			}

			map_base_ = MapViewOfFile(image_map_, FILE_MAP_READ, 0, 0, map_size_);
			if (map_base_ == 0) {
				throw(std::exception("Map file failed! Error code:"));
			}
		}
		catch (std::exception e) {
			OutputDebugString(e.what());
			CloseAllHandle();
			return false;
		}

		return true;
	}

	void OsDependance::CloseAllHandle() {
		if (map_base_ != nullptr) {
			UnmapViewOfFile(map_base_);
			map_base_ = nullptr;
		}
		if (image_map_ != 0) {
			CloseHandle(image_map_);
			image_map_ = 0;
		}
		if (image_file_ != INVALID_HANDLE_VALUE) {
			CloseHandle(image_file_);
			image_file_ = INVALID_HANDLE_VALUE;
		}
	}

}