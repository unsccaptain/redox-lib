#pragma once

#ifdef OS_WINDOWS
#define WIN32_LEAN_AND_MEAN             // 从 Windows 头文件中排除极少使用的内容
#include <Windows.h>
#include <string>

namespace pecoff {
	class OsDependance {
	public:
		OsDependance() :image_file_(INVALID_HANDLE_VALUE),
			image_map_(0),
			map_base_(nullptr),
			map_size_(0) {
		}

		~OsDependance() {
			CloseAllHandle();
		}

		bool CreateImageMap(const std::string& path);

		void* GetMapBase() { return map_base_; }

		HANDLE GetFileHandle() { return image_file_; }

		uint32_t GetMappedSize() { return (uint32_t)map_size_; }

	private:
		void CloseAllHandle();

	private:
		HANDLE image_file_;
		HANDLE image_map_;

		void* map_base_;
		uint64_t map_size_;

	};
}
#endif