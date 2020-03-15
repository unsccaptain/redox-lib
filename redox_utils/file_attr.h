#pragma once

#include <Windows.h>
#include <set>
#include <check.h>
#include <string>

#define MayFail(result)	CheckBool(result, "retrieve file attributes failed!")

namespace redox {
	using namespace std;

	class FileAttr {
	public:
		FileAttr(HANDLE file)
			:file_(file) {
		}

		template<class T>
		T GetCreationTime() {
			SYSTEMTIME system_time;
			FILE_BASIC_INFO basic_info;
			MayFail(GetFileInformationByHandleEx(file_, FileBasicInfo, &basic_info, sizeof(FILE_BASIC_INFO)));
			if (is_same<T, SYSTEMTIME>::value) {
				MayFail(FileTimeToSystemTime((PFILETIME)&basic_info.CreationTime, &system_time));
				return *(T*)&system_time;
			}
			else
				return *(T*)&basic_info.CreationTime;
		}

		template<class T>
		T GetLastAccessTime() {
			SYSTEMTIME system_time;
			FILE_BASIC_INFO basic_info;
			MayFail(GetFileInformationByHandleEx(file_, FileBasicInfo, &basic_info, sizeof(FILE_BASIC_INFO)));
			if (is_same<T, SYSTEMTIME>::value) {
				MayFail(FileTimeToSystemTime((PFILETIME)&basic_info.LastAccessTime, &system_time));
				return *(T*)&system_time;
			}
			else
				return *(T*)&basic_info.LastAccessTime;
		}

		template<class T>
		T GetLastWriteTime() {
			SYSTEMTIME system_time;
			FILE_BASIC_INFO basic_info;
			MayFail(GetFileInformationByHandleEx(file_, FileBasicInfo, &basic_info, sizeof(FILE_BASIC_INFO)));
			if (is_same<T, SYSTEMTIME>::value) {
				MayFail(FileTimeToSystemTime((PFILETIME)&basic_info.LastWriteTime, &system_time));
				return *(T*)&system_time;
			}
			else
				return *(T*)&basic_info.LastAccessTime;
		}

		template<class T>
		T GetChangeTime() {
			SYSTEMTIME system_time;
			FILE_BASIC_INFO basic_info;
			MayFail(GetFileInformationByHandleEx(file_, FileBasicInfo, &basic_info, sizeof(FILE_BASIC_INFO)));
			if (is_same<T, SYSTEMTIME>::value) {
				MayFail(FileTimeToSystemTime((PFILETIME)&basic_info.ChangeTime, &system_time));
				return *(T*)&system_time;
			}
			else
				return *(T*)&basic_info.ChangeTime;
		}

		LARGE_INTEGER GetAllocationSize() {
			FILE_STANDARD_INFO standard_info;
			MayFail(GetFileInformationByHandleEx(file_, FileStandardInfo, &standard_info, sizeof(FILE_STANDARD_INFO)));
			return standard_info.AllocationSize;
		}

		LARGE_INTEGER GetEndOfFile() {
			FILE_STANDARD_INFO standard_info;
			MayFail(GetFileInformationByHandleEx(file_, FileStandardInfo, &standard_info, sizeof(FILE_STANDARD_INFO)));
			return standard_info.EndOfFile;
		}

		set<DWORD> GetFileMetadata() {
			FILE_BASIC_INFO basic_info;
			set<DWORD> metadata;
			MayFail(GetFileInformationByHandleEx(file_, FileBasicInfo, &basic_info, sizeof(FILE_BASIC_INFO)));
			if (basic_info.FileAttributes & FILE_ATTRIBUTE_ARCHIVE)
				metadata.insert(FILE_ATTRIBUTE_ARCHIVE);
			if (basic_info.FileAttributes & FILE_ATTRIBUTE_HIDDEN)
				metadata.insert(FILE_ATTRIBUTE_HIDDEN);
			if (basic_info.FileAttributes & FILE_ATTRIBUTE_READONLY)
				metadata.insert(FILE_ATTRIBUTE_READONLY);
			if (basic_info.FileAttributes & FILE_ATTRIBUTE_SYSTEM)
				metadata.insert(FILE_ATTRIBUTE_SYSTEM);
			return metadata;
		}

		wstring GetFileName() {
			BYTE buffer[560] = { 0 };
			PFILE_NAME_INFO name_info = (PFILE_NAME_INFO)buffer;
			name_info->FileNameLength = 560;
			MayFail(GetFileInformationByHandleEx(file_, FileNameInfo, name_info, 560));
			return wstring(name_info->FileName);
		}

	private:
		HANDLE file_;
	};

}