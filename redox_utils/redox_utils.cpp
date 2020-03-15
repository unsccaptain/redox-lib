// redox_utils.cpp : 定义静态库的函数。
//

#include "redox_utils.h"
#include "file_attr.h"

// TODO: 这是一个库函数示例
void fnredoxutils()
{

	redox::FileAttr ft(0);
	auto tt = ft.GetCreationTime<FILETIME>();
}
