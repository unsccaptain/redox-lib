#pragma once
#include <node_api.h>

namespace pecoff {

	napi_value CreateAnalysis(napi_env env, napi_callback_info info);

	napi_value CreatePecoffRootObject(napi_env env);

#define NDH(f)
#define NDHA(f, l)
#define NFH(f)
#define NSH(f)
#define NSHA(f, l)
#define NOH32(f)
#define NOH64(f)
#define NID(f)
#define NED(f)
#define	NDID(f)
#define NDD(f)

#define DEF_CONST(domain, name, value)
}