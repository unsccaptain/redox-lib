#pragma once

#define WIN32_LEAN_AND_MEAN             // 从 Windows 头文件中排除极少使用的内容
// Windows 头文件
#include <windows.h>

#define NAPI_VERSION 5
#include <node_api.h>
#include <assert.h>
#include <check.h>

#define NAPI_CALL(env, call, ret)                                   \
  do {                                                              \
    napi_status status = (call);                                    \
    if (status != napi_ok) {                                        \
      const napi_extended_error_info* error_info = NULL;            \
      napi_get_last_error_info((env), &error_info);                 \
      bool is_pending;                                              \
      napi_is_exception_pending((env), &is_pending);                \
      if (!is_pending) {                                            \
        const char* message = (error_info->error_message == NULL)   \
            ? "empty error message"                                 \
            : error_info->error_message;                            \
        napi_throw_error((env), NULL, message);                     \
        ret;                                                        \
      }                                                             \
    }                                                               \
  } while(0)

#define NAPI_CALL_RETURN_NULL(env, call)                            \
    NAPI_CALL(env, call, return NULL)