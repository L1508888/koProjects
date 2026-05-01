
#ifndef MY_APPLICATION_LOG_UTIL_H
#define MY_APPLICATION_LOG_UTIL_H
#include <android/log.h>
#define TAG "Encrypt"
#define LOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__))
#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__))
#endif //MY_APPLICATION_LOG_UTIL_H
