LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := uid_scanner
LOCAL_SRC_FILES := uid_scanner.c
LOCAL_LDLIBS := -llog
LOCAL_CFLAGS := -Wall -Wextra -std=c99
include $(BUILD_EXECUTABLE)