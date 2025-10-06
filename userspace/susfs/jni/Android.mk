LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := susfsd
LOCAL_SRC_FILES := susfs.c
include $(BUILD_EXECUTABLE)
