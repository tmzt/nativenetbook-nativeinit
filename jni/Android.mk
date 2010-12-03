
LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE:= nativeinit 
LOCAL_SRC_FILES:= \
  init.c

LOCAL_LDLIBS := -ldl -llog

include $(BUILD_EXECUTABLE)
