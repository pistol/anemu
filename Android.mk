#
# instructions:
#
# 1) symlink anemu and radare2 inside <aosp> tree
# $ ln -s /path/to/anemu   <aosp>/dalvik/vm/anemu
# $ ln -s /path/to/radare2 <aosp>/dalvik/vm/anemu/radare2
#
# 2) use android build system to build:
# $ cd <aosp>
# $ . build/envsetup && lunch_<product>-eng
# $ cd dalvik/vm/anemu
# $ mm

LOCAL_PATH := $(call my-dir)

RASM := radare2

include $(CLEAR_VARS)
MY_PREFIX               := $(LOCAL_PATH)
MY_SOURCES              := $(wildcard $(MY_PREFIX)/$(RASM)/lib/*.a)
LOCAL_PREBUILT_LIBS     += $(MY_SOURCES:$(MY_PREFIX)%=%)
LOCAL_MODULE_TAGS       := optional
include $(BUILD_MULTI_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE            := libanemu
LOCAL_MODULE_TAGS       := optional
LOCAL_REQUIRED_MODULES  := libdarm
LOCAL_SHARED_LIBRARIES  := liblog
LOCAL_STATIC_LIBRARIES  := libdarm libr_asm libr_util libr_db libsdb libr
LOCAL_SRC_FILES         := anemu.c.arm rasm.c
LOCAL_C_INCLUDES        += dalvik/vm/darm-v7 \
                           dalvik/vm/anemu/$(RASM)/include/libr
LOCAL_CFLAGS            += -gdwarf-2 -g3 -O0 -Wall -march=armv7-a -mcpu=cortex-a9
LOCAL_CFLAGS            += -DANDROID
# include $(BUILD_STATIC_LIBRARY)
include $(BUILD_SHARED_LIBRARY)
