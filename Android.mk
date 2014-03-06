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

# RASM := radare2
# RASM := $(ANDROID)/arm/radare2/android-install/data/data/org.radare.installer/radare2/

# include $(CLEAR_VARS)
# MY_PREFIX               := $(LOCAL_PATH)
# MY_SOURCES              := $(wildcard $(MY_PREFIX)/$(RASM)/lib/*.a)
# LOCAL_PREBUILT_LIBS     += $(MY_SOURCES:$(MY_PREFIX)%=%)
# LOCAL_MODULE_TAGS       := optional
# include $(BUILD_MULTI_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE            := libanemu
LOCAL_MODULE_TAGS       := optional
LOCAL_REQUIRED_MODULES  := libdarm
LOCAL_SHARED_LIBRARIES  := libdl
# LOCAL_SHARED_LIBRARIES  := libdl liblog libdarm libcorkscrew
LOCAL_WHOLE_STATIC_LIBRARIES  += libdarm libcorkscrew
# LOCAL_STATIC_LIBRARIES  += libr_asm libr_util libr_db libsdb libr
LOCAL_SRC_FILES         := anemu.c.arm
# LOCAL_SRC_FILES         +=  rasm.c
LOCAL_C_INCLUDES        += dalvik/vm/darm-v7
# LOCAL_C_INCLUDES        += dalvik/vm/anemu/$(RASM)/include/libr
LOCAL_CFLAGS            += -O0 -g -Wall -march=armv7-a -mcpu=cortex-a9
LOCAL_CFLAGS            += -fPIC
LOCAL_CFLAGS            += -nodefaultlibs -nostdlib
LOCAL_LDFLAGS           := -Wl,--exclude-libs=libgcc.a

# explicitly out implicit libs like libdl and libc
LOCAL_SYSTEM_SHARED_LIBRARIES :=
LOCAL_STATIC_LIBRARIES += libc_nomalloc

# FIXME: flags (defines) are not used?
LOCAL_CFLAGS            += -DANDROID
# measurements enabled, disable logging
# LOCAL_CFLAGS            += -DPROFILE
# LOCAL_CFLAGS            += -UNDEBUG

# LOCAL_CFLAGS += -fno-function-sections
# LOCAL_CFLAGS += -fno-omit-frame-pointer
# LOCAL_CFLAGS += -pg

# include $(BUILD_SHARED_LIBRARY)
include $(BUILD_STATIC_LIBRARY)
