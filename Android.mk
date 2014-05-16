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
LOCAL_ARM_MODE          := arm
LOCAL_SRC_FILES         := anemu.c setcontext.S
LOCAL_C_INCLUDES        += dalvik/vm/darm-v7
# NDK_ROOT is automatically set when using ndk-build
ifneq (,$(NDK_ROOT))
LOCAL_CFLAGS            += -DNDK_BUILD
LOCAL_C_INCLUDES        += $(ANDROID)/arm/darm-v7
endif
LOCAL_CFLAGS            += -Wall -march=armv7-a -mcpu=cortex-a9 -mtune=cortex-a9 -mfpu=neon
LOCAL_CFLAGS            += -Ofast
# DEBUG: keep macros + debug symbols
LOCAL_CFLAGS            += -g3
LOCAL_CFLAGS            += -fno-omit-frame-pointer
LOCAL_CFLAGS            += -nodefaultlibs -nostdlib
LOCAL_LDFLAGS           := -Wl,--exclude-libs=libgcc.a

# explicitly out implicit libs like libdl and libc
LOCAL_SYSTEM_SHARED_LIBRARIES :=
LOCAL_STATIC_LIBRARIES += libc_nomalloc

# measurements enabled, disable logging
# LOCAL_CFLAGS            += -DPROFILE

# enable assertions by disabling NDEBUG flag
LOCAL_CFLAGS              += -UNDEBUG
# LOCAL_CFLAGS            += -DNDEBUG

ifeq ($(ARCH_ARM_HAVE_VFP),true)
LOCAL_CFLAGS += -DWITH_VFP
endif
ifeq ($(ARCH_ARM_HAVE_VFP_D32),true)
LOCAL_CFLAGS += -DWITH_VFP_D32
endif

# include $(BUILD_SHARED_LIBRARY)
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE            := emu-matrix
LOCAL_MODULE_TAGS       := optional
LOCAL_REQUIRED_MODULES  := libdarm
LOCAL_SHARED_LIBRARIES  := libc libdl
LOCAL_WHOLE_STATIC_LIBRARIES  += libanemu libdarm
LOCAL_STATIC_LIBRARIES  += libanemu libdarm
LOCAL_ARM_MODE          := arm
LOCAL_SRC_FILES         := tests/matrix.c
LOCAL_CFLAGS            += -O0 -Wall -march=armv7-a -mcpu=cortex-a9 -mfloat-abi=soft
# DEBUG: keep macros + debug symbols
LOCAL_CFLAGS            += -g3
# NDK_ROOT is automatically set when using ndk-build
ifneq (,$(NDK_ROOT))
	LOCAL_LDLIBS          += -L$(ANDROID)/arm/darm-v7/obj/local/armeabi-v7a/
	LOCAL_LDFLAGS         += -ldarm -lc -llog
endif
include $(BUILD_EXECUTABLE)
