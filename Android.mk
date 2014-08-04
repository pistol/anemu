# Useful adb line options:
# adb shell setprop log.redirect-stdio true
# adb shell setprop dalvik.vm.jniopts logThirdPartyJni

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
# LOCAL_WHOLE_STATIC_LIBRARIES  += libdarm libcorkscrew
LOCAL_WHOLE_STATIC_LIBRARIES  += libdarm
LOCAL_ARM_MODE          := arm
LOCAL_SRC_FILES         := anemu.c setcontext.S
LOCAL_CFLAGS            += -DEMU_TAINT_FILE
# Atomics need ANDROID_SMP=1
LOCAL_CFLAGS            += -DANDROID_SMP=1
# LOCAL_C_INCLUDES        += dalvik/vm/darm-v7
LOCAL_C_INCLUDES        += bionic/darm-v7
LOCAL_C_INCLUDES        += bionic/libc/private

# LOCAL_CFLAGS            += -I$(TAINTDROID)/bionic/libc/private
# LOCAL_C_INCLUDES        += $(TAINTDROID)/bionic/libc/private

# NDK_ROOT is automatically set when using ndk-build
ifneq (,$(NDK_ROOT))
LOCAL_CFLAGS            += -DNDK_BUILD
LOCAL_SRC_FILES         += xattr.c
LOCAL_C_INCLUDES        += $(ANDROID)/arm/darm-v7
endif
LOCAL_CFLAGS            += -Wall -march=armv7-a -mcpu=cortex-a9 -mtune=cortex-a9 -mfpu=neon

LOCAL_CFLAGS            += -O3

# LOCAL_CFLAGS            += -O0

# LOCAL_CFLAGS            += -O3
# LOCAL_CFLAGS            += -Ofast
# DEBUG: keep macros + debug symbols
LOCAL_CFLAGS            += -g3
LOCAL_CFLAGS            += -fno-omit-frame-pointer
LOCAL_CFLAGS            += -nodefaultlibs -nostdlib
LOCAL_CFLAGS            += -fno-strict-aliasing
LOCAL_LDFLAGS           := -Wl,--exclude-libs=libgcc.a

# explicitly out implicit libs like libdl and libc
LOCAL_SYSTEM_SHARED_LIBRARIES :=
LOCAL_STATIC_LIBRARIES += libc_nomalloc

# measurements enabled, disable logging
# LOCAL_CFLAGS            += -DPROFILE

# LOCAL_CFLAGS            += -DNO_TAINT

LOCAL_CFLAGS            += -DTAINT_STATS

# enable assertions by disabling NDEBUG flag
# LOCAL_CFLAGS            += -UNDEBUG
LOCAL_CFLAGS            += -DNDEBUG

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
LOCAL_REQUIRED_MODULES  := libanemu libdarm
LOCAL_SHARED_LIBRARIES  := libc libdl
# LOCAL_WHOLE_STATIC_LIBRARIES  += libanemu libdarm
LOCAL_STATIC_LIBRARIES  += libanemu libdarm
LOCAL_ARM_MODE          := arm
LOCAL_SRC_FILES         := tests/matrix.c
LOCAL_CFLAGS            += -Wall -march=armv7-a -mcpu=cortex-a9 -mfloat-abi=soft
LOCAL_CFLAGS            += -O3
# Disable optimizations, results in much higher instruction count
# LOCAL_CFLAGS            += -O0
LOCAL_CFLAGS            += -DNDEBUG
# DEBUG: keep macros + debug symbols
LOCAL_CFLAGS            += -g3
# NDK_ROOT is automatically set when using ndk-build
ifneq (,$(NDK_ROOT))
	LOCAL_LDLIBS          += -L$(ANDROID)/arm/anemu/obj/local/armeabi-v7a/
	LOCAL_LDLIBS          += -L$(ANDROID)/arm/darm-v7/obj/local/armeabi-v7a/
	LOCAL_LDFLAGS         += -lc -llog -lanemu -ldarm
endif
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE            := emu-jpeg
LOCAL_MODULE_TAGS       := optional
LOCAL_REQUIRED_MODULES  := libdarm
LOCAL_SHARED_LIBRARIES  := libexif libdl
LOCAL_C_INCLUDES        := external/jhead
# LOCAL_WHOLE_STATIC_LIBRARIES  += libanemu
LOCAL_STATIC_LIBRARIES  += libanemu
LOCAL_ARM_MODE          := arm
LOCAL_SRC_FILES         := tests/jpeg.c
LOCAL_CFLAGS            += -O0 -Wall -march=armv7-a -mcpu=cortex-a9 -mfloat-abi=soft
# DEBUG: keep macros + debug symbols
LOCAL_CFLAGS            += -g3
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE            := emu-asm
LOCAL_MODULE_TAGS       := optional
# LOCAL_STATIC_LIBRARIES  += libanemu
# LOCAL_SHARED_LIBRARIES  := libdl
# LOCAL_WHOLE_STATIC_LIBRARIES  += libanemu
LOCAL_ARM_MODE          := arm
LOCAL_SRC_FILES         := tests/asm.c
LOCAL_CFLAGS            += -O0 -Wall -march=armv7-a -mcpu=cortex-a9 -mfloat-abi=soft
# DEBUG: keep macros + debug symbols
LOCAL_CFLAGS            += -g3
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE            := emu-trap
LOCAL_MODULE_TAGS       := optional
# LOCAL_WHOLE_STATIC_LIBRARIES  += libanemu
LOCAL_STATIC_LIBRARIES  += libanemu
LOCAL_SHARED_LIBRARIES  := libdl
LOCAL_ARM_MODE          := arm
LOCAL_SRC_FILES         := tests/trap.c
LOCAL_CFLAGS            += -O0 -Wall -march=armv7-a -mcpu=cortex-a9
# DEBUG: keep macros + debug symbols
# LOCAL_CFLAGS            += -g3
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE            := emu-bench
LOCAL_MODULE_TAGS       := optional
# LOCAL_WHOLE_STATIC_LIBRARIES  += libanemu
LOCAL_STATIC_LIBRARIES  += libanemu
LOCAL_SHARED_LIBRARIES  += libdl
LOCAL_ARM_MODE          := arm
LOCAL_SRC_FILES         := tests/bench.c
LOCAL_CFLAGS            += -O0 -Wall -march=armv7-a -mcpu=cortex-a9
LOCAL_CFLAGS            += -DANDROID_SMP=1
LOCAL_C_INCLUDES        += bionic/darm-v7
LOCAL_C_INCLUDES        += bionic/libc/private
# DEBUG: keep macros + debug symbols
# LOCAL_CFLAGS            += -g3
# include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE            := emu-pass
LOCAL_MODULE_TAGS       := optional
LOCAL_STATIC_LIBRARIES  += libanemu
LOCAL_SHARED_LIBRARIES  += libdl
LOCAL_ARM_MODE          := arm
LOCAL_SRC_FILES         := tests/pass.c
LOCAL_CFLAGS            += -O3 -Wall -march=armv7-a -mcpu=cortex-a9
LOCAL_CFLAGS            += -DANDROID_SMP=1
LOCAL_CFLAGS            += -g3
include $(BUILD_EXECUTABLE)
