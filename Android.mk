LOCAL_PATH := $(call my-dir)

# include $(CLEAR_VARS)
# LOCAL_MODULE := libr_asm
# LOCAL_SRC_FILES := ../../arm/radare2/libr/asm/libr_asm.a
# LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/../../arm/radare2/libr/include
# include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_ARM_MODE := arm
LOCAL_MODULE_TAGS := optional

DARM := $(ANDROID)/arm/darm-v7
# RASM := $(ANDROID)/arm/radare2/libr
RASM := $(ANDROID)/arm/radare2/android-install/data/data/org.radare.installer/radare2/

LOCAL_MODULE := anemu 
LOCAL_SRC_FILES := anemu.c test.S rasm.c

LOCAL_STATIC_LIBRARIES := libdarm

LOCAL_CFLAGS += -gdwarf-2 -g3 -O0 -Wall -march=armv7-a -mcpu=cortex-a9 -marm -mfloat-abi=softfp
# LOCAL_CFLAGS += -fno-strict-aliasing
LOCAL_CFLAGS += -I$(DARM)
LOCAL_CFLAGS += -I$(RASM)/include/libr

# LOCAL_LDFLAGS += -L$(DARM) -ldarm
LOCAL_LDFLAGS += -L$(RASM)/lib -lr_asm -lr_util -lr_db -lsdb -lr

# TARGET_ARCH_ABI := armeabi-v7a
# TARGET_PLATFORM := android-14

include $(BUILD_EXECUTABLE)
