#ifndef _INCLUDE_ANEMU_H_
#define _INCLUDE_ANEMU_H_

#ifdef __cplusplus
extern "C" {  // only need to export C interface if
              // used by C++ source code
#endif

#define EMU_MARKER_START asm volatile("bkpt 0");
#define EMU_MARKER_STOP  asm volatile("bkpt 1337")

/* Public API */

typedef struct _taintinfo_t {
    uint32_t addr;
    uint32_t tag;
} taintinfo_t;

typedef struct _DvmEmuGlobals {
    taintinfo_t tinfo;
    bool enabled;
} DvmEmuGlobals;

void emu_register_handler(DvmEmuGlobals* state);

#ifdef __cplusplus
}
#endif

#endif  /* _INCLUDE_ANEMU_H_ */
