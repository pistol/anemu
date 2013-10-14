#ifndef _INCLUDE_ANEMU_H_
#define _INCLUDE_ANEMU_H_

#ifdef __cplusplus
extern "C" {  // only need to export C interface if
              // used by C++ source code
#endif

#define EMU_MARKER_START asm volatile("bkpt 0");
#define EMU_MARKER_STOP  asm volatile("bkpt 1337")

/* Public API */
void emu_register_handler();

void emu_set_taint_mem(uint32_t addr, uint32_t tag);
void emu_set_taint_array(uint32_t addr, uint32_t tag, uint32_t length);

bool emu_enabled();

#ifdef __cplusplus
}
#endif

#endif  /* _INCLUDE_ANEMU_H_ */
