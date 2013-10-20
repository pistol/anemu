#ifndef _INCLUDE_ANEMU_H_
#define _INCLUDE_ANEMU_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {  // only need to export C interface if
              // used by C++ source code
#endif

#define MARKER_START_VAL    0x100
#define MARKER_STOP_VAL     0x200

#define EMU_MARKER_START asm volatile("bkpt " #MARKER_START_VAL);
#define EMU_MARKER_STOP  asm volatile("bkpt " #MARKER_STOP_VAL)

/* Public API */
void emu_register_handler();

void emu_set_taint_mem(uint32_t addr, uint32_t tag);
void emu_set_taint_array(uint32_t addr, uint32_t tag, uint32_t length);

bool emu_enabled();

#ifdef __cplusplus
}
#endif

#endif  /* _INCLUDE_ANEMU_H_ */
