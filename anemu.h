#ifndef _INCLUDE_ANEMU_H_
#define _INCLUDE_ANEMU_H_

#ifdef __cplusplus
extern "C" {  // only need to export C interface if
              // used by C++ source code
#endif

/* Public API */

void emu_register_handler();

#ifdef __cplusplus
}
#endif

#endif  /* _INCLUDE_ANEMU_H_ */
