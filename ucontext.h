// #include <signal.h>
#include <asm/sigcontext.h>

#ifndef _UCONTEXT_H
#define _UCONTEXT_H 1

typedef struct sigcontext mcontext_t;

typedef struct ucontext {
    uint32_t          uc_flags;
    struct ucontext*  uc_link;
    stack_t           uc_stack;
    mcontext_t        uc_mcontext;
    /* Only expose the 32 non-realtime signals in Bionic's 32-bit sigset_t
     * The _unused field is required padding from the kernel. */
    sigset_t          uc_sigmask;
    int               _unused[32 - sizeof(sigset_t)/sizeof(int)];
    uint32_t          uc_regspace[128] __attribute__((__aligned__(8)));
} ucontext_t;

#endif
