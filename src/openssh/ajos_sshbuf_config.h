// Configuration for OpenSSH sshbuf in AJOS kernel
// This file should be included before sshbuf.h

#ifndef AJOS_SSHBUF_CONFIG_H
#define AJOS_SSHBUF_CONFIG_H

#include "ajos_compat.h"

// OpenBSD-specific macros
#ifndef __predict_false
#define __predict_false(x) (x)
#endif
#ifndef __predict_true
#define __predict_true(x) (x)
#endif

// ROUNDUP macro
#ifndef ROUNDUP
#define ROUNDUP(x, y) ((((x) + (y) - 1) / (y)) * (y))
#endif

// OpenSSH's sshbuf uses these macros for allocation
// We override them to use kernel kmalloc/kfree
#ifndef SSH_BUFFER_ALLOC
#define SSH_BUFFER_ALLOC(x) kmalloc(x)
#endif

#ifndef SSH_BUFFER_FREE
#define SSH_BUFFER_FREE(x) kfree(x)
#endif

// OpenSSH uses malloc/calloc/realloc/free directly in some places
// These are already defined in ajos_compat.h, but we ensure they're available
// (malloc/free are already macros in ajos_compat.h)

#endif // AJOS_SSHBUF_CONFIG_H
