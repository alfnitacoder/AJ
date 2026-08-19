// Minimal includes.h for OpenSSH in AJOS kernel
// This replaces OpenSSH's includes.h which has many POSIX dependencies

#ifndef INCLUDES_H
#define INCLUDES_H

// AJOS compatibility layer (must come first for malloc/free macros)
#include "ajos_compat.h"

// System types (defined in ajos_compat.h, no need to include headers)
// All standard types are defined manually since we use -nostdinc

// OpenSSH-specific includes
#include "openssh/ssherr.h"

// Forward declarations (will be included when needed)
// #include "openssh/sshbuf.h"  // Included in files that need it

#endif // INCLUDES_H
