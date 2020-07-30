/**
  @file nv_types.h

  @brief
  This file defines the general types used by the Nagra product interfaces.

  @details
  It focuses on defining fixed-size integer types and boolean types.

  COPYRIGHT:
    2015 - 2015 Nagravision S.A.
*/

/* ========================================================================== */
/*                         DOCUMENTATION ORGANISATION                         */
/* -------------------------------------------------------------------------- */
/* This file is always part of other documentation and has no independent     */
/* documentation.                                                             */
/* ========================================================================== */

/* ========================================================================== */
/*                              INTERNAL GROUPS                               */
/* ========================================================================== */

#ifndef NV_TYPES_H
#define NV_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================== */
/*                               INCLUDE FILES                                */
/* ========================================================================== */

#include <stddef.h>
#include <limits.h>

#ifndef _NV_REMAP_DEFS_

/* 
  This should be the preferred case unless the targeted platform tool chain 
  does not support fixed-size integer introduced in C99 standard.
*/
#   include <stdint.h>
#   include <stdbool.h>

#else  /* _NV_REMAP_DEFS_ */

#define INT8_MIN        CHAR_MIN
#define INT8_MAX        CHAR_MAX
#define UINT8_MAX       UCHAR_MAX
#define INT16_MIN       SHRT_MIN
#define INT16_MAX       SHRT_MAX
#define UINT16_MAX      USHRT_MAX
#define INT32_MIN       LONG_MIN
#define INT32_MAX       LONG_MAX
#define UINT32_MAX      ULONG_MAX

typedef signed char     int8_t;
typedef unsigned char   uint8_t;
typedef signed short    int16_t;
typedef unsigned short  uint16_t;
typedef signed long     int32_t;
typedef unsigned long   uint32_t;
typedef ptrdiff_t       intptr_t;

#ifndef __cplusplus     /* Boolean is a basic C++ type */
#ifndef bool
typedef uint8_t         bool;
#endif
#ifndef false
# define false          0
#endif
#endif                  /* __cplusplus */

#endif  /* _NV_REMAP_DEFS_ */

#ifdef __cplusplus
}
#endif

#endif /* NV_TYPES_H */

/* ========================================================================== */
/* End of File                                                                */
/* ========================================================================== */
