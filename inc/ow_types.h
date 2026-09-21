/* ow_types.h - OpenWindows Core Types */
#ifndef OW_TYPES_H
#define OW_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef uint32_t OW_STATUS;

#define OW_SUCCESS              0x00000000U
#define OW_ERR_INVALID_PARAM    0x0011AEE0U
#define OW_ERR_NULL_POINTER     0x0011AEE1U
#define OW_ERR_NOT_FOUND        0x0011AEE2U
#define OW_ERR_ALREADY_EXISTS   0x0011AEE3U
#define OW_ERR_INSUFFICIENT     0x0011AEE4U
#define OW_ERR_NOT_INITIALIZED  0x0011AEE9U
#define OW_ERR_IO               0x00000001U
#define OW_ERR_CORRUPT          0x0011A3E0U

#define OW_MAX_NAME             256U
#define OW_MAX_PATH             512U

static inline bool ow_status_success(OW_STATUS s) { return s == OW_SUCCESS; }
static inline bool ow_status_error(OW_STATUS s) { return s != OW_SUCCESS; }

#endif /* OW_TYPES_H */
