/* ow_htl.h - Hardware Translation Layer Device Interface */
#ifndef OW_HTL_H
#define OW_HTL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    HTL_OK                  = 0,
    HTL_ERR_IO              = 1,
    HTL_ERR_TIMEOUT         = 2,
    HTL_ERR_INVALID_BLOCK   = 3,
    HTL_ERR_NOT_READY       = 4,
    HTL_ERR_WRITE_PROTECT   = 5,
    HTL_ERR_NO_DEVICE       = 6,
    HTL_ERR_INVALID_PARAM   = 7
} htl_status_t;

typedef enum {
    HTL_DEV_UNKNOWN         = 0,
    HTL_DEV_NVME            = 1,
    HTL_DEV_AHCI_SATA       = 2,
    HTL_DEV_USB_MASS        = 3
} htl_device_type_t;

typedef htl_status_t (*htl_read_block_fn)(void *ctx, uint32_t block_num, void *buf, uint32_t block_size);
typedef htl_status_t (*htl_write_block_fn)(void *ctx, uint32_t block_num, const void *buf, uint32_t block_size);
typedef htl_status_t (*htl_flush_cache_fn)(void *ctx);
typedef htl_status_t (*htl_entropy_fn)(void *ctx, uint8_t *out, size_t len);

typedef struct {
    htl_read_block_fn    read_block;
    htl_write_block_fn   write_block;
    htl_flush_cache_fn   flush_cache;
    htl_entropy_fn       entropy;        /* optional HW RNG for per-volume nonces */
    void                *driver_ctx;
    htl_device_type_t    device_type;
    uint32_t             block_size;
    uint32_t             total_blocks;
    uint8_t              write_protect;
    uint8_t              reserved[3];
} htl_device_t;

bool htl_device_valid(const htl_device_t *dev);
htl_status_t htl_read_block(htl_device_t *dev, uint32_t block_num, void *buf);
htl_status_t htl_write_block(htl_device_t *dev, uint32_t block_num, const void *buf);
htl_status_t htl_flush_cache(htl_device_t *dev);
htl_status_t htl_zero_block(htl_device_t *dev, uint32_t block_num);

/* Fill `len` bytes from the device entropy source. Returns
 * HTL_ERR_NOT_READY when the driver provides no entropy callback. */
htl_status_t htl_get_entropy(htl_device_t *dev, uint8_t *out, size_t len);

#endif /* OW_HTL_H */
