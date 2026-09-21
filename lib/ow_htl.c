/* ow_htl.c - Hardware Translation Layer Device Operations */
#include "ow_htl.h"

bool htl_device_valid(const htl_device_t *dev) {
    if (!dev) return false;
    if (!dev->read_block || !dev->write_block) return false;
    if (dev->block_size == 0 || dev->total_blocks == 0) return false;
    return true;
}

htl_status_t htl_read_block(htl_device_t *dev, uint32_t block_num, void *buf) {
    if (!dev || !buf) return HTL_ERR_INVALID_PARAM;
    if (!dev->read_block) return HTL_ERR_NO_DEVICE;
    if (block_num >= dev->total_blocks) return HTL_ERR_INVALID_BLOCK;
    return dev->read_block(dev->driver_ctx, block_num, buf, dev->block_size);
}

htl_status_t htl_write_block(htl_device_t *dev, uint32_t block_num, const void *buf) {
    if (!dev || !buf) return HTL_ERR_INVALID_PARAM;
    if (!dev->write_block) return HTL_ERR_NO_DEVICE;
    if (dev->write_protect) return HTL_ERR_WRITE_PROTECT;
    if (block_num >= dev->total_blocks) return HTL_ERR_INVALID_BLOCK;
    return dev->write_block(dev->driver_ctx, block_num, buf, dev->block_size);
}

htl_status_t htl_flush_cache(htl_device_t *dev) {
    if (!dev) return HTL_ERR_INVALID_PARAM;
    if (!dev->flush_cache) return HTL_OK;
    return dev->flush_cache(dev->driver_ctx);
}

htl_status_t htl_zero_block(htl_device_t *dev, uint32_t block_num) {
    uint8_t zero[4096];
    uint32_t i;
    if (!dev) return HTL_ERR_INVALID_PARAM;
    for (i = 0; i < dev->block_size && i < 4096; i++) zero[i] = 0;
    return htl_write_block(dev, block_num, zero);
}

htl_status_t htl_get_entropy(htl_device_t *dev, uint8_t *out, size_t len) {
    if (!htl_device_valid(dev) || !out || len == 0) {
        return HTL_ERR_INVALID_PARAM;
    }
    if (!dev->entropy) {
        return HTL_ERR_NOT_READY;
    }
    return dev->entropy(dev->driver_ctx, out, len);
}
