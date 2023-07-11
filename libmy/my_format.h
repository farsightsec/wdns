#ifndef MY_NUM_TO_STR_H
#define MY_NUM_TO_STR_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * Format bytes as a NUL-terminated hex string into dst, with each byte represented as two characters.
 * for up to dst_size bytes
 *
 * Returns a size of formatted string or dst_size (whichever is less).
 */
size_t my_bytes_to_hex_str(const uint8_t *src, size_t len, bool is_upper, char *dst, size_t dst_size);

/*
 * Format uint16_t num as NUL-terminated hex string for up to dst_size.
 *
 * Returns a size of formatted string or dst_size (whichever is less).
 */
size_t my_uint16_to_hex_str(uint16_t num, bool is_upper, char *dst, size_t dst_size);

/*
 * Format num as numerical NUL-terminated string up to dst_size, using dst as buffer.
 * Places pointer to the start of formatted string into *start
 * Returns a size of formatted string.
 */
size_t my_uint64_to_str(uint64_t num, char *dst, size_t dst_size, const char **start);


#endif /* MY_NUM_TO_STR_H */
