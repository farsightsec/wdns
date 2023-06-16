#ifndef MY_NUM_TO_STR_H
#define MY_NUM_TO_STR_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * Formats bytes in src to hexadecimal null terminated, front padded with 0 string:
 * 	0x1f1e1d -> '1f1e1d\0'
 * 	0xf -> '0f\0'
 *
 * \return Pointer to dst.
 */
const char * my_bytes_to_hex_str(const uint8_t *src, size_t len, bool is_upper, char *dst);

/**
 * Formats num to hexadecimal string.
 * does not terminate with 0
 *
 * \return Pointer to place in dst after inserted symbols.
 */
const char * my_uint16_to_hex_str(uint16_t num, bool is_upper, char *dst);

/**
 * Formats num as numerical string front padded with 0.
 * does not terminate with 0
 * \return Pointer to dst.
 */
const char *my_uint64_to_str_padded(uint64_t num, int size, char *dst);

/**
 * Formats num as numerical string 0 terminated string.
 *
 * \return Size of numerical string.
 */
size_t my_uint64_to_str(uint64_t num, char *dst);

#endif /* MY_NUM_TO_STR_H */