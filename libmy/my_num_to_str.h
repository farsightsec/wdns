#ifndef MY_NUM_TO_STR_H
#define MY_NUM_TO_STR_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * Format bytes as a NUL-terminated hex string, with each byte represented as two characters.
 * Returns a pointer to the newly formatted string.
 */
const char *my_bytes_to_hex_str(const uint8_t *src, size_t len, bool is_upper, char *dst);

/*
 * Format num as NUL-terminated hex string.
 * Returns a pointer to the newly formatted string.
 */
const char *my_uint16_to_hex_str(uint16_t num, bool is_upper, char *dst);

/*
 * Format num as numerical string, front padded with zeroes to ndigits chars, without a NUL terminating byte.
 * Returns a pointer to the newly formatted string.
 */
const char *my_uint64_to_str_padded(uint64_t num, uint32_t ndigits, char *dst);

/*
 * Format num as NUL-terminated numerical string, returning the string length.
 */
size_t my_uint64_to_str(uint64_t num, char *dst);

#endif /* MY_NUM_TO_STR_H */
