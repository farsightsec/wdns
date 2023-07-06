#ifndef MY_NUM_TO_STR_H
#define MY_NUM_TO_STR_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * Format bytes as a null-terminated hex string, with each byte represented as two characters.
 * Returns a pointer to the newly formatted string.
 */
const char *my_bytes_to_hex_str(const uint8_t *src, size_t len, bool is_upper, char *dst);

/*
 * Format num as hex string, but without a nul terminating byte.
 * Returns a pointer to the newly formatted string.
 */
const char *my_uint16_to_hex_str(uint16_t num, bool is_upper, char *dst);

/*
 * Format num as numerical string, front padded with zeroes to size chars, without a nul terminating byte.
 * Returns a pointer to the newly formatted string.
 */
const char *my_uint64_to_str_padded(uint64_t num, int size, char *dst);

/*
 * Format num as null-terminated numerical string, returning the string length.
 */
size_t my_uint64_to_str(uint64_t num, char *dst);

#endif /* MY_NUM_TO_STR_H */