#ifndef MY_NUM_TO_STR_H
#define MY_NUM_TO_STR_H


/**
 * Formats num to hexadecimal null terminated, front padded with 0, lowercase string:
 * 	0x1f -> '1f\0'
 * 	0xf -> '0f\0'
 *
 * \return Pointer to dst.
 */
const char *my_uint8_to_hex_str_padded(uint8_t num, char *dst);

/**
 * Formats num to hexadecimal null terminated, front padded with 0, uppercase string:
 * 	0x1f -> '1F\0'
 * 	0xf -> '0F\0'
 *
 * \return Pointer to dst.
 */
const char *my_uint8_to_hex_STR_padded(uint8_t num, char *dst);

/**
 * Formats num to hexadecimal string.
 * does not terminate with 0
 *
 * \return Pointer to place in dst after inserted symbols.
 */
const char *my_uint16_to_hex_str(uint16_t num, char *dst);

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