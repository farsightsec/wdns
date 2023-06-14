#ifndef MY_NUM_TO_STR_H
#define MY_NUM_TO_STR_H


const char * my_uint8_to_hex_str_padded(uint8_t num, char *dst);
const char * my_uint8_to_hex_STR_padded(uint8_t num, char *dst);
const char *my_uint16_to_hex_str(uint16_t num, char *dst);
const char * my_uint64_to_str_padded(uint64_t num, int size, char * dst);
size_t my_uint64_to_str(uint64_t num, char *dst);

#endif /* MY_NUM_TO_STR_H */