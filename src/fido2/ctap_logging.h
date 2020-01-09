#ifndef __CTAP_LOGGING_H
#define __CTAP_LOGGING_H

#if defined(SEMIHOSTING)
void ctap_dump_hex1(const char* tag, const uint8_t* data, int length);

#define dump_hex1(tag, data, length) \
    do { \
        ctap_dump_hex1(#tag, data, length); \
    } while(0);

#define printf1(tag, ...) \
    do { \
        printf(#tag ": " __VA_ARGS__); \
    } while(0);

#define printf2(tag, ...) \
    do { \
        printf(#tag ": " __VA_ARGS__); \
    } while(0);

#else
#define dump_hex1(...)

#define printf1(tag, ...) \
    do { \
        screen_sprintf_debug(500, #tag __VA_ARGS__); \
    } while(0);

#define printf2(tag, ...) \
    do { \
        screen_sprintf_debug(500, #tag __VA_ARGS__); \
    } while(0);

#endif

#endif
