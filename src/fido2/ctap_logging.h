#ifndef __CTAP_LOGGING_H
#define __CTAP_LOGGING_H

#if defined(SEMIHOSTING)

inline void dump_hex(const uint8_t* buf, int size)
{
    while(size--)
    {
        printf("%02x ", *buf++);
    }
    printf("\n");
}

inline void ctap_dump_hex1(const char* tag, const uint8_t* data, int length)
{
    printf("%s: ",  tag);
    dump_hex(data,length);
    printf("\n");
}

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

#if defined(CTAP_PRINT_TO_SCREEN)
#define printf1(tag, ...) \
    do { \
        screen_sprintf_debug(500, #tag __VA_ARGS__); \
    } while(0);

#define printf2(tag, ...) \
    do { \
        screen_sprintf_debug(500, #tag __VA_ARGS__); \
    } while(0);

#else
inline void ctap_logging_discard_args(const char* tag, ...) {
    (void)tag;
}

#define printf1(tag, ...)  \
    do { \
        ctap_logging_discard_args(#tag, __VA_ARGS__); \
    } while(0)

#define printf2(tag, ...) \
    do { \
        ctap_logging_discard_args(#tag, __VA_ARGS__); \
    } while(0)

#endif // CTAP_PRINT_TO_SCREEN

#endif // SEMIHOSTING

#endif // __CTAP_LOGGING_H
