#pragma once

#ifdef _WIN32

#define _PACKED_ 

#include <windows.h>

#define u_int8_t  UCHAR
#define u_int16_t USHORT
#define u_int32_t ULONG
#define u_int64_t ULONGLONG

#define int8_t  CHAR
#define int16_t SHORT
#define int32_t LONG
#define int64_t LONGLONG

#define u_char  UCHAR

#else

#define _PACKED_  __attribute__((__packed__))

#endif
