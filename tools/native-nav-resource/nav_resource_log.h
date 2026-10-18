#pragma once
#include <cstdio>

namespace zt
{
    inline void info(const char *message)
    {
        std::fputs(message, stderr);
        std::fputc('\n', stderr);
    }

    inline void warn(const char *message)
    {
        info(message);
    }

    template <class First, class... A> void info(const char *format, First first, A... args)
    {
        std::fprintf(stderr, format, first, args...);
        std::fputc('\n', stderr);
    }

    template <class First, class... A> void warn(const char *format, First first, A... args)
    {
        std::fprintf(stderr, format, first, args...);
        std::fputc('\n', stderr);
    }
} // namespace zt
