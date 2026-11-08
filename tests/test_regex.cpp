// Reproduce the CRLF stop-pattern bug found by static analysis.
// A real file is read through the production regex_list implementation.
// Patterns must lose the carriage return without dereferencing string::end.
// The compiled expression must then match an ordinary input line.
// This regression runs with native and sanitizer builds using their regex ABI.
#include "config.h"
#include "beregex.h"
#include <cstdio>
#include <unistd.h>

int main()
{
    char path[] = "tcpflow-regex-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return 1;
    const char text[] = "([a-z]+)\r\n";
    bool valid = write(fd, text, sizeof(text) - 1) == sizeof(text) - 1;
    close(fd);
    regex_list patterns;
    valid = patterns.readfile(path) == 0 && valid;
    unlink(path);
    if (!valid || patterns.patterns.empty() || patterns.patterns[0]->pat != "([a-z]+)") return 1;
    std::string found;
    size_t offset = 0, length = 0;
    return patterns.check("abc", &found, &offset, &length) && found == "abc" && offset == 0 && length == 3 ? 0 : 1;
}
