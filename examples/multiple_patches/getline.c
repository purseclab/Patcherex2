#include <stdio.h>

int my_getline(char* buf) {
    int i = 0;
    while (1) {
        char c = getc(stdin);
        if (c == '\n') break;
        buf[i++] = c;
    }
    buf[i] = '\0';
    return i;
}

int main() {

    char buf[10];
    my_getline(buf);
    puts(buf);

    return 0;
}