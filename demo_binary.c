//gcc demo_binary.c -o demo_binary -fno-stack-protector -z execstack -no-pie
//./demo_binary
#include <stdio.h>

void vuln() {
    char buf[64];
    puts("Enter input:");
    gets(buf);         
}

int main() {
    vuln();
    return 0;
}
