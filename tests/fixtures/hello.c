#include <stdio.h>

static int helper(int x) {
    return x + 7;
}

int main(void) {
    puts("hello ghidra");
    return helper(35);
}
