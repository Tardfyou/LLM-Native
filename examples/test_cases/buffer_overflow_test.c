// Example test case for buffer overflow vulnerability
// This code contains a buffer overflow vulnerability

#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[10];

    // VULNERABILITY: Buffer overflow - no bounds checking
    strcpy(buffer, input);  // If input is longer than 10 chars, this overflows

    printf("Buffer content: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        vulnerable_function(argv[1]);
    }

    return 0;
}
