#include <stdio.h>
#include <string.h>

char flag[] = "FLAG{stack_smashing_detected}";

void secret() {
    printf("Congratulations! %s\n", flag);
}

void vulnerable() {
    char buffer[64];
    printf("Enter your name: ");
    gets(buffer);  // Vulnerable!
    printf("Hello, %s!\n", buffer);
}

int main() {
    vulnerable();
    return 0;
}
