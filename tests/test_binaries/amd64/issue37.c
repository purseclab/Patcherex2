#include <stdio.h>
#include <stdlib.h>

/* Force jge rel32; compilers normally use rel8 for nearby targets. */
__asm__(
    ".intel_syntax noprefix\n"
    ".text\n"
    ".globl check\n"
    ".type check, @function\n"
    "check:\n"
    "    push rbp\n"
    "    mov rbp, rsp\n"
    "    mov dword ptr [rbp - 4], edi\n"
    "    mov dword ptr [rbp - 8], esi\n"
    "    mov eax, dword ptr [rbp - 4]\n"
    "    cmp eax, dword ptr [rbp - 8]\n"
    "    .byte 0x0f, 0x8d\n"
    "    .long skip - . - 4\n"
    "    mov eax, 0\n"
    "    pop rbp\n"
    "    ret\n"
    "skip:\n"
    "    mov eax, 1\n"
    "    pop rbp\n"
    "    ret\n"
    ".size check, .-check\n"
    ".att_syntax prefix\n"
);

int check(int budget, int cost);

int main(void) {
    char input[16];
    if (fgets(input, sizeof(input), stdin) == NULL) {
        return 2;
    }
    int cost = atoi(input);
    printf("check(10, %d) -> %d\n", cost, check(10, cost));
    return 0;
}
