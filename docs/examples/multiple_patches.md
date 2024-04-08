# Multiple Patches

Here is a simple example of a vulnerable C program which we will use to show how different patches can be used together:

```c title="examples/multiple_patches/getline.c"
--8<-- "examples/multiple_patches/getline.c"
```

And here is the disassembly of the relevant functions:

```asm title="examples/multiple_patches/getline"
0000000000001189 <my_getline>:
    1189:	f3 0f 1e fa          	endbr64
    118d:	55                   	push   %rbp
    118e:	48 89 e5             	mov    %rsp,%rbp
    1191:	48 83 ec 20          	sub    $0x20,%rsp
    1195:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
    1199:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    11a0:	48 8b 05 69 2e 00 00 	mov    0x2e69(%rip),%rax        # 4010 <stdin@GLIBC_2.2.5>
    11a7:	48 89 c7             	mov    %rax,%rdi
    11aa:	e8 e1 fe ff ff       	call   1090 <getc@plt>
    11af:	88 45 fb             	mov    %al,-0x5(%rbp)
    11b2:	80 7d fb 0a          	cmpb   $0xa,-0x5(%rbp)
    11b6:	74 1b                	je     11d3 <my_getline+0x4a>
    11b8:	8b 45 fc             	mov    -0x4(%rbp),%eax
    11bb:	8d 50 01             	lea    0x1(%rax),%edx
    11be:	89 55 fc             	mov    %edx,-0x4(%rbp)
    11c1:	48 63 d0             	movslq %eax,%rdx
    11c4:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    11c8:	48 01 c2             	add    %rax,%rdx
    11cb:	0f b6 45 fb          	movzbl -0x5(%rbp),%eax
    11cf:	88 02                	mov    %al,(%rdx)
    11d1:	eb cd                	jmp    11a0 <my_getline+0x17>
    11d3:	90                   	nop
    11d4:	8b 45 fc             	mov    -0x4(%rbp),%eax
    11d7:	48 63 d0             	movslq %eax,%rdx
    11da:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    11de:	48 01 d0             	add    %rdx,%rax
    11e1:	c6 00 00             	movb   $0x0,(%rax)
    11e4:	8b 45 fc             	mov    -0x4(%rbp),%eax
    11e7:	c9                   	leave
    11e8:	c3                   	ret

00000000000011e9 <main>:
    11e9:	f3 0f 1e fa          	endbr64
    11ed:	55                   	push   %rbp
    11ee:	48 89 e5             	mov    %rsp,%rbp
    11f1:	48 83 ec 20          	sub    $0x20,%rsp
    11f5:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
    11fc:	00 00 
    11fe:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1202:	31 c0                	xor    %eax,%eax
    1204:	48 8d 45 ee          	lea    -0x12(%rbp),%rax
    1208:	48 89 c7             	mov    %rax,%rdi
    120b:	e8 79 ff ff ff       	call   1189 <my_getline>
    1210:	48 8d 45 ee          	lea    -0x12(%rbp),%rax
    1214:	48 89 c7             	mov    %rax,%rdi
    1217:	e8 54 fe ff ff       	call   1070 <puts@plt>
    121c:	b8 00 00 00 00       	mov    $0x0,%eax
    1221:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
    1225:	64 48 2b 14 25 28 00 	sub    %fs:0x28,%rdx
    122c:	00 00 
    122e:	74 05                	je     1235 <main+0x4c>
    1230:	e8 4b fe ff ff       	call   1080 <__stack_chk_fail@plt>
    1235:	c9                   	leave
    1236:	c3                   	ret
```

The program currently reads a string from standard input and echos it back. We can run it with short strings:
```bash
$ ./getline
aaaaa
aaaaa
```
And it works fine. Using a longer string, however will cause it to crash:
```bash
$ ./getline
aaaaaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaaaaa
*** stack smashing detected ***: terminated
[1]    194473 IOT instruction (core dumped)  ./getline
```

We will patch this program to fix the vulnerability, by adding a second argument to the `my_getline` function, and printing a message when the buffer would have overflowed. Here is the script:

```python title="examples/multiple_patches/patch.py"
--8<-- "examples/multiple_patches/patch.py"
```

This patch adds the buffer size as a second argument to `my_getline`. To do this we insert instructions at the beginning to save the argument, and in the loop body we insert a check to see if the index is out of bounds. When it is, we print a message, which was inserted using the `InsertDataPatch`. We can use the `SAVE_CONTEXT` and `RESTORE_CONTEXT` macros (expanded by Patcherex2) to do operations that could modify data we have in registers, like calling a function. We also insert instructions in `main` to put the buffer size in `esi` before calling the function. Now we can run the script to patch the binary and run the new fixed program:
```bash
$ ./getline.patched 
aaaaaaaaaaaaaaaaaaaaaaa
Ran out of space
aaaaaaaaa
```

We have successfully fixed the bug with Patcherex2.
