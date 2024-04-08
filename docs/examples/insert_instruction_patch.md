# InsertInstructionPatch

We have a simple C program:

```c title="examples/insert_instruction_patch/add.c"
--8<-- "examples/insert_instruction_patch/add.c"
```

And here is the disassembly of the compiled binary:

```asm title="examples/insert_instruction_patch/add"
0000000000001149 <add>:
    1149:	f3 0f 1e fa          	endbr64
    114d:	55                   	push   %rbp
    114e:	48 89 e5             	mov    %rsp,%rbp
    1151:	89 7d fc             	mov    %edi,-0x4(%rbp)
    1154:	89 75 f8             	mov    %esi,-0x8(%rbp)
    1157:	8b 55 fc             	mov    -0x4(%rbp),%edx
    115a:	8b 45 f8             	mov    -0x8(%rbp),%eax
    115d:	01 d0                	add    %edx,%eax
    115f:	5d                   	pop    %rbp
    1160:	c3                   	ret

0000000000001161 <main>:
    1161:	f3 0f 1e fa          	endbr64
    1165:	55                   	push   %rbp
    1166:	48 89 e5             	mov    %rsp,%rbp
    1169:	be 03 00 00 00       	mov    $0x3,%esi
    116e:	bf 02 00 00 00       	mov    $0x2,%edi
    1173:	e8 d1 ff ff ff       	call   1149 <add>
    1178:	89 c6                	mov    %eax,%esi
    117a:	48 8d 05 83 0e 00 00 	lea    0xe83(%rip),%rax        # 2004 <_IO_stdin_used+0x4>
    1181:	48 89 c7             	mov    %rax,%rdi
    1184:	b8 00 00 00 00       	mov    $0x0,%eax
    1189:	e8 c2 fe ff ff       	call   1050 <printf@plt>
    118e:	b8 00 00 00 00       	mov    $0x0,%eax
    1193:	5d                   	pop    %rbp
    1194:	c3                   	ret
```

Suppose we want to modify the add function to do some 
extra calculations on the first argument, for example doubling it and adding 5, without changing the rest of the
function. We can use Patcherex2's `InsertInstructionPatch`
to insert these instructions at the address `114d` which is
at the beginning of the function. To insert instructions, we
need at least enough space to fit a jump instruction
before the function ends, so we cannot insert them
later on in the function.
Here is how:

```python title="examples/insert_instruction_patch/patch.py"
--8<-- "examples/insert_instruction_patch/patch.py"
```

Now we can run this script and run the patched binary
to see the result:

```bash
$ ./add.patched
2 + 3 = 12
```

We have successfully modified the binary at the
instruction level.
