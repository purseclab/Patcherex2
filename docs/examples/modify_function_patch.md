# ModifyFunctionPatch

Consider a simple C program:

```c title="examples/modify_function_patch/add.c"
--8<-- "examples/modify_function_patch/add.c"
```

After compiling and executing this program, the output is:

```bash
$ gcc -o add add.c && ./add
2 + 3 = 5
```

Now, we can use Patcherex2 to modify the `add` function to multiply the two arguments instead of adding them.

```python title="examples/modify_function_patch/patch.py"
--8<-- "examples/modify_function_patch/patch.py"
```

Executing the patched program yields a different result:

```bash
$ ./add_patched
2 + 3 = 6
```

💥 We've successfully modified the binary with Patcherex2!
