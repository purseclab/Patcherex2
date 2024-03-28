# Advanced Usage

## Reuse Unreachable Code Locations
Patcherex2 can be used to reuse unreachable code locations in the binary.
Add the following code anywhere before `apply_patches` to reuse unreachable code.

```python
for func in p.binary_analyzer.get_unused_funcs():
    p.allocation_manager.add_free_space(func["addr"], func["size"], "RX")
```

## Pre- and Post- Function Hooks
Patcherex2 allows you to add pre- and post- function hooks to the function call when using `InsertFunctionPatch` and first argument is a address.

```python
InsertFunctionPatch(0xdeadbeef, "int foo(int a) { return bar(); }", prefunc="mov rdi, 0x10", postfunc="mov rdi, rax")
```
At the address `0xdeadbeef`, pre-function hook `mov rdi, 0x10` will be executed before the function `foo` is called and post-function hook `mov rdi, rax` will be executed after the function `foo` is called. This is useful when you want to pass arguments to the function or get the return value from the function.

## Save Context and Restore Context when using `Insert*Patch`
When using `InsertInstructionPatch` or `InsertFunctionPatch`, it is possible to save the context before the inserted content and restore the context after the inserted content. This is useful when the inserted content modifies the context.

```python
InsertInstructionPatch(0xdeadbeef, "push rbp", save_context=True)
```
