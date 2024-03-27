# Patcherex2

[![Latest Release](https://img.shields.io/pypi/v/patcherex2.svg)](https://pypi.python.org/pypi/patcherex2/)
[![PyPI Statistics](https://img.shields.io/pypi/dm/patcherex2.svg)](https://pypistats.org/packages/patcherex2)
[![CI](https://img.shields.io/github/actions/workflow/status/purseclab/patcherex2/ci.yml?label=CI
)](https://github.com/purseclab/Patcherex2/actions/workflows/test.yml)
[![License](https://img.shields.io/github/license/purseclab/patcherex2.svg)](https://github.com/purseclab/Patcherex2/blob/main/LICENSE)

Patcherex2 is a rewritten adaptation of the original [Patcherex](https://github.com/angr/patcherex) project, aimed at building upon its core ideas and extending its capabilities.

## Installation

Patcherex2 is available on PyPI and can be installed using pip. Alternatively, you can use the provided Docker image.

### pip
```bash
pip install patcherex2
```
<details>
<summary>Install from latest commit</summary>

```bash
pip install git+https://github.com/purseclab/Patcherex2.git
```
</details>

### Docker
```bash
docker run --rm -it -v ${PWD}:/workdir -w /workdir ghcr.io/purseclab/patcherex2
```

<details>
<summary>Build from latest commit</summary>

```bash
docker build -t --platform linux/amd64 patcherex2 https://github.com/purseclab/Patcherex2.git
docker run --rm -it -v ${PWD}:/workdir -w /workdir patcherex2
```
</details>

<br>

Examples and more rigorous documentation can be found [here](https://purseclab.github.io/Patcherex2).

### Patch Types
The core of Patcherex2 consists of 9 different types of patches, which are used to manipulate the binary in different ways.

|          | Data              | Instruction         | Function            |
|---------:|-------------------|---------------------|---------------------|
| _**Insert**_ | InsertDataPatch   | InsertInstructionPatch | InsertFunctionPatch |
| _**Remove**_ | RemoveDataPatch   | RemoveInstructionPatch | RemoveFunctionPatch |
| _**Modify**_ | ModifyDataPatch   | ModifyInstructionPatch | ModifyFunctionPatch |

These patches are categorized into three tiers:
 - Data Patches: 
    Operating at the raw bytes level, data patches are ideal for patching the `.data` section or any other raw data.

 - Instruction Patches:
    These patches target the instruction level, enabling modifications to the assembly code of the binary.

 - Function Patches:
    At the highest level, function patches manipulate the binary through C code, this level deals with modifications at the function level.

Each tier features three patch types:
 - Insert Patch: Adds new data, instructions, or functions to the binary.
 - Remove Patch: Deletes existing data, instructions, or functions from the binary.
 - Modify Patch: Replaces the content of data, instructions, or functions within the binary.

#### Insert{Data, Instruction, Function}Patch
 - Syntax
    ```python
    Insert*Patch(addr_or_name, content)
    ```
    - Arguments
        - `addr_or_name`: The address or name of the {data, instruction, function} to be inserted.
            - When the first argument is an address, patcherex will insert content right before the given address.
            - When the first argument is a name, patcherex will automatically find free spaces in the binary and insert the content there, and the `name` provided can be later used for referencing the inserted content.
        - `content`: The content to be inserted.
            - Content is different for each patch type:
                - For `InsertDataPatch`, `content` is a byte string.
                - For `InsertInstructionPatch`, `content` is a list of assembly instructions, separated by newlines.
                - For `InsertFunctionPatch`, `content` is a C function. 

#### Modify{Data, Instruction, Function}Patch
 - Syntax
    ```python
    Modify*Patch(addr_or_name, content)
    ```
    - Arguments
        - `addr_or_name`: The address or name of the {data, instruction, function} to be modified.
            - When the first argument is an address, patcherex will modify the content at the given address.
            - When the first argument is a name, patcherex will try to first find the address of the given name/symbol and then modify the content at that address.
        - `content`: The new content to replace the existing content.
            - Content is different for each patch type:
                - For `ModifyDataPatch`, `content` is a byte string.
                - For `ModifyInstructionPatch`, `content` is a list of assembly instructions, separated by newlines.
                - For `ModifyFunctionPatch`, `content` is a C function.

#### Remove{Data, Instruction, Function}Patch
 - Syntax
    ```python
    Remove*Patch(addr_or_name, num_bytes: int)
    ```
    - Arguments
        - `addr_or_name`: The address or name of the {data, instruction, function} to be removed.
            - When the first argument is an address, patcherex will remove the content at the given address.
            - When the first argument is a name, patcherex will try to first find the address of the given name/symbol and then remove the content at that address.
        - `num_bytes`: This is optional for `RemoveInstructionPatch` and `RemoveFunctionPatch`, but required for `RemoveDataPatch`, and specifies the number of bytes to be removed.

#### Referencing previously inserted content.
Examples:
- This will load effective address of the data `my_data` into the `rsi` register.
    ```python
    InsertDataPatch("my_data", b"Hello, World!")
    InsertInstructionPatch(0xdeadbeef, "lea rsi, [{my_data}]")
    ```
- This will replace the content of function `foo` to call function `bar` and return the result.
    ```python
    InsertFunctionPatch("bar", "int bar() { return 42; }")
    ModifyFunctionPatch("foo", "int bar(void); int foo() { return bar(); }")
    ```


### Patcherex2 Advanced Usage
#### Reuse Unreachable Code Locations
Patcherex2 can be used to reuse unreachable code locations in the binary.
Add the following code anywhere before `apply_patches` to reuse unreachable code.

```python
for func in p.binary_analyzer.get_unused_funcs():
    p.allocation_manager.add_free_space(func["addr"], func["size"], "RX")
```

### Pre- and Post- Function Hooks
Patcherex2 allows you to add pre- and post- function hooks to the function call when using `InsertFunctionPatch` and first argument is a address.

```python
InsertFunctionPatch(0xdeadbeef, "int foo(int a) { return bar(); }", prefunc="mov rdi, 0x10", postfunc="mov rdi, rax")
```
At the address `0xdeadbeef`, pre-function hook `mov rdi, 0x10` will be executed before the function `foo` is called and post-function hook `mov rdi, rax` will be executed after the function `foo` is called. This is useful when you want to pass arguments to the function or get the return value from the function.

### Save Context and Restore Context when using `Insert*Patch`
When using `InsertInstructionPatch` or `InsertFunctionPatch`, it is possible to save the context before the inserted content and restore the context after the inserted content. This is useful when the inserted content modifies the context.

```python
InsertInstructionPatch(0xdeadbeef, "push rbp", save_context=True)
```

## Supported Targets

|           | Linux x86 | Linux amd64 | Linux arm | Linux aarch64 | Linux PowerPC (32bit) | Linux PowerPC (64bit) | Linux PowerPCle (64bit) | Linux MIPS (32bit) | Linux MIPS (64bit) | Linux MIPSEL<br>​(32bit) | Linux MIPSEL<br>(64bit) | SPARCv8 (LEON3) | PowerPC (VLE) (IHEX)
|-|-|-|-|-|-|-|-|-|-|-|-|-|-|
InsertDataPatch         | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | ⬜ | ⬜ |
RemoveDataPatch         | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | ⬜ | ⬜ |
ModifyDataPatch         | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | ⬜ | ⬜ |
InsertInstructionPatch  | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | ⬜ | ⬜ |
RemoveInstructionPatch  | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | ⬜ | ⬜ |
ModifyInstructionPatch  | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | ⬜ | ⬜ |
InsertFunctionPatch     | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | ⬜ | ⬜ |
ModifyFunctionPatch     | 🟨 | 🟩 | 🟩 | 🟩 | 🟨 | 🟨 | 🟨 | 🟨 | 🟨 | 🟨 | 🟨 | ⬜ | ⬜ |

🟩 Fully Functional, 🟨 Limited Functionality, 🟥 Not Working, ⬜ Not Tested, 🟪 Work in Progress
