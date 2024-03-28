## Patch Types

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

### Insert{Data, Instruction, Function}Patch
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

### Modify{Data, Instruction, Function}Patch
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

### Remove{Data, Instruction, Function}Patch
 - Syntax
    ```python
    Remove*Patch(addr_or_name, num_bytes: int)
    ```
    - Arguments
        - `addr_or_name`: The address or name of the {data, instruction, function} to be removed.
            - When the first argument is an address, patcherex will remove the content at the given address.
            - When the first argument is a name, patcherex will try to first find the address of the given name/symbol and then remove the content at that address.
        - `num_bytes`: This is optional for `RemoveInstructionPatch` and `RemoveFunctionPatch`, but required for `RemoveDataPatch`, and specifies the number of bytes to be removed.

### Referencing previously inserted content.
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
