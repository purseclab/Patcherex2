## Basic Usage

Patcherex2 is designed to be used as a library, and can be used to manipulate binaries in various ways.

### Example
Consider a simple C program:

```c
#include <stdio.h>

int add(int a, int b) {
    return a + b;
}

int main() {
    printf("2 + 3 = %d\n", add(2, 3));
    return 0;
}
```

After compiling and executing this program, the output is:

```bash
$ gcc -o add add.c && ./add
2 + 3 = 5
```

Now, we can use Patcherex2 to modify the `add` function to multiply the two arguments instead of adding them.

```python
from patcherex2 import *

p = Patcherex("add")

new_add_func = """
int add(int a, int b) {
    return a * b;
}
"""

p.patches.append(ModifyFunctionPatch("add", new_add_func))

p.apply_patches()
p.binfmt_tool.save_binary("add_patched")
```

Executing the patched program yields a different result:

```bash
$ ./add_patched
2 + 3 = 6
```

💥 We've successfully modified the binary with Patcherex2!
