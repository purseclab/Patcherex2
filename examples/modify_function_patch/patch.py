from patcherex2 import *

p = Patcherex("add")

new_add_func = """
int add(int a, int b) {
    return a * b;
}
"""

p.patches.append(ModifyFunctionPatch("add", new_add_func))

p.apply_patches()
p.save_binary("add_patched")
