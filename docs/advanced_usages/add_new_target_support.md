# Adding New Target Support

Patcherex2 has been designed with extensibility in mind, making it easy to add support for new targets. This document will walk you through the process of defining a new target in Patcherex2.

## Defining a New Target

The first step is to define a new target class that inherits from the `Target` base class. This class should specify the required components to support the target. Here's an example of the existing `elf_amd64_linux` target definition.

```python title="src/patcherex2/targets/elf_amd64_linux.py"
--8<-- "src/patcherex2/targets/elf_amd64_linux.py"
```

### `detect_target` Method

The `detect_target` static method is responsible for automatically detecting if a given binary is supported by this target. It should return `True` if the binary matches the target criteria, or `False` otherwise. In the example above, it checks if the file is an ELF binary for the AMD64 architecture.

### `get_{component}` Methods

The target definition should define methods to get the required components. The method names should be in the format `get_{component}`. The following are the list of components that must be defined for a target:

- assembler
- disassembler
- compiler
- binary_analyzer (Extract extra information from the binary file)
- allocation_manager (Find free space or allocate new space in the binary)
- binfmt_tool (Parse and modify binary formats, such as ELF, PE, IHEX, etc.)
- utils
- archinfo (Architecture specific information, such as register names, sizes, etc.)

These methods allow you to specify the appropriate implementation for each component based on the target's requirements. Patcherex2 provides multiple implementations for common components that you can choose from.

##### Adding New Components

If your target requires custom components not provided by Patcherex2, you can define new component classes that inherit from the respective base component classes. These custom components should implement the necessary methods to support your target's specific needs.

## Registering the New Target

Once you have defined your target class, Patcherex2 will automatically register it if it is defined before creating a Patcherex2 instance (`p = Patcherex("/path/to/bin")`). Patcherex2 will call the `detect_target` method of each registered target to determine the appropriate target for the given binary.

## Manually Selecting the Target

If your target is designed for manual selection only (i.e., `detect_target` always returns `False`), or if you want to override the automatic target detection, you can specify the target class when creating the Patcherex2 instance:

```python
p = Patcherex("/path/to/binary", target_cls=MyCustomTarget)
```

## Configuring the Target

### Selecting Component Implementations

Some targets may support multiple implementations for a given component, allowing you to choose the desired implementation. You can configure the target by passing a configuration dictionary to the Patcherex2 constructor.

For example, if your target's `get_assembler` method supports multiple assemblers:

```python
def get_assembler(self, assembler):
    assembler = assembler or "keystone"
    if assembler == "keystone":
        return Keystone()
    elif assembler == "gas":
        return Gas()
    raise NotImplementedError()
```

You can select the assembler like this:

```python
p = Patcherex("/path/to/binary", target_opts={"assembler": "gas"})
```

This will use the `Gas` assembler instead of the default `Keystone` assembler.

### Configuring Components

Some component implementations accept additional keyword arguments for configuration. You can pass these options through the `component_opts` parameter when creating the Patcherex2 instance.

For example, if your target's `get_assembler` method accepts keyword arguments:

```python
def get_assembler(self, assembler, **kwargs):
    assembler = assembler or "some_assembler"
    if assembler == "some_assembler":
        return SomeAssembler(**kwargs)
    raise NotImplementedError()
```

You can configure the assembler options like this:

```python
p = Patcherex("/path/to/binary", component_opts={"assembler": {"arch": "x86", "mode": "64"}})
```

This will create the `SomeAssembler` instance with the provided keyword arguments:

```python
SomeAssembler(arch="x86", mode="64")
```

By following these steps and leveraging the extensible architecture of Patcherex2, you can easily add support for new targets and customize their behavior to suit your specific requirements.
