# Patcherex2

[![Latest Release](https://img.shields.io/pypi/v/patcherex2.svg)](https://pypi.python.org/pypi/patcherex2/)
[![PyPI Statistics](https://img.shields.io/pypi/dm/patcherex2.svg)](https://pypistats.org/packages/patcherex2)
[![CI](https://img.shields.io/github/actions/workflow/status/purseclab/patcherex2/ci.yml?label=CI)](https://github.com/purseclab/Patcherex2/actions/workflows/ci.yml)
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
docker build -t patcherex2 --platform linux/amd64 https://github.com/purseclab/Patcherex2.git
docker run --rm -it -v ${PWD}:/workdir -w /workdir patcherex2
```
</details>


## Usage
You can find usage examples [here](https://purseclab.github.io/Patcherex2/examples/insert_instruction_patch/).


## Documentation
General documentation and API reference for Patcherex2 can be found at [purseclab.github.io/Patcherex2](https://purseclab.github.io/Patcherex2/).


## Supported Targets

|           | Linux x86 | Linux amd64 | Linux arm | Linux aarch64 | Linux PowerPC (32bit) | Linux PowerPC (64bit) | Linux PowerPCle (64bit) | Linux MIPS (32bit) | Linux MIPS (64bit) | Linux MIPSEL<br>​(32bit) | Linux MIPSEL<br>(64bit) | SPARCv8 (LEON3) | PowerPC (VLE) (IHEX)
|-|-|-|-|-|-|-|-|-|-|-|-|-|-|
InsertDataPatch              | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | ⬜ | ⬜ |
RemoveDataPatch              | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | ⬜ | ⬜ |
ModifyDataPatch              | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | ⬜ | ⬜ |
InsertInstructionPatch (ASM) | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | ⬜ | ⬜ |
InsertInstructionPatch (C)   | 🟥 | 🟩 | 🟥 | 🟩 | 🟥 | 🟥 | 🟥 | 🟥 | 🟥 | 🟥 | 🟥 | 🟥 | 🟥 |
RemoveInstructionPatch       | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | ⬜ | ⬜ |
ModifyInstructionPatch       | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | ⬜ | ⬜ |
InsertFunctionPatch          | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | ⬜ | ⬜ |
ModifyFunctionPatch          | 🟨 | 🟩 | 🟩 | 🟩 | 🟨 | 🟨 | 🟨 | 🟨 | 🟨 | 🟨 | 🟨 | ⬜ | ⬜ |

🟩 Fully Functional, 🟨 Limited Functionality, 🟥 Not Working, ⬜ Not Tested, 🟪 Work in Progress


## Acknowledgements
This project was developed as part of the [DARPA AMP](https://www.darpa.mil/program/assured-micropatching) program, under contract N6600120C4031.

