<p align="center" style="text-decoration: none;">
  <img alt="Patcherex2" src="https://github.com/purseclab/Patcherex2/raw/refs/heads/main/patcherex2.png" width="100%">
  <a href="https://pypi.python.org/pypi/patcherex2/">
    <img src="https://img.shields.io/pypi/v/patcherex2.svg" alt="Latest Release">
  </a>
  <a href="https://pypistats.org/packages/patcherex2">
    <img src="https://img.shields.io/pypi/dm/patcherex2.svg" alt="PyPI Statistics">
  </a>
  <a href="https://github.com/purseclab/Patcherex2/actions/workflows/ci.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/purseclab/patcherex2/ci.yml?label=CI" alt="CI">
  </a>
  <a href="https://github.com/purseclab/Patcherex2/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/purseclab/patcherex2.svg" alt="License">
  </a>
  
</p>

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

|           | Linux x86 | Linux amd64 | Linux arm | Linux aarch64 | Linux PowerPC (32bit) | Linux PowerPC (64bit) | Linux PowerPCle (64bit) | Linux MIPS (32bit) | Linux MIPS (64bit) | Linux MIPSEL<br>​(32bit) | Linux MIPSEL<br>(64bit) | Linux s390x | SPARCv8 (LEON3) | PowerPC (VLE) (IHEX)
|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|
InsertDataPatch              | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | ⬜ | ⬜ |
RemoveDataPatch              | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | ⬜ | ⬜ |
ModifyDataPatch              | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | ⬜ | ⬜ |
InsertInstructionPatch (ASM) | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | ⬜ | ⬜ |
InsertInstructionPatch (C)   | 🟥 | 🟩 | 🟥 | 🟩 | 🟥 | 🟥 | 🟥 | 🟥 | 🟥 | 🟥 | 🟥 | 🟥 | 🟥 | 🟥 |
RemoveInstructionPatch       | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | ⬜ | ⬜ |
ModifyInstructionPatch       | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | ⬜ | ⬜ |
InsertFunctionPatch          | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟨 | ⬜ | ⬜ |
ModifyFunctionPatch          | 🟨 | 🟩 | 🟩 | 🟩 | 🟨 | 🟨 | 🟨 | 🟨 | 🟨 | 🟨 | 🟨 | 🟨 | ⬜ | ⬜ |

🟩 Fully Functional, 🟨 Limited Functionality, 🟥 Not Working, ⬜ Not Tested, 🟪 Work in Progress


## Acknowledgements
This project was initially developed as part of the [DARPA AMP](https://www.darpa.mil/program/assured-micropatching) program, under contract N6600120C4031. This project is also supported by NSF, under [Award \# 2442339](https://www.nsf.gov/awardsearch/show-award?AWD_ID=2442339).

