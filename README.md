# Patcherex 2

[![Latest Release](https://img.shields.io/pypi/v/patcherex2.svg)](https://pypi.python.org/pypi/patcherex2/)
[![PyPI Statistics](https://img.shields.io/pypi/dm/patcherex2.svg)](https://pypistats.org/packages/patcherex2)
[![CI](https://img.shields.io/github/actions/workflow/status/purseclab/patcherex2/ci.yml?label=CI
)](https://github.com/purseclab/Patcherex2/actions/workflows/test.yml)
[![License](https://img.shields.io/github/license/purseclab/patcherex2.svg)](https://github.com/purseclab/Patcherex2/blob/main/LICENSE)

> [!WARNING]
> This project is currently in its initial development stages. Please anticipate potential breaking changes. The first stable release is targeted for early March 2024.

Patcherex 2 is a rewritten adaptation of the original [Patcherex](https://github.com/angr/patcherex) project, aimed at building upon its core ideas and extending its capabilities.

## Installation

Patcherex 2 is available on PyPI and can be installed with pip:

```bash
pip install patcherex2
```

## Usage

Coming soon.

## Supported Targets

|           | Linux x86 | Linux amd64 | Linux arm | Linux aarch64 | Linux PowerPC (32bit) | Linux PowerPC (64bit) | Linux MIPS (32bit) | Linux MIPS (64bit) | SPARCv8 (LEON3) | PowerPC (VLE) (IHEX)
|-|-|-|-|-|-|-|-|-|-|-|
InsertDataPatch         | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | ⬜ | ⬜ | 🟩 | 🟩 |
RemoveDataPatch         | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | ⬜ | ⬜ | 🟩 | 🟩 |
ModifyDataPatch         | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | ⬜ | ⬜ | 🟩 | 🟩 |
InsertInstructionPatch  | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | ⬜ | ⬜ | 🟩 | 🟩 |
RemoveInstructionPatch  | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | ⬜ | ⬜ | 🟩 | 🟩 |
ModifyInstructionPatch  | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | 🟩 | ⬜ | ⬜ | 🟩 | 🟩 |
InsertFunctionPatch     | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
ModifyFunctionPatch     | 🟨 | 🟩 | 🟩 | 🟩 | 🟨 | 🟨 | 🟨 | 🟨 | ⬜ | ⬜ | 🟩 | 🟩 |

🟩 Fully Functional, 🟨 Limited Functionality, 🟥 Not Working, ⬜ Not Tested, 🟪 Work in Progress
