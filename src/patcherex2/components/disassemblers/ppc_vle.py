from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile

from ..assets.assets import Assets
from .disassembler import Disassembler

logger = logging.getLogger(__name__)


class PpcVle(Disassembler):
    def __init__(self, p) -> None:
        self.p = p
        self.assets_path = Assets("ppc_vle").path

    def disassemble(self, input: bytes, base=0, **kwargs) -> list[dict[str, str | int]]:
        if isinstance(input, str):
            input = bytes(map(ord, input))
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "code.bin"), "wb") as f:
                f.write(input)

            try:
                proc = subprocess.run(
                    [
                        os.path.join(self.assets_path, "powerpc-eabivle-objdump"),
                        "-D",
                        "-b",
                        "binary",
                        f"--adjust-vma={hex(base)}",
                        "-m",
                        "powerpc:common",
                        "-EB",
                        os.path.join(td, "code.bin"),
                    ],
                    check=True,
                    capture_output=True,
                )
                # skip objdump's 7 header lines
                str_result = "\n".join(proc.stdout.decode("utf-8").splitlines()[7:])
            except subprocess.CalledProcessError as e:
                logger.error(e.stderr.decode("utf-8"))
                raise e

        result = []
        for line in str_result.splitlines():
            m = re.match(
                r"\s+(?P<address>[0-9a-f]+):\s+(?P<bytes>([0-9a-f]{2}\s)+)\s+(?P<mnemonic>.+?)\s+(?P<op_str>.+?)$",
                line,
            )
            if m:
                instr = m.groupdict()
                result.append(
                    {
                        "address": int(instr["address"], 16),
                        "size": len(bytes.fromhex(instr["bytes"])),
                        "mnemonic": re.sub(r"\s+", "", instr["mnemonic"]),
                        "op_str": re.sub(
                            r"\s+", "", instr["op_str"].split(";")[0]
                        ).replace(",", ", "),
                    }
                )
        return result
