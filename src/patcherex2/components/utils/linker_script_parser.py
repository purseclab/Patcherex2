import os

import lark


class LinkerScriptParser:
    def __init__(self, linker_script_content: str) -> None:
        self.linker_script_content = linker_script_content
        self.ast = self._parse()

    @staticmethod
    def from_file(linker_script_path: str):
        with open(linker_script_path) as f:
            return LinkerScriptParser(f.read())

    @staticmethod
    def from_string(linker_script_content: str):
        return LinkerScriptParser(linker_script_content)

    def _parse(self):
        with open(os.path.join(os.path.dirname(__file__), "linker_script.lark")) as f:
            parser = lark.Lark(f.read())
            return parser.parse(self.linker_script_content)

    def _get_ast_data(self, tree, name):
        node = next(tree.find_data(name), None)
        return node.children[0].value if node else None

    def get_memory_regions(self):
        memory_regions = []
        for mem_def in self.ast.find_data("memory_def"):
            memory_regions.append(
                {
                    "name": self._get_ast_data(mem_def, "memory_name"),
                    "attr": self._get_ast_data(mem_def, "memory_attr"),
                    "origin": self._get_ast_data(mem_def, "memory_origin"),
                    "length": self._get_ast_data(mem_def, "memory_length"),
                }
            )
        return memory_regions

    def get_sections(self):
        sections = []
        for section_def in self.ast.find_data("section_def"):
            sections.append(
                {
                    "name": self._get_ast_data(section_def, "section_name"),
                    "addr": self._get_ast_data(section_def, "section_addr"),
                    "region": self._get_ast_data(section_def, "section_region"),
                    "lma_region": self._get_ast_data(section_def, "section_lma_region"),
                }
            )
        return sections
