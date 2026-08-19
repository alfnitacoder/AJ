"""Run AJLang from: python -m ajlang file.aj (run from AJOS root)"""

import sys
from pathlib import Path

# Ensure AJOS root is on path
_ajos_root = Path(__file__).resolve().parent.parent
if str(_ajos_root) not in sys.path:
    sys.path.insert(0, str(_ajos_root))

from ajlang.interpreter import Interpreter
from ajlang.lexer import Lexer
from ajlang.parser import Parser
from ajlang.parser import ParseError
from ajlang.interpreter import RuntimeError


def run_file(path: str) -> int:
    with open(path, "r") as f:
        source = f.read()

    try:
        lexer = Lexer(source)
        tokens = lexer.tokenize()
        parser = Parser(tokens)
        program = parser.parse()
        interpreter = Interpreter()
        interpreter.run(program)
        return 0
    except ParseError as e:
        print(f"Parse error: {e}", file=sys.stderr)
        return 1
    except RuntimeError as e:
        print(f"Runtime error: {e}", file=sys.stderr)
        return 1


def main():
    if len(sys.argv) < 2:
        print("AJLang - usage: python -m ajlang <file.aj>")
        print("              ajlang <file.aj>")
        sys.exit(1)

    path = sys.argv[1]
    if not Path(path).exists():
        print(f"Error: File not found: {path}", file=sys.stderr)
        sys.exit(1)

    sys.exit(run_file(path))


if __name__ == "__main__":
    main()
