# AJLang — A Programming Language for AJOS

**File extension:** `.aj`

AJLang is implemented and ready to use. Run it on your Mac:

```bash
python run_aj.py examples/hello.aj
python -m ajlang examples/fib.aj
```

## Language Reference

See `ajlang/README.md` for full syntax. Highlights:

- `print expr` – output
- `input x` or `input x "prompt"` – read from stdin
- `let x = expr` – variables
- `def name(a, b) ... end` – functions with `return`
- `if/else/end` – conditionals
- `while/do/end` – loops
- `for i = 1 to 10 do ... end` – for loops
- `+ - * / %`, `== != < >`, `and or not` – operators

## Examples

- `examples/hello.aj` – basic print and variables
- `examples/fib.aj` – Fibonacci loop
- `examples/conditions.aj` – if/else and booleans
- `examples/functions.aj` – user-defined functions, recursion
- `examples/for_loop.aj` – for loop and modulo
- `examples/input_demo.aj` – read user input
