# AJLang

A simple programming language with `.aj` file extension. Tree-walk interpreter in Python.

## Run

```bash
# From AJOS root:
python run_aj.py examples/hello.aj
python -m ajlang examples/hello.aj
```

## Syntax

```aj
// Comments with //
print "Hello, world!"
print 42

let x = 10
print x + 5

if x > 5 then
  print "big"
else
  print "small"
end

while x > 0 do
  print x
  let x = x - 1
end

// Functions
def greet(name)
  print "Hello, " + name + "!"
end
greet("AJLang")

// For loop
for i = 1 to 10 do
  print i
end

// Modulo
print 10 % 3   // 1

// Input
input name "Your name? "
print "Hi, " + name + "!"
```

## Features

- **print** – output values
- **input** – read from stdin (`input x` or `input x "prompt"`)
- **let** – bind variables
- **def / end** – define functions with `return`
- **if / then / else / end** – conditionals
- **while / do / end** – loops
- **for var = start to end do / end** – for loops
- **Expressions** – `+ - * / %`, `== != < <= > >=`, `and or not`
- **Types** – numbers, strings, booleans

## Examples

| File | Description |
|------|-------------|
| `examples/hello.aj` | Basic print and variables |
| `examples/fib.aj` | Fibonacci with while loop |
| `examples/conditions.aj` | if/else and booleans |
| `examples/functions.aj` | User-defined functions, recursion |
| `examples/for_loop.aj` | For loop and modulo |
| `examples/input_demo.aj` | Read user input |
