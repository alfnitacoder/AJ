"""AJLang Interpreter - executes AST."""

from ajlang.ast import (
    BinaryExpr,
    BoolExpr,
    CallExpr,
    DefStmt,
    ExprStmt,
    ForStmt,
    IfStmt,
    InputStmt,
    LetStmt,
    NumberExpr,
    PrintStmt,
    Program,
    ReturnStmt,
    Stmt,
    StringExpr,
    UnaryExpr,
    VarExpr,
    WhileStmt,
)


class RuntimeError(Exception):
    def __init__(self, msg: str):
        super().__init__(msg)


class Interpreter:
    def __init__(self):
        self.variables: dict[str, float | str | bool] = {}
        self.functions: dict[str, tuple[list[str], list[Stmt]]] = {}
        self._return_value: tuple[bool, float | str | bool | None] = (False, None)

    def run(self, program: Program) -> None:
        # First pass: register all functions
        for stmt in program.statements:
            if isinstance(stmt, DefStmt):
                self.functions[stmt.name] = (stmt.params, stmt.body)
        for stmt in program.statements:
            if not isinstance(stmt, DefStmt):
                self.execute(stmt)

    def execute(self, stmt: Stmt) -> None:
        if isinstance(stmt, InputStmt):
            if stmt.prompt is not None:
                prompt_val = self.evaluate(stmt.prompt)
                print(prompt_val, end="")
            line = input().strip()
            # Try to parse as number
            try:
                if "." in line:
                    self.variables[stmt.target] = float(line)
                else:
                    self.variables[stmt.target] = int(line)
            except ValueError:
                self.variables[stmt.target] = line
        elif isinstance(stmt, PrintStmt):
            value = self.evaluate(stmt.value)
            if isinstance(value, float) and value == int(value):
                print(int(value))
            else:
                print(value)
        elif isinstance(stmt, LetStmt):
            self.variables[stmt.name] = self.evaluate(stmt.value)
        elif isinstance(stmt, IfStmt):
            if self.is_truthy(self.evaluate(stmt.condition)):
                for s in stmt.then_body:
                    self.execute(s)
                    if self._return_value[0]:
                        return
            elif stmt.else_body:
                for s in stmt.else_body:
                    self.execute(s)
                    if self._return_value[0]:
                        return
        elif isinstance(stmt, WhileStmt):
            while self.is_truthy(self.evaluate(stmt.condition)):
                for s in stmt.body:
                    self.execute(s)
                    if self._return_value[0]:
                        return
        elif isinstance(stmt, ForStmt):
            start_val = int(self.evaluate(stmt.start))
            end_val = int(self.evaluate(stmt.end))
            for i in range(start_val, end_val + 1):
                self.variables[stmt.var] = i
                for s in stmt.body:
                    self.execute(s)
                    if self._return_value[0]:
                        return
                if self._return_value[0]:
                    break
        elif isinstance(stmt, DefStmt):
            pass  # Already registered in run()
        elif isinstance(stmt, ExprStmt):
            self.evaluate(stmt.expr)  # evaluate for side effects (e.g. function call)
        elif isinstance(stmt, ReturnStmt):
            val = self.evaluate(stmt.value) if stmt.value else None
            self._return_value = (True, val)
        else:
            raise RuntimeError(f"Unknown statement type: {type(stmt)}")

    def evaluate(self, expr):
        if isinstance(expr, NumberExpr):
            return expr.value
        if isinstance(expr, StringExpr):
            return expr.value
        if isinstance(expr, BoolExpr):
            return expr.value
        if isinstance(expr, VarExpr):
            if expr.name not in self.variables:
                raise RuntimeError(f"Undefined variable: {expr.name}")
            return self.variables[expr.name]
        if isinstance(expr, CallExpr):
            if expr.name not in self.functions:
                raise RuntimeError(f"Undefined function: {expr.name}")
            params, body = self.functions[expr.name]
            if len(expr.args) != len(params):
                raise RuntimeError(f"Function {expr.name} expects {len(params)} args, got {len(expr.args)}")
            # Save old env and push new bindings
            old_vars = dict(self.variables)
            for i, p in enumerate(params):
                self.variables[p] = self.evaluate(expr.args[i])
            self._return_value = (False, None)
            for s in body:
                self.execute(s)
                if self._return_value[0]:
                    break
            result = self._return_value[1]
            self.variables = old_vars
            self._return_value = (False, None)
            return result
        if isinstance(expr, UnaryExpr):
            right = self.evaluate(expr.right)
            if expr.op == "!":
                return not self.is_truthy(right)
            if expr.op == "-":
                if isinstance(right, bool):
                    raise RuntimeError("Cannot negate boolean")
                return -right
            raise RuntimeError(f"Unknown unary operator: {expr.op}")
        if isinstance(expr, BinaryExpr):
            left = self.evaluate(expr.left)
            right = self.evaluate(expr.right)

            if expr.op == "and":
                return self.is_truthy(left) and self.is_truthy(right)
            if expr.op == "or":
                return self.is_truthy(left) or self.is_truthy(right)
            if expr.op == "==":
                return left == right
            if expr.op == "!=":
                return left != right
            if expr.op == "<":
                return left < right
            if expr.op == "<=":
                return left <= right
            if expr.op == ">":
                return left > right
            if expr.op == ">=":
                return left >= right
            if expr.op == "+":
                if isinstance(left, str) or isinstance(right, str):
                    def fmt(v):
                        if isinstance(v, float) and v == int(v):
                            return str(int(v))
                        return str(v)
                    return fmt(left) + fmt(right)
                return left + right
            if expr.op == "-":
                return left - right
            if expr.op == "*":
                return left * right
            if expr.op == "/":
                if right == 0:
                    raise RuntimeError("Division by zero")
                return left / right
            if expr.op == "%":
                if right == 0:
                    raise RuntimeError("Modulo by zero")
                return left % right

            raise RuntimeError(f"Unknown binary operator: {expr.op}")

        raise RuntimeError(f"Unknown expression type: {type(expr)}")

    def is_truthy(self, value) -> bool:
        if value is None:
            return False
        if isinstance(value, bool):
            return value
        return True
