"""AJLang AST - Abstract Syntax Tree nodes."""

from abc import ABC
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class ASTNode(ABC):
    pass


@dataclass
class Program(ASTNode):
    statements: list["Stmt"]


# Statements
@dataclass
class Stmt(ASTNode):
    pass


@dataclass
class PrintStmt(Stmt):
    value: "Expr"


@dataclass
class ExprStmt(Stmt):
    expr: "Expr"


@dataclass
class InputStmt(Stmt):
    target: str  # variable to store input
    prompt: Optional["Expr"] = None  # optional prompt string


@dataclass
class LetStmt(Stmt):
    name: str
    value: "Expr"


@dataclass
class DefStmt(Stmt):
    name: str
    params: list[str]
    body: list[Stmt]


@dataclass
class ReturnStmt(Stmt):
    value: Optional["Expr"] = None


@dataclass
class IfStmt(Stmt):
    condition: "Expr"
    then_body: list[Stmt]
    else_body: Optional[list[Stmt]] = None


@dataclass
class WhileStmt(Stmt):
    condition: "Expr"
    body: list[Stmt]


@dataclass
class ForStmt(Stmt):
    var: str
    start: "Expr"
    end: "Expr"
    body: list[Stmt]


# Expressions
@dataclass
class Expr(ASTNode):
    pass


@dataclass
class NumberExpr(Expr):
    value: float


@dataclass
class StringExpr(Expr):
    value: str


@dataclass
class BoolExpr(Expr):
    value: bool


@dataclass
class VarExpr(Expr):
    name: str


@dataclass
class BinaryExpr(Expr):
    left: Expr
    op: str
    right: Expr


@dataclass
class UnaryExpr(Expr):
    op: str
    right: Expr


@dataclass
class CallExpr(Expr):
    name: str
    args: list[Expr]
