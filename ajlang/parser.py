"""AJLang Parser - builds AST from tokens."""

from __future__ import annotations

from ajlang.ast import (
    ASTNode,
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
from ajlang.lexer import Token, TokenType


class ParseError(Exception):
    def __init__(self, msg: str, token: Token):
        self.msg = msg
        self.token = token
        super().__init__(f"{msg} at line {token.line}")


class Parser:
    def __init__(self, tokens: list[Token]):
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> Token:
        while self.pos < len(self.tokens) and self.tokens[self.pos].type == TokenType.NEWLINE:
            self.pos += 1
        if self.pos >= len(self.tokens):
            return self.tokens[-1]  # EOF
        return self.tokens[self.pos]

    def advance(self) -> Token:
        while self.pos < len(self.tokens) and self.tokens[self.pos].type == TokenType.NEWLINE:
            self.pos += 1
        if self.pos >= len(self.tokens):
            return self.tokens[-1]
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def expect(self, expected: TokenType) -> Token:
        tok = self.advance()
        if tok.type != expected:
            raise ParseError(f"Expected {expected.name}, got {tok.type.name}", tok)
        return tok

    def parse(self) -> Program:
        statements = []
        while self.peek().type != TokenType.EOF:
            stmt = self.parse_statement()
            if stmt:
                statements.append(stmt)
        return Program(statements)

    def parse_statement(self) -> Stmt | None:
        tok = self.peek()
        if tok.type == TokenType.EOF:
            return None

        if tok.type == TokenType.PRINT:
            self.advance()
            value = self.parse_expression()
            return PrintStmt(value)

        if tok.type == TokenType.INPUT:
            self.advance()
            target = self.expect(TokenType.IDENTIFIER).literal
            prompt = None
            if self.peek().type in (TokenType.STRING, TokenType.IDENTIFIER):
                prompt = self.parse_expression()
            return InputStmt(target, prompt)

        if tok.type == TokenType.LET:
            self.advance()
            name = self.expect(TokenType.IDENTIFIER).literal
            self.expect(TokenType.EQ)
            value = self.parse_expression()
            return LetStmt(name, value)

        if tok.type == TokenType.IF:
            self.advance()
            condition = self.parse_expression()
            self.expect(TokenType.THEN)
            then_body = self.parse_block()
            else_body = None
            if self.peek().type == TokenType.ELSE:
                self.advance()
                else_body = self.parse_block()
            self.expect(TokenType.END)
            return IfStmt(condition, then_body, else_body)

        if tok.type == TokenType.WHILE:
            self.advance()
            condition = self.parse_expression()
            self.expect(TokenType.DO)
            body = self.parse_block()
            self.expect(TokenType.END)
            return WhileStmt(condition, body)

        if tok.type == TokenType.FOR:
            self.advance()
            var = self.expect(TokenType.IDENTIFIER).literal
            self.expect(TokenType.EQ)
            start = self.parse_expression()
            self.expect(TokenType.TO)
            end = self.parse_expression()
            self.expect(TokenType.DO)
            body = self.parse_block()
            self.expect(TokenType.END)
            return ForStmt(var, start, end, body)

        if tok.type == TokenType.DEF:
            self.advance()
            name = self.expect(TokenType.IDENTIFIER).literal
            self.expect(TokenType.LPAREN)
            params = []
            while self.peek().type != TokenType.RPAREN:
                params.append(self.expect(TokenType.IDENTIFIER).literal)
                if self.peek().type == TokenType.COMMA:
                    self.advance()
            self.expect(TokenType.RPAREN)
            body = self.parse_block()
            self.expect(TokenType.END)
            return DefStmt(name, params, body)

        if tok.type == TokenType.RETURN:
            self.advance()
            value = None
            if self.peek().type not in (TokenType.NEWLINE, TokenType.EOF, TokenType.END, TokenType.ELSE):
                value = self.parse_expression()
            return ReturnStmt(value)

        # Expression statement (e.g. function call)
        if tok.type == TokenType.IDENTIFIER:
            expr = self.parse_expression()
            return ExprStmt(expr)

        raise ParseError(f"Unexpected token {tok.type.name}", tok)

    def parse_block(self) -> list[Stmt]:
        block = []
        while self.peek().type not in (TokenType.ELSE, TokenType.END, TokenType.EOF):
            stmt = self.parse_statement()
            if stmt:
                block.append(stmt)
        return block

    def parse_expression(self) -> Expr:
        return self.parse_or()

    def parse_or(self) -> Expr:
        left = self.parse_and()
        while self.peek().type == TokenType.OR:
            self.advance()
            right = self.parse_and()
            left = BinaryExpr(left, "or", right)
        return left

    def parse_and(self) -> Expr:
        left = self.parse_equality()
        while self.peek().type == TokenType.AND:
            self.advance()
            right = self.parse_equality()
            left = BinaryExpr(left, "and", right)
        return left

    def parse_equality(self) -> Expr:
        left = self.parse_comparison()
        while self.peek().type in (TokenType.EQEQ, TokenType.BANGEQ):
            op = self.advance()
            right = self.parse_comparison()
            left = BinaryExpr(left, "==" if op.type == TokenType.EQEQ else "!=", right)
        return left

    def parse_comparison(self) -> Expr:
        left = self.parse_term()
        while self.peek().type in (TokenType.LT, TokenType.LTE, TokenType.GT, TokenType.GTE):
            op = self.advance()
            right = self.parse_term()
            left = BinaryExpr(left, op.type.value, right)
        return left

    def parse_term(self) -> Expr:
        left = self.parse_factor()
        while self.peek().type in (TokenType.PLUS, TokenType.MINUS):
            op = self.advance()
            right = self.parse_factor()
            left = BinaryExpr(left, op.type.value, right)
        return left

    def parse_factor(self) -> Expr:
        left = self.parse_unary()
        while self.peek().type in (TokenType.STAR, TokenType.SLASH, TokenType.PERCENT):
            op = self.advance()
            right = self.parse_unary()
            left = BinaryExpr(left, op.type.value, right)
        return left

    def parse_unary(self) -> Expr:
        if self.peek().type in (TokenType.BANG, TokenType.NOT):
            self.advance()
            return UnaryExpr("!", self.parse_unary())
        if self.peek().type == TokenType.MINUS:
            self.advance()
            return UnaryExpr("-", self.parse_unary())
        return self.parse_primary()

    def parse_primary(self) -> Expr:
        tok = self.advance()
        if tok.type == TokenType.NUMBER:
            return NumberExpr(tok.literal)
        if tok.type == TokenType.STRING:
            return StringExpr(tok.literal)
        if tok.type == TokenType.TRUE:
            return BoolExpr(True)
        if tok.type == TokenType.FALSE:
            return BoolExpr(False)
        if tok.type == TokenType.IDENTIFIER:
            if self.peek().type == TokenType.LPAREN:
                self.advance()  # consume (
                args = []
                while self.peek().type != TokenType.RPAREN:
                    args.append(self.parse_expression())
                    if self.peek().type == TokenType.COMMA:
                        self.advance()
                self.expect(TokenType.RPAREN)
                return CallExpr(tok.literal, args)
            return VarExpr(tok.literal)
        if tok.type == TokenType.LPAREN:
            expr = self.parse_expression()
            self.expect(TokenType.RPAREN)
            return expr
        raise ParseError(f"Expected expression, got {tok.type.name}", tok)
