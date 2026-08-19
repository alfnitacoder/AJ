"""AJLang Lexer - tokenizes .aj source code."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class TokenType(Enum):
    # Literals
    NUMBER = "NUMBER"
    STRING = "STRING"
    IDENTIFIER = "IDENTIFIER"
    # Keywords
    PRINT = "print"
    LET = "let"
    IF = "if"
    THEN = "then"
    ELSE = "else"
    END = "end"
    WHILE = "while"
    FOR = "for"
    TO = "to"
    DO = "do"
    DEF = "def"
    RETURN = "return"
    INPUT = "input"
    TRUE = "true"
    FALSE = "false"
    NOT = "not"
    # Operators
    PLUS = "+"
    MINUS = "-"
    STAR = "*"
    SLASH = "/"
    PERCENT = "%"
    EQ = "="
    EQEQ = "=="
    BANG = "!"
    BANGEQ = "!="
    LT = "<"
    LTE = "<="
    GT = ">"
    GTE = ">="
    AND = "and"
    OR = "or"
    # Delimiters
    LPAREN = "("
    RPAREN = ")"
    COMMA = ","
    NEWLINE = "NEWLINE"
    EOF = "EOF"


@dataclass
class Token:
    type: TokenType
    literal: Optional[str | float] = None
    line: int = 0

    def __repr__(self):
        lit = f", {self.literal!r}" if self.literal is not None else ""
        return f"Token({self.type.name}{lit})"


KEYWORDS = {
    "print": TokenType.PRINT,
    "input": TokenType.INPUT,
    "let": TokenType.LET,
    "def": TokenType.DEF,
    "return": TokenType.RETURN,
    "if": TokenType.IF,
    "then": TokenType.THEN,
    "else": TokenType.ELSE,
    "end": TokenType.END,
    "while": TokenType.WHILE,
    "for": TokenType.FOR,
    "to": TokenType.TO,
    "do": TokenType.DO,
    "true": TokenType.TRUE,
    "false": TokenType.FALSE,
    "and": TokenType.AND,
    "or": TokenType.OR,
    "not": TokenType.NOT,
}


class Lexer:
    def __init__(self, source: str):
        self.source = source
        self.pos = 0
        self.line = 1

    def peek(self) -> Optional[str]:
        if self.pos >= len(self.source):
            return None
        return self.source[self.pos]

    def advance(self) -> Optional[str]:
        if self.pos >= len(self.source):
            return None
        ch = self.source[self.pos]
        self.pos += 1
        if ch == "\n":
            self.line += 1
        return ch

    def skip_comment(self):
        while self.peek() and self.peek() != "\n":
            self.advance()

    def skip_whitespace(self):
        while self.peek() and self.peek() in " \t\r":
            self.advance()

    def read_number(self) -> float:
        start = self.pos
        while self.peek() and (self.peek().isdigit() or self.peek() == "."):
            self.advance()
        return float(self.source[start : self.pos])

    def read_string(self, quote: str) -> str:
        result = []
        self.advance()  # consume opening quote
        while self.peek() != quote:
            ch = self.advance()
            if ch is None:
                raise RuntimeError(f"Unterminated string at line {self.line}")
            if ch == "\\":
                esc = self.advance()
                if esc == "n":
                    result.append("\n")
                elif esc == "t":
                    result.append("\t")
                elif esc == "\\":
                    result.append("\\")
                elif esc == quote:
                    result.append(quote)
                else:
                    result.append(esc)
            else:
                result.append(ch)
        self.advance()  # consume closing quote
        return "".join(result)

    def read_identifier(self) -> str:
        start = self.pos
        while self.peek() and (self.peek().isalnum() or self.peek() == "_"):
            self.advance()
        return self.source[start : self.pos]

    def next_token(self) -> Token:
        self.skip_whitespace()

        ch = self.peek()
        line = self.line

        if ch is None:
            return Token(TokenType.EOF, line=line)

        if ch == "\n":
            self.advance()
            return Token(TokenType.NEWLINE, line=line)

        if ch == "/" and self.source[self.pos : self.pos + 2] == "//":
            self.skip_comment()
            return self.next_token()

        if ch.isdigit():
            return Token(TokenType.NUMBER, self.read_number(), line)

        if ch in '"\'':
            return Token(TokenType.STRING, self.read_string(ch), line)

        if ch.isalpha() or ch == "_":
            ident = self.read_identifier()
            return Token(KEYWORDS.get(ident, TokenType.IDENTIFIER), ident, line)

        # Two-char operators
        two = self.source[self.pos : self.pos + 2]
        if two == "==":
            self.advance()
            self.advance()
            return Token(TokenType.EQEQ, line=line)
        if two == "!=":
            self.advance()
            self.advance()
            return Token(TokenType.BANGEQ, line=line)
        if two == "<=":
            self.advance()
            self.advance()
            return Token(TokenType.LTE, line=line)
        if two == ">=":
            self.advance()
            self.advance()
            return Token(TokenType.GTE, line=line)

        # Single-char
        single = {
            "+": TokenType.PLUS,
            "-": TokenType.MINUS,
            "*": TokenType.STAR,
            "/": TokenType.SLASH,
            "%": TokenType.PERCENT,
            "=": TokenType.EQ,
            "!": TokenType.BANG,
            "<": TokenType.LT,
            ">": TokenType.GT,
            "(": TokenType.LPAREN,
            ")": TokenType.RPAREN,
            ",": TokenType.COMMA,
        }
        if ch in single:
            self.advance()
            return Token(single[ch], line=line)

        self.advance()
        raise RuntimeError(f"Unexpected character '{ch}' at line {line}")

    def tokenize(self) -> list[Token]:
        tokens = []
        while True:
            tok = self.next_token()
            tokens.append(tok)
            if tok.type == TokenType.EOF:
                break
        return tokens
