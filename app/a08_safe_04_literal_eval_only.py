import ast

def safe(expr: str):
    return ast.literal_eval(expr)
