# Copyright (c) 2025 iiPython

def log(severity: str, category: str, message: str) -> None:
    print(f"[{severity.upper()}] {category.upper()}: {message}")

def info(category: str, message: str) -> None:
    log("info", category, message)

def warn(category: str, message: str) -> None:
    log("warn", category, message)

def error(category: str, message: str) -> None:
    log("error", category, message)
