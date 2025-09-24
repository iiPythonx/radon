# Copyright (c) 2025 iiPython

class Logging:
    COLOR_MAP: dict[str, int] = {
        "info":  34,
        "warn":  33,
        "error": 31,
        "netw":  36
    }

    @classmethod
    def log(cls, severity: str, category: str, message: str) -> None:
        print(f"\033[{cls.COLOR_MAP[severity]}m[{severity.upper()}] {category.upper()}: {message}\033[0m")

    @classmethod
    def info(cls, category: str, message: str) -> None:
        cls.log("info", category, message)

    @classmethod
    def warn(cls, category: str, message: str) -> None:
        cls.log("warn", category, message)

    @classmethod
    def error(cls, category: str, message: str) -> None:
        cls.log("error", category, message)
    
    @classmethod
    def network(cls, type: str, packet: str) -> None:
        cls.log("netw", type, packet)

log = Logging
