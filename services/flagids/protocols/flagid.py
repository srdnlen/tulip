from dataclasses import dataclass

@dataclass
class FlagId:
    tick: int
    service: str
    flagstore: str
    content: str | dict
