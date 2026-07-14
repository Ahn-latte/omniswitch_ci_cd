import re


PROMPT_PATTERN = re.compile(r"(?m)[^\n\r]+[>#]\s?$")
PASSWORD_PROMPT_PATTERN = re.compile(r"(?im)password\s*:\s*$")


def detect_prompt(text: str) -> str | None:
    match = PROMPT_PATTERN.search(text)
    if not match:
        return None
    return match.group(0).strip()


def is_password_prompt(text: str) -> bool:
    return PASSWORD_PROMPT_PATTERN.search(text) is not None
