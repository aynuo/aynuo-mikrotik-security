"""Safe, offline MikroTik export parser.

Only RouterOS ``add`` and ``set`` statements are interpreted as data. The
uploaded text is never executed or passed to a shell.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field


SENSITIVE_KEYS = {
    "authentication-key", "community", "encryption-key", "key", "passphrase",
    "password", "pre-shared-key", "private-key", "secret",
}
SENSITIVE = re.compile(
    r"(?i)\b(" + "|".join(re.escape(key) for key in sorted(SENSITIVE_KEYS, key=len, reverse=True))
    + r")\s*=\s*(\"(?:\\.|[^\"])*\"|\S+)"
)
VERSION_HEADER = re.compile(r"\bby RouterOS\s+([^\s]+)", re.IGNORECASE)
MODEL_HEADER = re.compile(r"^#\s*model\s*=\s*(.+?)\s*$", re.IGNORECASE)

# These menus contain multiple addressable rows even when RouterOS writes
# them with ``set`` rather than ``add``.
COLLECTION_SECTIONS = {
    "interface/ethernet", "interface/ethernet/poe", "interface/wifi",
    "interface/wifi/security", "interface/wireless",
    "interface/wireless/security-profiles", "ip/firewall/filter",
    "ip/firewall/nat", "ip/service", "snmp/community", "system/logging", "user",
}


def redact(value: str) -> str:
    return SENSITIVE.sub(lambda match: f"{match.group(1)}=[REDACTED]", value)


def scalar(value: str):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    if value.lower() in {"yes", "true"}:
        return True
    if value.lower() in {"no", "false"}:
        return False
    if re.fullmatch(r"-?\d+", value):
        try:
            return int(value)
        except ValueError:
            pass
    return value


def logical_lines(text: str) -> list[str]:
    """Join RouterOS backslash continuations without changing command data."""
    lines: list[str] = []
    pending = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        pending = f"{pending} {stripped}".strip() if pending else stripped
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue
        lines.append(pending)
        pending = ""
    if pending:
        lines.append(pending)
    return lines


def tokens(line: str) -> list[str]:
    lexer = shlex.shlex(line, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    lexer.escape = "\\"
    try:
        return list(lexer)
    except ValueError as exc:
        raise ValueError(f"Malformed RouterOS command: {exc}") from exc


@dataclass
class RouterExport:
    sections: dict[str, list[dict]] = field(default_factory=dict)
    present_sections: set[str] = field(default_factory=set)
    identity: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def get(self, path: str) -> list[dict]:
        return self.sections.get(path.strip("/"), [])

    def has(self, path: str) -> bool:
        return path.strip("/") in self.present_sections

    def settings(self, path: str) -> dict:
        rows = self.get(path)
        return rows[0] if rows else {}


def _parse_item(command: str, section: str) -> dict:
    parts = tokens(command)
    item: dict = {"_raw": redact(command)}
    positional: list[str] = []
    for token in parts[1:]:
        clean = token.strip("[]")
        if not clean or clean == "find":
            continue
        if "=" in clean:
            key, value = clean.split("=", 1)
            if key:
                item[key] = scalar(value)
        else:
            positional.append(clean)
    if command.startswith("set ") and section in COLLECTION_SECTIONS and positional:
        item.setdefault("name", positional[0])
    return item


def parse_export(text: str) -> RouterExport:
    if not text or not text.strip():
        raise ValueError("The configuration export is empty.")
    if "\x00" in text:
        raise ValueError("The configuration contains binary NUL characters and is not a text export.")
    if len(text.encode("utf-8", "ignore")) > 5 * 1024 * 1024:
        raise ValueError("The configuration export exceeds the size limit.")

    parsed = RouterExport()
    section: str | None = None
    commands = 0
    for line_number, line in enumerate(logical_lines(text), start=1):
        if not line:
            continue
        if line.startswith("#"):
            version = VERSION_HEADER.search(line)
            model = MODEL_HEADER.match(line)
            if version:
                parsed.metadata["routeros_version"] = version.group(1)
            if model:
                parsed.metadata["hardware_model"] = model.group(1).strip()
            continue
        if line.startswith("/"):
            # Text exports spell menu paths with spaces (``/ip service``),
            # while normalized internal paths use ``ip/service``.
            section = re.sub(r"\s+", "/", line[1:].strip().strip("/"))
            if not section or any(char in section for char in "\r\n\x00"):
                raise ValueError(f"Invalid RouterOS section on line {line_number}.")
            parsed.present_sections.add(section)
            continue
        if not section or not (line.startswith("add ") or line.startswith("set ")):
            continue

        item = _parse_item(line, section)
        commands += 1
        if line.startswith("add ") or section in COLLECTION_SECTIONS:
            parsed.sections.setdefault(section, []).append(item)
        else:
            rows = parsed.sections.setdefault(section, [{}])
            rows[0].update(item)

        if section == "system/identity" and item.get("name"):
            parsed.identity["name"] = str(item["name"])

    if not parsed.present_sections or commands == 0:
        raise ValueError(
            "This is not a recognizable RouterOS text export. Upload a RouterOS .rsc export containing configuration commands."
        )
    if not parsed.identity.get("name"):
        parsed.warnings.append("The export does not contain a system identity.")
    return parsed

