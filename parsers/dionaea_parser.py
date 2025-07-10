import re
from typing import Optional, Dict

class DionaeaParser:
    LOG_PATTERN = re.compile(
        r"""
        ^\[(?P<timestamp>\d{8} \d{2}:\d{2}:\d{2})\]   # [10072025 15:08:39]
        \s(?P<module>\w+)                             # connection, incident, ftp, etc.
        \s(?P<source>[\w/\.]+):(?P<line>\d+)-(?P<level>\w+):  # /path/to/file.py:123-level
        \s(?P<message>.+)$                            # actual log message
        """, re.VERBOSE
    )

    def parse(self, line: str) -> Optional[Dict]:
        match = self.LOG_PATTERN.match(line.strip())
        if not match:
            return None

        module = match.group("module")
        message = match.group("message").strip()

        # Ignora cleanup di SIP
        if module.lower() == "sip" and "cleanup" in message.lower():
            return None

        return {
            "timestamp": match.group("timestamp"),
            "module": module,
            "source_file": match.group("source"),
            "line_number": int(match.group("line")),
            "log_level": match.group("level").lower(),
            "message": message
        }