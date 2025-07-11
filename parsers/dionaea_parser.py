import re
from datetime import datetime

class DionaeaParser:
    def __init__(self):
        # Regex generico per il timestamp e tipo log
        self.base_pattern = re.compile(
            r'\[(\d{8} \d{2}:\d{2}:\d{2})\] (\w+) ([^:]+):(\d+)-(debug|info|message): (.+)'
        )

        # Pattern dettagliati (esempi reali)
        self.patterns = [
            {
                'type': 'connection',
                'regex': re.compile(
                    r'connection (?P<conn_id>0x[a-f0-9]+) accept/(?P<protocol>\w+)/(?P<state>\w+) \[(?P<src_ip>[\d\.]+):(?P<src_port>\d+)->(?P<dst_ip>[\d\.]+):(?P<dst_port>\d+)\] state: (?P<from_state>\w+)->(?P<to_state>\w+)',
                    re.IGNORECASE
                )
            },
            {
                'type': 'incident',
                'regex': re.compile(
                    r'traceable_ihandler_cb incident (?P<incident_id>0x[a-f0-9]+) ctx (?P<context>0x[a-f0-9]+)'
                )
            },
            {
                'type': 'disconnect',
                'regex': re.compile(
                    r'traceable_disconnect_cb con (?P<conn_id>0x[a-f0-9]+) ctx (?P<context>0x[a-f0-9]+)'
                )
            },
            {
                'type': 'username',
                'regex': re.compile(r'username: \(string\) (?P<username>\S+)', re.IGNORECASE)
            },
            {
                'type': 'password',
                'regex': re.compile(r'password: \(string\) (?P<password>\S+)', re.IGNORECASE)
            },
        ]

    def parse(self, log: str):
        match = self.base_pattern.match(log)
        if not match:
            return [{'warning': 'Unparsable Dionaea log format', 'raw': log}]

        timestamp_str, category, file_info, line, level, message = match.groups()
        try:
            timestamp = datetime.strptime(timestamp_str, "%d%m%Y %H:%M:%S")
        except ValueError:
            timestamp = None

        parsed_entries = []

        for pattern in self.patterns:
            m = pattern['regex'].search(message)
            if m:
                data = {
                    'type': pattern['type'],
                    'timestamp': timestamp.isoformat() if timestamp else None,
                    **m.groupdict()
                }
                parsed_entries.append(data)
                break

        if not parsed_entries:
            parsed_entries.append({
                'warning': 'No parsable Dionaea entries found',
                'raw': log
            })

        return parsed_entries