import re
from datetime import datetime
from typing import List, Dict

class DionaeaParser:
    def parse(self, raw_log: str) -> List[Dict]:
        parsed_logs = []

        timestamp = self.extract_timestamp(raw_log)
        if not timestamp:
            return [{"warning": "Invalid timestamp", "raw": raw_log}]
       
        # Pattern: traceable_ihandler_cb incident <id> ctx <ctx>
        match = re.search(r'traceable_ihandler_cb incident (\S+) ctx (\S+)', raw_log)
        if match:
            parsed_logs.append({
                "type": "incident",
                "timestamp": timestamp,
                "incident_id": match.group(1),
                "context": match.group(2),
            })
            return parsed_logs

        # Pattern: cmd 'b'PASS''
        match = re.search(r"cmd\s+'b'(.*?)''", raw_log)
        if match:
            parsed_logs.append({
                "type": "ftp_command",
                "timestamp": timestamp,
                "command": match.group(1)
            })
            return parsed_logs

        # Pattern: command: (string) USER
        match = re.search(r'command: \(string\) (\w+)', raw_log)
        if match:
            parsed_logs.append({
                "type": "ftp_command",
                "timestamp": timestamp,
                "command": match.group(1)
            })
            return parsed_logs

        # Pattern: (null): (string) anonymous
        if "(string) anonymous" in raw_log:
            parsed_logs.append({
                "type": "ftp_login",
                "timestamp": timestamp,
                "user": "anonymous"
            })
            return parsed_logs

        # Pattern: ftp.py:.*b'PASS .*'
        match = re.search(r"ftp\.py:[\d]+-debug: b'PASS (.*?)\\r\\n'", raw_log)
        if match:
            parsed_logs.append({
                "type": "ftp_password",
                "timestamp": timestamp,
                "password": match.group(1)
            })
            return parsed_logs

        # Altri incident ID semplici (senza ctx)
        match = re.search(r'incident (\S+) dionaea', raw_log)
        if match:
            parsed_logs.append({
                "type": "incident",
                "timestamp": timestamp,
                "incident_id": match.group(1)
            })
            return parsed_logs

        # Nessun pattern corrispondente
        parsed_logs.append({
            "warning": "No parsable Dionaea entries found",
            "raw": raw_log
        })

        return parsed_logs

    def extract_timestamp(self, raw_log: str) -> str:
        match = re.search(r'\[(\d{2})(\d{2})(\d{4}) (\d{2}):(\d{2}):(\d{2})\]', raw_log)
        if match:
            day, month, year, hour, minute, second = match.groups()
            dt = datetime.strptime(f"{year}-{month}-{day} {hour}:{minute}:{second}", "%Y-%m-%d %H:%M:%S")
            return dt.isoformat()
        return ""