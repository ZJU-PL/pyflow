import subprocess
import argparse
import sys
import json
from datetime import datetime
from typing import Dict, List, Optional

class SystemMonitor:
    def __init__(self):
        self.history_file = "monitor_history.json"
        self.history = self._load_history()

    def _load_history(self) -> Dict:
        try:
            with open(self.history_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save_history(self):
        with open(self.history_file, 'w') as f:
            json.dump(self.history, f)

    def check_disk_usage(self, path: str = "/") -> Dict:
        try:
            output = subprocess.check_output(["df", "-h", path]).decode()
            lines = output.split('\n')
            headers = lines[0].split()
            values = lines[1].split()
            return dict(zip(headers, values))
        except subprocess.CalledProcessError as e:
            return {"error": str(e)}

    def check_process(self, process_name: str) -> Dict:
        # Fixed: No longer vulnerable to command injection
        try:
            # Use pgrep to safely find process IDs first
            pgrep_cmd = ["pgrep", "-f", process_name]
            pgrep_result = subprocess.run(
                pgrep_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False
            )
            
            if not pgrep_result.stdout.strip():
                return {"processes": []}
                
            # Get process details using ps with specific PIDs
            pids = pgrep_result.stdout.split()
            ps_cmd = ["ps", "-o", "user,pid,pcpu,pmem,command", "-p", ",".join(pids)]
            ps_result = subprocess.run(
                ps_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            
            processes = []
            lines = ps_result.stdout.split('\n')[1:]  # Skip header
            for line in lines:
                if line.strip():
                    parts = line.split(maxsplit=4)  # Split into 5 parts (last is command)
                    processes.append({
                        "user": parts[0],
                        "pid": parts[1],
                        "cpu": parts[2],
                        "mem": parts[3],
                        "command": parts[4] if len(parts) > 4 else ""
                    })
            return {"processes": processes}
            
        except subprocess.CalledProcessError:
            return {"processes": []}
        except Exception as e:
            return {"error": str(e)}

    def log_metric(self, metric_name: str, value: float):
        timestamp = datetime.now().isoformat()
        if metric_name not in self.history:
            self.history[metric_name] = []
        self.history[metric_name].append({"timestamp": timestamp, "value": value})
        self._save_history()

    def get_metric_history(self, metric_name: str) -> List[Dict]:
        return self.history.get(metric_name, [])

def main():
    parser = argparse.ArgumentParser(description="System Monitoring Tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    disk_parser = subparsers.add_parser("disk")
    disk_parser.add_argument("--path", default="/", help="Path to check disk usage")

    process_parser = subparsers.add_parser("process")
    process_parser.add_argument("name", help="Process name to check")

    log_parser = subparsers.add_parser("log")
    log_parser.add_argument("metric", help="Metric name to log")
    log_parser.add_argument("value", type=float, help="Metric value")

    history_parser = subparsers.add_parser("history")
    history_parser.add_argument("metric", help="Metric name to view history")

    args = parser.parse_args()
    monitor = SystemMonitor()

    if args.command == "disk":
        result = monitor.check_disk_usage(args.path)
        print(json.dumps(result, indent=2))
    elif args.command == "process":
        result = monitor.check_process(args.name)
        print(json.dumps(result, indent=2))
    elif args.command == "log":
        monitor.log_metric(args.metric, args.value)
        print("Metric logged successfully")
    elif args.command == "history":
        history = monitor.get_metric_history(args.metric)
        print(json.dumps(history, indent=2))

if __name__ == "__main__":
    main()