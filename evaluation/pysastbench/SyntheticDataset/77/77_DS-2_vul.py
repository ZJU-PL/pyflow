import subprocess
import sys
import argparse
import socket
import re
from typing import List, Optional

class NetworkDiagnostics:
    def __init__(self, target_host: str):
        self.target_host = target_host
        self.validate_host()

    def validate_host(self) -> bool:
        try:
            socket.gethostbyname(self.target_host)
            return True
        except socket.gaierror:
            print(f"Error: Unable to resolve {self.target_host}")
            sys.exit(1)

    def ping_host(self, count: int = 4) -> str:
        try:
            result = subprocess.check_output(
                f"ping -c {count} {self.target_host}",
                shell=True,
                stderr=subprocess.STDOUT
            )
            return result.decode()
        except subprocess.CalledProcessError as e:
            return e.output.decode()

    def trace_route(self) -> str:
        # Vulnerable function - command injection via target_host
        try:
            trace = subprocess.check_output(
                f"traceroute {self.target_host}",
                shell=True,
                stderr=subprocess.STDOUT
            )
            return trace.decode()
        except subprocess.CalledProcessError as e:
            return e.output.decode()

    def dns_lookup(self, record_type: str = "A") -> List[str]:
        try:
            output = subprocess.check_output(
                ["dig", "+short", self.target_host, record_type],
                stderr=subprocess.STDOUT
            )
            return output.decode().splitlines()
        except subprocess.CalledProcessError:
            return []

    def port_scan(self, ports: str) -> dict:
        try:
            open_ports = []
            for port in map(int, ports.split(',')):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target_host, port))
                if result == 0:
                    open_ports.append(str(port))
                sock.close()
            return {'open_ports': open_ports}
        except ValueError:
            return {'error': 'Invalid port numbers'}

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Network Diagnostics Tool')
    parser.add_argument('host', help='Target hostname or IP address')
    subparsers = parser.add_subparsers(dest='command', required=True)

    ping_parser = subparsers.add_parser('ping')
    ping_parser.add_argument('-c', type=int, default=4, help='Packet count')

    traceroute_parser = subparsers.add_parser('traceroute')

    dns_parser = subparsers.add_parser('dns')
    dns_parser.add_argument('-t', default='A', help='Record type')

    scan_parser = subparsers.add_parser('scan')
    scan_parser.add_argument('ports', help='Comma-separated port list')

    return parser.parse_args()

def main() -> None:
    args = parse_args()
    diag = NetworkDiagnostics(args.host)

    if args.command == 'ping':
        print(diag.ping_host(args.c))
    elif args.command == 'traceroute':
        print(diag.trace_route())
    elif args.command == 'dns':
        print('\n'.join(diag.dns_lookup(args.t)))
    elif args.command == 'scan':
        result = diag.port_scan(args.ports)
        if 'error' in result:
            print(result['error'])
        else:
            print('Open ports:', ', '.join(result['open_ports']))

if __name__ == '__main__':
    main()