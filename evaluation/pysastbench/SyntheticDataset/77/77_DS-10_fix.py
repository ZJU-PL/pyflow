import subprocess
import argparse
import sys
import re
from typing import Optional, Dict, List

class NetworkConfigurator:
    def __init__(self, interface: str = "eth0"):
        self.interface = interface
        self.sysctl_path = "/proc/sys/net/ipv4/"

    def validate_ip(self, ip: str) -> bool:
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return re.match(pattern, ip) is not None

    def get_current_config(self) -> Dict[str, str]:
        config = {}
        try:
            result = subprocess.run(["ifconfig", self.interface], capture_output=True, text=True)
            if result.returncode == 0:
                config["interface"] = self.interface
                ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
                if ip_match:
                    config["ip"] = ip_match.group(1)
        except Exception:
            pass
        return config

    def set_static_ip(self, ip: str, netmask: str = "255.255.255.0") -> bool:
        if not self.validate_ip(ip) or not self.validate_ip(netmask):
            print("Invalid IP address format", file=sys.stderr)
            return False

        try:
            subprocess.run(["ifconfig", self.interface, ip, "netmask", netmask], check=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to set IP: {e}", file=sys.stderr)
            return False

    def configure_kernel_param(self, param: str, value: str) -> bool:
        """Safely configure kernel parameter without command injection vulnerability"""
        try:
            # Validate parameter name contains only safe characters
            if not re.match(r'^[a-zA-Z0-9_.-]+$', param):
                print("Invalid parameter name", file=sys.stderr)
                return False
                
            # Construct the path to the sysctl parameter
            param_path = f"{self.sysctl_path}{param.replace('.', '/')}"
            
            # Write the value directly to the sysctl file
            with open(param_path, 'w') as f:
                f.write(value)
            return True
        except FileNotFoundError:
            print(f"Parameter not found: {param}", file=sys.stderr)
            return False
        except PermissionError:
            print(f"Permission denied when writing to {param}", file=sys.stderr)
            return False
        except Exception as e:
            print(f"Failed to configure parameter: {e}", file=sys.stderr)
            return False

    def apply_routing_rules(self, rules: List[str]) -> bool:
        try:
            for rule in rules:
                subprocess.run(["ip", "route", "add"] + rule.split(), check=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to apply routing rules: {e}", file=sys.stderr)
            return False

def main():
    parser = argparse.ArgumentParser(description="Network Configuration Tool")
    parser.add_argument("--interface", default="eth0", help="Network interface to configure")
    subparsers = parser.add_subparsers(dest="command", required=True)

    show_parser = subparsers.add_parser("show", help="Show current configuration")

    ip_parser = subparsers.add_parser("ip", help="Set static IP address")
    ip_parser.add_argument("address", help="IP address to set")
    ip_parser.add_argument("--netmask", default="255.255.255.0", help="Network mask")

    sysctl_parser = subparsers.add_parser("sysctl", help="Configure kernel parameter")
    sysctl_parser.add_argument("parameter", help="Parameter name")
    sysctl_parser.add_argument("value", help="Parameter value")

    route_parser = subparsers.add_parser("route", help="Add routing rule")
    route_parser.add_argument("rules", nargs="+", help="Routing rules to add")

    args = parser.parse_args()
    configurator = NetworkConfigurator(args.interface)

    if args.command == "show":
        config = configurator.get_current_config()
        print(f"Interface: {config.get('interface', 'N/A')}")
        print(f"IP Address: {config.get('ip', 'N/A')}")
    elif args.command == "ip":
        success = configurator.set_static_ip(args.address, args.netmask)
        print("IP configuration", "succeeded" if success else "failed")
    elif args.command == "sysctl":
        success = configurator.configure_kernel_param(args.parameter, args.value)
        print("Parameter configuration", "succeeded" if success else "failed")
    elif args.command == "route":
        success = configurator.apply_routing_rules(args.rules)
        print("Routing configuration", "succeeded" if success else "failed")

if __name__ == "__main__":
    main()