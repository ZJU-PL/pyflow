import subprocess
import argparse
import sys
import json
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import Optional, Dict

class WebhookTester:
    def __init__(self, port: int = 8000):
        self.port = port
        self.last_payload: Optional[Dict] = None
        self.server_thread: Optional[Thread] = None
        self.server: Optional[HTTPServer] = None

    class RequestHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            self.server.webhook_tester.last_payload = json.loads(post_data.decode())
            self.send_response(200)
            self.end_headers()

    def start_server(self):
        handler = self.RequestHandler
        handler.server = self
        self.server = HTTPServer(('', self.port), handler)
        self.server.webhook_tester = self
        self.server_thread = Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop_server(self):
        if self.server:
            self.server.shutdown()
            self.server_thread.join()

    def test_curl_request(self, url: str, data: Optional[Dict] = None) -> str:
        # Fixed: No longer vulnerable to command injection
        try:
            cmd = ["curl", "-X", "POST", "--fail", "--silent", "--show-error"]
            
            # Validate URL format
            parsed_url = urllib.parse.urlparse(url)
            if not all([parsed_url.scheme, parsed_url.netloc]):
                raise ValueError("Invalid URL format")
                
            if data:
                # Use --data-binary to safely pass JSON data
                cmd.extend(["--data-binary", json.dumps(data)])
                cmd.extend(["-H", "Content-Type: application/json"])
            
            cmd.append(url)
            
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False
            )
            return result.stdout if result.returncode == 0 else result.stderr
        except ValueError as e:
            return f"Error: {str(e)}"
        except Exception as e:
            return f"Unexpected error: {str(e)}"

    def generate_ngrok_url(self) -> str:
        # Fixed: No longer vulnerable to command injection
        try:
            result = subprocess.run(
                ["curl", "-s", "http://localhost:4040/api/tunnels"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            tunnels = json.loads(result.stdout)['tunnels']
            https_tunnel = next(t for t in tunnels if t['proto'] == 'https')
            return https_tunnel['public_url']
        except json.JSONDecodeError:
            return "Error: Invalid response from ngrok"
        except StopIteration:
            return "Error: No HTTPS tunnel found"
        except Exception as e:
            return f"Error: {str(e)}"

def main():
    parser = argparse.ArgumentParser(description="Webhook Testing Utility")
    subparsers = parser.add_subparsers(dest="command", required=True)

    server_parser = subparsers.add_parser("server", help="Start webhook server")
    server_parser.add_argument("--port", type=int, default=8000, help="Port to listen on")

    test_parser = subparsers.add_parser("test", help="Test webhook URL")
    test_parser.add_argument("url", help="URL to test")
    test_parser.add_argument("--data", help="JSON data to send")

    ngrok_parser = subparsers.add_parser("ngrok", help="Get ngrok URL")

    args = parser.parse_args()
    tester = WebhookTester(args.port if hasattr(args, 'port') else 8000)

    try:
        if args.command == "server":
            tester.start_server()
            print(f"Server running on port {args.port}. Press Ctrl+C to stop...")
            try:
                while True:
                    pass
            except KeyboardInterrupt:
                tester.stop_server()
        elif args.command == "test":
            data = json.loads(args.data) if args.data else None
            result = tester.test_curl_request(args.url, data)
            print(result)
            if tester.last_payload:
                print("\nLast received payload:", json.dumps(tester.last_payload, indent=2))
        elif args.command == "ngrok":
            print(tester.generate_ngrok_url())
    except json.JSONDecodeError:
        print("Error: Invalid JSON data", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()