"""
DOUBLE_FREE True Positive #2: Socket double close()

Ground truth: BUG - DOUBLE_FREE
Reasoning: Closing a socket twice. The first close() releases the socket
descriptor; the second close() attempts to free the same descriptor again.

The analyzer should detect:
- socket.close() transitions socket to closed state
- Second close() on already-closed socket (double-free)
"""

import socket

def double_close_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.close()
    # BUG: double close
    sock.close()

if __name__ == "__main__":
    double_close_socket()
