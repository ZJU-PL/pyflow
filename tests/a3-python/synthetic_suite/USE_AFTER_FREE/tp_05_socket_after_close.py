"""
USE_AFTER_FREE True Positive 5: Socket use after close()

Expected: BUG - USE_AFTER_FREE
Reason: Using a socket after close() is use-after-free semantics.
        The socket resource is freed, but we attempt I/O.
"""
import socket

def test_socket_after_close():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.close()
    sock.send(b"data")  # BUG: use after close

if __name__ == "__main__":
    test_socket_after_close()
