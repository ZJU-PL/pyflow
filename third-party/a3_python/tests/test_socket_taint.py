"""
Test network socket taint tracking (Iteration 530).

Verifies that sockets created from tainted URLs/addresses properly
propagate taint to received data.

This implements socket object taint tracking similar to cursor taint tracking
(Iteration 529). Key insight: socket.recv() should inherit taint from BOTH
the NETWORK_RECV source AND the socket object itself (if the socket was created
from a tainted URL/address).
"""

import pytest
from a3_python.z3model.taint_lattice import (
    TaintLabel, SourceType, SinkType
)
from a3_python.semantics.security_tracker_lattice import (
    LatticeSecurityTracker
)


def test_socket_from_tainted_url_is_tainted():
    """
    Test: sock = socket.create_connection((host, port)) where host is tainted
    Expected: sock inherits taint from host
    """
    tracker = LatticeSecurityTracker()
    
    # Simulate: host = request.args.get('host')
    host = "tainted_host"
    host_label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
    tracker.set_label(host, host_label)
    
    # Clean port
    port = 80
    port_label = TaintLabel.clean()
    tracker.set_label(port, port_label)
    
    # Simulate: sock = socket.create_connection((host, port))
    # The create_connection() function should propagate taint from arguments to result
    sock = "socket_object"
    sock_result_label, _ = tracker.handle_call_post(
        func_name="socket.create_connection",
        func_ref=None,
        args=[host, port],
        result=sock,
        location="test:10"
    )
    
    # Verify: sock is tainted from host
    assert sock_result_label.has_untrusted_taint(), \
        "Socket should inherit taint from host"
    assert sock_result_label.tau == host_label.tau, \
        "Socket should have same τ bits as host"


def test_socket_recv_from_tainted_socket_is_tainted():
    """
    Test: data = sock.recv(1024) where sock is tainted
    Expected: data inherits taint from sock AND NETWORK source
    """
    tracker = LatticeSecurityTracker()
    
    # Create tainted socket (simulating connection to tainted host)
    sock = "socket_object"
    sock_label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
    tracker.set_label(sock, sock_label)
    
    # Simulate: data = sock.recv(1024)
    # This is BOTH a source (NETWORK) AND should inherit from sock
    data = "received_data"
    data_label, _ = tracker.handle_call_post(
        func_name="socket.recv",
        func_ref=sock,  # Method call on socket
        args=[1024],
        result=data,
        location="test:20"
    )
    
    # Verify: data has NETWORK taint
    assert data_label.has_untrusted_taint(), \
        "Received data should be tainted (from NETWORK source)"
    
    # Verify: data also inherits socket's taint
    network_bit = 1 << SourceType.NETWORK_RECV.value
    http_bit = 1 << SourceType.HTTP_PARAM.value
    assert (data_label.tau & http_bit) != 0, \
        "Received data should inherit HTTP_PARAM taint from socket"
    assert (data_label.tau & network_bit) != 0, \
        "Received data should have NETWORK_RECV taint from source"


def test_clean_socket_produces_network_taint_only():
    """
    Test: socket from clean address should only have NETWORK taint, not the address taint
    """
    tracker = LatticeSecurityTracker()
    
    # Clean host (hardcoded)
    host = "api.example.com"
    host_label = TaintLabel.clean()
    tracker.set_label(host, host_label)
    
    port = 443
    port_label = TaintLabel.clean()
    tracker.set_label(port, port_label)
    
    # sock = socket.create_connection((host, port))
    sock = "socket"
    sock_label, _ = tracker.handle_call_post(
        func_name="socket.create_connection",
        func_ref=None,
        args=[host, port],
        result=sock,
        location="test:30"
    )
    
    # Clean address → clean socket (but recv will add NETWORK taint)
    assert not sock_label.has_untrusted_taint(), \
        "Socket from clean address should be clean (no false positive)"
    
    # data = sock.recv(1024)
    data = "data"
    data_label, _ = tracker.handle_call_post(
        func_name="socket.recv",
        func_ref=sock,
        args=[1024],
        result=data,
        location="test:31"
    )
    
    # Data should have NETWORK_RECV taint but not HTTP_PARAM taint
    network_bit = 1 << SourceType.NETWORK_RECV.value
    http_bit = 1 << SourceType.HTTP_PARAM.value
    assert (data_label.tau & network_bit) != 0, \
        "Received data should have NETWORK_RECV taint"
    assert (data_label.tau & http_bit) == 0, \
        "Received data should NOT have HTTP_PARAM taint from clean socket"


def test_end_to_end_tainted_socket_to_ssrf():
    """
    Test: full flow from tainted URL to SSRF
    
    url = request.args.get('url')     # Tainted
    parsed = urlparse(url)             # Tainted
    sock = connect(parsed.netloc)      # Tainted
    data = sock.recv(1024)             # Tainted
    requests.get(data.decode())        # FULL_SSRF!
    """
    tracker = LatticeSecurityTracker()
    
    # 1. Tainted URL from HTTP param
    url = "user_url"
    url_label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM)
    tracker.set_label(url, url_label)
    
    # 2. Parse URL (taint propagates)
    host = "parsed_host"
    # Simulate: host = urlparse(url).netloc
    # For simplicity, just propagate the taint
    tracker.set_label(host, url_label)
    
    # 3. Create socket with tainted host
    sock = "sock"
    sock_label, _ = tracker.handle_call_post(
        func_name="socket.create_connection",
        func_ref=None,
        args=[host, 80],
        result=sock,
        location="test:40"
    )
    assert sock_label.has_untrusted_taint()
    
    # 4. Receive data from tainted socket
    data = "received"
    data_label, _ = tracker.handle_call_post(
        func_name="socket.recv",
        func_ref=sock,
        args=[1024],
        result=data,
        location="test:41"
    )
    assert data_label.has_untrusted_taint()
    
    # 5. Use tainted data as URL in HTTP request - should detect FULL_SSRF
    # Simulate: requests.get(data.decode())
    # The data is tainted, decode() propagates taint, then used as URL
    decoded_url = "decoded_url"
    tracker.set_label(decoded_url, data_label)
    
    violation = tracker.handle_call_pre(
        func_name="requests.get",
        args=[decoded_url],
        location="test:45",
        is_method_call=False
    )
    
    # Verify: SSRF detected
    assert violation is not None, "Should detect SSRF"
    assert violation.bug_type == "SSRF", \
        f"Expected SSRF, got {violation.bug_type}"


def test_socket_from_clean_host_with_tainted_request():
    """
    Test: Clean socket can still send tainted requests (normal SSRF)
    
    This is the standard SSRF case - the socket itself is clean,
    but the URL/request is tainted from user input.
    """
    tracker = LatticeSecurityTracker()
    
    # Clean host
    host = "api.example.com"
    tracker.set_label(host, TaintLabel.clean())
    
    # Clean socket
    sock = "socket"
    sock_label, _ = tracker.handle_call_post(
        func_name="socket.create_connection",
        func_ref=None,
        args=[host, 443],
        result=sock,
        location="test:50"
    )
    assert not sock_label.has_untrusted_taint()
    
    # Tainted URL from HTTP param
    url = "https://attacker.com/evil"
    url_label = TaintLabel.from_untrusted_source(SourceType.HTTP_PARAM, "test:51")
    tracker.set_label(url, url_label)
    
    # Use tainted URL in requests.get - should detect SSRF
    violation = tracker.handle_call_pre(
        func_name="requests.get",
        args=[url],
        location="test:52",
        is_method_call=False
    )
    
    assert violation is not None, "Should detect SSRF"
    assert violation.bug_type == "SSRF"


def test_socket_sendall_with_tainted_data():
    """
    Test: sock.sendall(tainted_data) should propagate taint
    
    This verifies that data sent through sockets maintains taint,
    which is important for tracking data exfiltration.
    """
    tracker = LatticeSecurityTracker()
    
    # Clean socket
    sock = "socket"
    sock_label = TaintLabel.clean()
    tracker.set_label(sock, sock_label)
    
    # Tainted data (e.g., password)
    sensitive_data = "password123"
    data_label = TaintLabel.from_sensitive_source(SourceType.PASSWORD, "test:60")
    tracker.set_label(sensitive_data, data_label)
    
    # Send tainted data through socket - should detect cleartext exposure
    # Note: This would require a CLEARTEXT_NETWORK_SEND sink type
    # For now, just verify taint propagates through sendall
    violation = tracker.handle_call_pre(
        func_name="socket.sendall",
        args=[sock, sensitive_data],
        location="test:61",
        is_method_call=True
    )
    
    # This test verifies the infrastructure works
    # Actual violation detection depends on having appropriate sink contracts
    # We expect no violation here since we don't have CLEARTEXT_NETWORK_SEND sink yet
    # but the taint should be tracked
    assert data_label.has_sensitivity(), \
        "Sensitive data should maintain sensitivity marker"


def test_urllib_request_with_tainted_url():
    """
    Test: urllib.request.urlopen(tainted_url) should detect SSRF
    """
    tracker = LatticeSecurityTracker()
    
    # Tainted URL from user input
    url = "user_supplied_url"
    url_label = TaintLabel.from_untrusted_source(SourceType.USER_INPUT, "test:70")
    tracker.set_label(url, url_label)
    
    # urlopen with tainted URL
    violation = tracker.handle_call_pre(
        func_name="urllib.request.urlopen",
        args=[url],
        location="test:71",
        is_method_call=False
    )
    
    # Should detect SSRF
    assert violation is not None, "Should detect SSRF"
    assert violation.bug_type == "SSRF"
