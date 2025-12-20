"""
Formatting utilities for human-readable output.

Provides functions to format time durations and memory sizes in
appropriate units with readable representations.
"""


def elapsedTime(t):
    """
    Format a time duration in seconds as a human-readable string.
    
    Automatically selects the most appropriate unit:
    - Milliseconds for times < 1 second
    - Seconds for times < 1 minute
    - Minutes for times < 1 hour
    - Hours for times >= 1 hour
    
    Args:
        t: Time duration in seconds (float)
        
    Returns:
        Formatted string with appropriate unit (e.g., "123.4 ms", "45.6 s")
        
    Example:
        elapsedTime(0.05) -> "50 ms"
        elapsedTime(125.5) -> "2.091 m"
    """
    if t < 1.0:
        return "%5.4g ms" % (t * 1000.0)
    elif t < 60.0:
        return "%5.4g s" % (t)
    elif t < 3600.0:
        return "%5.4g m" % (t / 60.0)
    else:
        return "%5.4g h" % (t / 3600.0)


def memorySize(sz):
    """
    Format a memory size in bytes as a human-readable string.
    
    Automatically selects the most appropriate unit:
    - Bytes for sizes < 1 KB
    - KB for sizes < 1 MB
    - MB for sizes < 1 GB
    - GB for sizes < 1 TB
    - TB for sizes >= 1 TB
    
    Args:
        sz: Memory size in bytes (int or float)
        
    Returns:
        Formatted string with appropriate unit (e.g., "512 B", "1.5 MB")
        
    Example:
        memorySize(512) -> "512 B"
        memorySize(1048576) -> "1 MB"
        memorySize(1536000000) -> "1.465 GB"
    """
    fsz = float(sz)
    if sz < 1024:
        return "%5g B" % fsz
    elif sz < 1024**2:
        return "%5.4g KB" % (fsz / (1024))
    elif sz < 1024**3:
        return "%5.4g MB" % (fsz / (1024**2))
    elif sz < 1024**4:
        return "%5.4g GB" % (fsz / (1024**3))
    else:
        return "%5.4g TB" % (fsz / (1024**4))
