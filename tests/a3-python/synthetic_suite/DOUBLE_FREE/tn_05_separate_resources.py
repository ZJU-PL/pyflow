"""
DOUBLE_FREE True Negative #5: Separate resources

Ground truth: SAFE
Reasoning: Two separate file objects are opened and each is closed once.
No resource is closed twice.

The analyzer should verify:
- Each resource has distinct identity
- Each close() operates on a different resource
- No double-free occurs
"""

def separate_resources():
    f1 = open("file1.txt", "w")
    f2 = open("file2.txt", "w")
    
    f1.write("data1")
    f2.write("data2")
    
    f1.close()
    f2.close()
    # SAFE: two different resources, each closed once

if __name__ == "__main__":
    separate_resources()
