"""
DOUBLE_FREE True Negative #3: Context manager proper usage

Ground truth: SAFE
Reasoning: Using with-statement for automatic resource cleanup. The context
manager's __exit__ is called exactly once automatically.

The analyzer should verify:
- with-statement guarantees single __exit__ call
- No manual close() after with-block
- Proper resource lifecycle
"""

def context_manager_proper():
    with open("data.txt", "w") as f:
        f.write("content")
    # SAFE: file is closed automatically once by with-statement
    # No second close attempted

if __name__ == "__main__":
    context_manager_proper()
