"""
NULL_PTR True Negative #5: All paths assign non-None before use

Ground truth: SAFE
Bug type: NULL_PTR
Reason: All control paths assign non-None value before dereference

Semantic model: Control flow ensures non-None at dereference on all paths.
"""

def process(value, mode):
    if mode == "default":
        result = {"status": "ok"}
    else:
        # SAFE: This path also assigns dict (not None)
        result = {"status": "custom"}
    
    # SAFE: result is guaranteed to be dict on all paths
    status = result.get("status")
    return status

def main():
    output = process(42, "custom")
    print(output)

if __name__ == "__main__":
    main()
