"""
STACK_OVERFLOW True Negative #4: Bounded Recursion with Base Case
Ground Truth: SAFE

Well-structured recursion with guaranteed termination.
Base case ensures recursion depth is bounded by input size.
"""

def sum_list_recursive(lst):
    """Recursive sum with proper base case."""
    if not lst:
        return 0
    return lst[0] + sum_list_recursive(lst[1:])

def binary_search(arr, target, left=0, right=None):
    """Binary search - recursion depth O(log n)."""
    if right is None:
        right = len(arr) - 1
    
    if left > right:
        return -1
    
    mid = (left + right) // 2
    if arr[mid] == target:
        return mid
    elif arr[mid] < target:
        return binary_search(arr, target, left=mid + 1, right=right)
    else:
        return binary_search(arr, target, left=left, right=mid - 1)

def main():
    # Small list - bounded recursion depth
    small_list = list(range(100))
    result = sum_list_recursive(small_list)
    print(f"Sum of {len(small_list)} elements: {result}")
    
    # Binary search - O(log n) depth even for large arrays
    large_array = list(range(100000))
    idx = binary_search(large_array, 50000)
    print(f"Found 50000 at index {idx}")

if __name__ == "__main__":
    main()
