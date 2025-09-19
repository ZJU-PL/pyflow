#!/usr/bin/env python3
"""
Data Structures Example for PyFlow

This example demonstrates data structure operations including lists, tuples,
classes, and object manipulation that can be analyzed by PyFlow's shape analysis.

Usage:
    pyflow optimize data_structures.py --analysis shape
    pyflow callgraph data_structures.py
"""

class Point:
    """A simple 2D point class."""
    
    def __init__(self, x, y):
        self.x = x
        self.y = y
    
    def distance_to(self, other):
        """Calculate distance to another point."""
        dx = self.x - other.x
        dy = self.y - other.y
        return (dx * dx + dy * dy) ** 0.5
    
    def __str__(self):
        return f"Point({self.x}, {self.y})"

class Rectangle:
    """A rectangle class with width and height."""
    
    def __init__(self, width, height):
        self.width = width
        self.height = height
    
    def area(self):
        """Calculate the area of the rectangle."""
        return self.width * self.height
    
    def perimeter(self):
        """Calculate the perimeter of the rectangle."""
        return 2 * (self.width + self.height)

def create_point_list(coordinates):
    """Create a list of Point objects from coordinate pairs."""
    points = []
    for x, y in coordinates:
        points.append(Point(x, y))
    return points

def find_closest_point(target, points):
    """Find the point closest to the target point."""
    if not points:
        return None
    
    closest = points[0]
    min_distance = target.distance_to(closest)
    
    for point in points[1:]:
        distance = target.distance_to(point)
        if distance < min_distance:
            min_distance = distance
            closest = point
    
    return closest

def process_shapes(rectangles):
    """Process a list of rectangles and return summary statistics."""
    if not rectangles:
        return {"count": 0, "total_area": 0, "avg_area": 0}
    
    total_area = 0
    for rect in rectangles:
        total_area += rect.area()
    
    return {
        "count": len(rectangles),
        "total_area": total_area,
        "avg_area": total_area / len(rectangles)
    }

def create_coordinate_pairs(n):
    """Create n coordinate pairs as tuples."""
    pairs = []
    for i in range(n):
        pairs.append((i * 2, i * 3))
    return pairs

def manipulate_lists(data):
    """Demonstrate various list operations."""
    # Create a copy
    result = data[:]
    
    # Add elements
    result.append(100)
    result.insert(0, -1)
    
    # Remove elements
    if 5 in result:
        result.remove(5)
    
    # Sort
    result.sort()
    
    return result

if __name__ == "__main__":
    # Example usage
    coordinates = [(0, 0), (3, 4), (1, 1), (5, 5)]
    points = create_point_list(coordinates)
    
    target = Point(2, 2)
    closest = find_closest_point(target, points)
    print(f"Closest point to {target}: {closest}")
    
    rectangles = [Rectangle(3, 4), Rectangle(5, 2), Rectangle(1, 8)]
    stats = process_shapes(rectangles)
    print(f"Rectangle statistics: {stats}")
    
    data = [3, 1, 4, 1, 5, 9]
    manipulated = manipulate_lists(data)
    print(f"Original: {data}")
    print(f"Manipulated: {manipulated}")
    
    pairs = create_coordinate_pairs(3)
    print(f"Coordinate pairs: {pairs}")
