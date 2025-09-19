#!/usr/bin/env python3
"""
Complex Nested Structures and Edge Cases Example for PyFlow

This example demonstrates complex nested structures, edge cases, and advanced
Python features that can be analyzed by PyFlow's static analysis tools.

Usage:
    pyflow optimize complex_nested.py --analysis all
    pyflow callgraph complex_nested.py
"""

import sys
from typing import Any, Dict, List, Optional, Union, Callable, TypeVar, Generic
from dataclasses import dataclass, field
from enum import Enum
import functools

# Complex nested data structures
@dataclass
class Node:
    """Tree node with complex relationships."""
    value: Any
    children: List['Node'] = field(default_factory=list)
    parent: Optional['Node'] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_child(self, child: 'Node') -> None:
        """Add a child node."""
        child.parent = self
        self.children.append(child)
    
    def find_descendants(self, predicate: Callable[[Any], bool]) -> List['Node']:
        """Find all descendants matching predicate."""
        results = []
        for child in self.children:
            if predicate(child.value):
                results.append(child)
            results.extend(child.find_descendants(predicate))
        return results
    
    def get_path_to_root(self) -> List['Node']:
        """Get path from this node to root."""
        path = [self]
        current = self.parent
        while current:
            path.append(current)
            current = current.parent
        return path

class Graph:
    """Complex graph structure with multiple edge types."""
    
    def __init__(self):
        self.nodes: Dict[str, Any] = {}
        self.edges: List[Dict[str, Any]] = []
        self.adjacency: Dict[str, List[str]] = {}
    
    def add_node(self, node_id: str, data: Any) -> None:
        """Add a node to the graph."""
        self.nodes[node_id] = data
        self.adjacency[node_id] = []
    
    def add_edge(self, from_node: str, to_node: str, weight: float = 1.0, 
                 edge_type: str = "default") -> None:
        """Add an edge between nodes."""
        if from_node not in self.nodes or to_node not in self.nodes:
            raise ValueError("Node not found")
        
        edge = {
            "from": from_node,
            "to": to_node,
            "weight": weight,
            "type": edge_type
        }
        self.edges.append(edge)
        self.adjacency[from_node].append(to_node)
    
    def find_shortest_path(self, start: str, end: str) -> Optional[List[str]]:
        """Find shortest path using BFS."""
        if start not in self.nodes or end not in self.nodes:
            return None
        
        queue = [(start, [start])]
        visited = {start}
        
        while queue:
            current, path = queue.pop(0)
            if current == end:
                return path
            
            for neighbor in self.adjacency.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))
        
        return None

# Complex inheritance hierarchy
class Animal:
    """Base animal class."""
    
    def __init__(self, name: str, species: str):
        self.name = name
        self.species = species
        self.energy = 100
    
    def move(self) -> str:
        """Generic move method."""
        self.energy -= 10
        return f"{self.name} moves"
    
    def eat(self, food: str) -> str:
        """Generic eat method."""
        self.energy += 20
        return f"{self.name} eats {food}"

class Mammal(Animal):
    """Mammal subclass."""
    
    def __init__(self, name: str, species: str, warm_blooded: bool = True):
        super().__init__(name, species)
        self.warm_blooded = warm_blooded
        self.body_temperature = 37.0 if warm_blooded else 20.0
    
    def regulate_temperature(self) -> str:
        """Regulate body temperature."""
        if self.warm_blooded:
            return f"{self.name} maintains {self.body_temperature}°C"
        return f"{self.name} adapts to environment"

class Bird(Animal):
    """Bird subclass."""
    
    def __init__(self, name: str, species: str, can_fly: bool = True):
        super().__init__(name, species)
        self.can_fly = can_fly
        self.wingspan = 0.0
    
    def fly(self) -> str:
        """Fly method."""
        if self.can_fly:
            self.energy -= 15
            return f"{self.name} flies"
        return f"{self.name} cannot fly"

class FlyingMammal(Mammal, Bird):
    """Multiple inheritance example."""
    
    def __init__(self, name: str, species: str):
        Mammal.__init__(self, name, species, warm_blooded=True)
        Bird.__init__(self, name, species, can_fly=True)
        self.nocturnal = True
    
    def hunt_at_night(self) -> str:
        """Hunt at night."""
        if self.nocturnal:
            return f"{self.name} hunts at night"
        return f"{self.name} hunts during day"

# Complex function with nested logic
def complex_algorithm(data: List[Dict[str, Any]], 
                     filters: List[Callable[[Dict[str, Any]], bool]],
                     transformers: List[Callable[[Dict[str, Any]], Dict[str, Any]]],
                     aggregators: List[Callable[[List[Dict[str, Any]]], Any]]) -> Dict[str, Any]:
    """Complex algorithm with multiple processing steps."""
    
    # Step 1: Apply filters
    filtered_data = data
    for filter_func in filters:
        filtered_data = [item for item in filtered_data if filter_func(item)]
    
    # Step 2: Apply transformers
    transformed_data = []
    for item in filtered_data:
        transformed_item = item.copy()
        for transformer in transformers:
            try:
                transformed_item = transformer(transformed_item)
            except Exception as e:
                print(f"Transform error: {e}")
                continue
        transformed_data.append(transformed_item)
    
    # Step 3: Apply aggregators
    results = {}
    for i, aggregator in enumerate(aggregators):
        try:
            results[f"aggregate_{i}"] = aggregator(transformed_data)
        except Exception as e:
            print(f"Aggregation error: {e}")
            results[f"aggregate_{i}"] = None
    
    return results

# Complex decorator with state
def complex_decorator(initial_state: Dict[str, Any] = None):
    """Complex decorator with state management."""
    if initial_state is None:
        initial_state = {}
    
    def decorator(func):
        state = initial_state.copy()
        call_count = 0
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            
            # Update state
            state['call_count'] = call_count
            state['last_args'] = args
            state['last_kwargs'] = kwargs
            
            # Pre-processing
            if 'pre_hook' in state:
                state['pre_hook'](args, kwargs)
            
            try:
                result = func(*args, **kwargs)
                
                # Post-processing
                if 'post_hook' in state:
                    state['post_hook'](result)
                
                return result
            except Exception as e:
                state['last_error'] = e
                if 'error_hook' in state:
                    state['error_hook'](e)
                raise
        
        # Add state management methods
        wrapper.get_state = lambda: state.copy()
        wrapper.update_state = lambda updates: state.update(updates)
        wrapper.reset_state = lambda: state.clear()
        
        return wrapper
    return decorator

# Complex context manager
class ComplexContextManager:
    """Complex context manager with multiple resources."""
    
    def __init__(self, resources: List[str]):
        self.resources = resources
        self.acquired_resources = []
        self.state = {}
    
    def __enter__(self):
        """Acquire resources."""
        for resource in self.resources:
            try:
                # Simulate resource acquisition
                self.acquired_resources.append(resource)
                self.state[resource] = f"acquired_{resource}"
                print(f"Acquired resource: {resource}")
            except Exception as e:
                print(f"Failed to acquire {resource}: {e}")
                self.cleanup()
                raise
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Release resources."""
        self.cleanup()
        if exc_type:
            print(f"Exception in context: {exc_type.__name__}: {exc_val}")
        return False  # Don't suppress exceptions
    
    def cleanup(self):
        """Clean up acquired resources."""
        for resource in reversed(self.acquired_resources):
            try:
                print(f"Releasing resource: {resource}")
                del self.state[resource]
            except Exception as e:
                print(f"Error releasing {resource}: {e}")
        self.acquired_resources.clear()
    
    def use_resource(self, resource: str) -> str:
        """Use a specific resource."""
        if resource not in self.acquired_resources:
            raise ValueError(f"Resource {resource} not acquired")
        return f"Using {resource}: {self.state[resource]}"

# Complex exception handling with nested contexts
def complex_error_handling():
    """Demonstrate complex error handling patterns."""
    
    class CustomError(Exception):
        def __init__(self, message: str, error_code: int, context: Dict[str, Any] = None):
            super().__init__(message)
            self.error_code = error_code
            self.context = context or {}
    
    def risky_operation(level: int) -> str:
        """Operation that can fail at different levels."""
        if level < 0:
            raise CustomError("Negative level", 1001, {"level": level})
        elif level == 0:
            raise ValueError("Zero level not allowed")
        elif level > 10:
            raise CustomError("Level too high", 1002, {"level": level, "max": 10})
        
        return f"Operation successful at level {level}"
    
    def nested_operation(levels: List[int]) -> List[str]:
        """Nested operation with error handling."""
        results = []
        
        for i, level in enumerate(levels):
            try:
                with ComplexContextManager([f"resource_{i}"]):
                    result = risky_operation(level)
                    results.append(result)
            except CustomError as e:
                print(f"Custom error at level {level}: {e} (code: {e.error_code})")
                results.append(f"Error: {e.error_code}")
            except ValueError as e:
                print(f"Value error at level {level}: {e}")
                results.append("Value error")
            except Exception as e:
                print(f"Unexpected error at level {level}: {e}")
                results.append("Unexpected error")
        
        return results
    
    return nested_operation

# Complex generic types
T = TypeVar('T')
K = TypeVar('K')
V = TypeVar('V')

class ComplexGeneric(Generic[T, K, V]):
    """Complex generic class with multiple type parameters."""
    
    def __init__(self):
        self.data: Dict[K, List[T]] = {}
        self.metadata: Dict[K, V] = {}
        self.processors: List[Callable[[T], T]] = []
    
    def add_item(self, key: K, item: T, metadata: V = None) -> None:
        """Add item with key and metadata."""
        if key not in self.data:
            self.data[key] = []
        self.data[key].append(item)
        if metadata is not None:
            self.metadata[key] = metadata
    
    def process_items(self, key: K) -> List[T]:
        """Process items for a given key."""
        if key not in self.data:
            return []
        
        items = self.data[key]
        for processor in self.processors:
            items = [processor(item) for item in items]
        return items
    
    def get_metadata(self, key: K) -> Optional[V]:
        """Get metadata for a key."""
        return self.metadata.get(key)
    
    def add_processor(self, processor: Callable[[T], T]) -> None:
        """Add a processor function."""
        self.processors.append(processor)

# Complex nested function definitions
def create_nested_functions():
    """Create complex nested function definitions."""
    
    def outer_function(x: int):
        """Outer function."""
        outer_var = x * 2
        
        def middle_function(y: int):
            """Middle function."""
            middle_var = y + outer_var
            
            def inner_function(z: int):
                """Inner function."""
                return z + middle_var + outer_var
            
            return inner_function
        
        return middle_function
    
    def create_closure_chain(n: int):
        """Create a chain of closures."""
        def closure_0(x):
            return x + n
        
        def closure_1(x):
            return closure_0(x) * 2
        
        def closure_2(x):
            return closure_1(x) ** 2
        
        return closure_2
    
    return outer_function, create_closure_chain

# Complex data validation
def complex_validation():
    """Complex data validation with nested rules."""
    
    class ValidationError(Exception):
        def __init__(self, field: str, message: str, value: Any = None):
            super().__init__(message)
            self.field = field
            self.value = value
    
    def validate_person(data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate person data with complex rules."""
        errors = []
        
        # Name validation
        if 'name' not in data:
            errors.append(ValidationError('name', 'Name is required'))
        elif not isinstance(data['name'], str):
            errors.append(ValidationError('name', 'Name must be string', data['name']))
        elif len(data['name']) < 2:
            errors.append(ValidationError('name', 'Name too short', data['name']))
        
        # Age validation
        if 'age' not in data:
            errors.append(ValidationError('age', 'Age is required'))
        elif not isinstance(data['age'], int):
            errors.append(ValidationError('age', 'Age must be integer', data['age']))
        elif data['age'] < 0 or data['age'] > 150:
            errors.append(ValidationError('age', 'Age out of range', data['age']))
        
        # Email validation
        if 'email' in data:
            email = data['email']
            if not isinstance(email, str):
                errors.append(ValidationError('email', 'Email must be string', email))
            elif '@' not in email:
                errors.append(ValidationError('email', 'Invalid email format', email))
        
        # Address validation
        if 'address' in data:
            address = data['address']
            if not isinstance(address, dict):
                errors.append(ValidationError('address', 'Address must be object', address))
            else:
                required_fields = ['street', 'city', 'country']
                for field in required_fields:
                    if field not in address:
                        errors.append(ValidationError(f'address.{field}', f'{field} is required'))
                    elif not isinstance(address[field], str):
                        errors.append(ValidationError(f'address.{field}', f'{field} must be string', address[field]))
        
        if errors:
            raise ValidationError('validation', f'Validation failed with {len(errors)} errors', errors)
        
        return data
    
    return validate_person

if __name__ == "__main__":
    # Example usage
    print("=== Complex Tree Structure ===")
    root = Node("root", metadata={"type": "root"})
    child1 = Node("child1", metadata={"type": "child"})
    child2 = Node("child2", metadata={"type": "child"})
    grandchild = Node("grandchild", metadata={"type": "grandchild"})
    
    root.add_child(child1)
    root.add_child(child2)
    child1.add_child(grandchild)
    
    descendants = root.find_descendants(lambda x: "child" in x)
    print(f"Descendants: {[d.value for d in descendants]}")
    
    path = grandchild.get_path_to_root()
    print(f"Path to root: {[n.value for n in path]}")
    
    print("\n=== Complex Graph ===")
    graph = Graph()
    for i in range(5):
        graph.add_node(f"node_{i}", f"data_{i}")
    
    graph.add_edge("node_0", "node_1", 1.0, "direct")
    graph.add_edge("node_1", "node_2", 2.0, "indirect")
    graph.add_edge("node_0", "node_3", 1.5, "direct")
    graph.add_edge("node_3", "node_4", 0.5, "direct")
    
    path = graph.find_shortest_path("node_0", "node_4")
    print(f"Shortest path: {path}")
    
    print("\n=== Complex Inheritance ===")
    bat = FlyingMammal("Bat", "Chiroptera")
    print(bat.move())
    print(bat.fly())
    print(bat.hunt_at_night())
    print(bat.regulate_temperature())
    
    print("\n=== Complex Algorithm ===")
    data = [
        {"name": "Alice", "age": 25, "score": 85},
        {"name": "Bob", "age": 30, "score": 92},
        {"name": "Charlie", "age": 35, "score": 78}
    ]
    
    filters = [lambda x: x["age"] >= 25, lambda x: x["score"] >= 80]
    transformers = [lambda x: {**x, "grade": "A" if x["score"] >= 90 else "B"}]
    aggregators = [lambda x: sum(item["score"] for item in x) / len(x)]
    
    result = complex_algorithm(data, filters, transformers, aggregators)
    print(f"Algorithm result: {result}")
    
    print("\n=== Complex Decorator ===")
    @complex_decorator({"initial": "state"})
    def test_function(x, y):
        return x + y
    
    test_function.update_state({"pre_hook": lambda args, kwargs: print(f"Pre: {args}, {kwargs}")})
    test_function.update_state({"post_hook": lambda result: print(f"Post: {result}")})
    
    result = test_function(5, 3)
    print(f"Decorated function result: {result}")
    print(f"State: {test_function.get_state()}")
    
    print("\n=== Complex Context Manager ===")
    with ComplexContextManager(["resource1", "resource2"]) as cm:
        print(cm.use_resource("resource1"))
        print(cm.use_resource("resource2"))
    
    print("\n=== Complex Error Handling ===")
    error_handler = complex_error_handling()
    results = error_handler([1, 0, 5, 15, -1])
    print(f"Error handling results: {results}")
    
    print("\n=== Complex Generic ===")
    generic = ComplexGeneric[str, str, int]()
    generic.add_item("key1", "value1", 100)
    generic.add_item("key1", "value2", 200)
    generic.add_processor(lambda x: x.upper())
    
    processed = generic.process_items("key1")
    metadata = generic.get_metadata("key1")
    print(f"Processed: {processed}")
    print(f"Metadata: {metadata}")
    
    print("\n=== Nested Functions ===")
    outer_func, closure_chain = create_nested_functions()
    nested_func = outer_func(10)(20)
    result = nested_func(5)
    print(f"Nested function result: {result}")
    
    closure = closure_chain(3)
    closure_result = closure(2)
    print(f"Closure chain result: {closure_result}")
    
    print("\n=== Complex Validation ===")
    validator = complex_validation()
    
    valid_data = {
        "name": "John Doe",
        "age": 30,
        "email": "john@example.com",
        "address": {
            "street": "123 Main St",
            "city": "Anytown",
            "country": "USA"
        }
    }
    
    try:
        validated = validator(valid_data)
        print(f"Valid data: {validated}")
    except ValidationError as e:
        print(f"Validation error: {e}")
    
    invalid_data = {
        "name": "A",  # Too short
        "age": "thirty",  # Wrong type
        "email": "invalid-email"  # Invalid format
    }
    
    try:
        validator(invalid_data)
    except ValidationError as e:
        print(f"Validation failed: {e}")
