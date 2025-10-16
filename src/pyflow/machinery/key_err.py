"""
Key error tracking for PyFlow static analysis.

This module provides functionality for tracking and reporting key errors
that occur during analysis, such as missing dictionary keys or attribute
access errors.
"""


class KeyErrors(object):
    """
    Tracks and manages key errors found during analysis.
    
    This class collects information about potential key errors (such as
    missing dictionary keys or attribute access errors) that are detected
    during static analysis of the code.
    """
    
    def __init__(self):
        """Initialize the key error tracker with an empty list."""
        self.key_errs = []  # List of key error dictionaries

    def add(self, filename, lineno, namespace, key):
        """
        Add a key error to the collection.
        
        Args:
            filename (str): The file where the error occurred.
            lineno (int): The line number where the error occurred.
            namespace (str): The namespace/scope where the error occurred.
            key (str): The key that was missing or caused the error.
        """
        self.key_errs.append({
            "filename": filename, 
            "lineno": lineno, 
            "namespace": namespace, 
            "key": key
        })

    def get(self):
        """
        Get all collected key errors.
        
        Returns:
            list: List of key error dictionaries.
        """
        return self.key_errs