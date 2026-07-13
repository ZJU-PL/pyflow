"""
Structured logging for AI analysis.

This module provides structured logging capabilities for AI analysis events and state changes,
with support for JSON and CSV output formats for easy post-processing.
"""

import json
import csv
import time
import logging
from typing import Dict, Any, List, Optional, Union, TextIO
from pathlib import Path
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum


class LogLevel(Enum):
    """Log levels for AI analysis events."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class EventType(Enum):
    """Types of AI analysis events."""
    ANALYSIS_START = "analysis_start"
    ANALYSIS_END = "analysis_end"
    ITERATION_START = "iteration_start"
    ITERATION_END = "iteration_end"
    FIXPOINT_REACHED = "fixpoint_reached"
    WIDENING_APPLIED = "widening_applied"
    STATE_CHANGE = "state_change"
    TRANSFER_FUNCTION = "transfer_function"
    JOIN_OPERATION = "join_operation"
    ERROR_EVENT = "error_event"
    PERFORMANCE_METRIC = "performance_metric"


@dataclass
class LogEvent:
    """Structured log event for AI analysis."""
    timestamp: float
    event_type: EventType
    level: LogLevel
    scope: Optional[str] = None
    iteration: Optional[int] = None
    message: str = ""
    data: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = asdict(self)
        result['event_type'] = self.event_type.value
        result['level'] = self.level.value
        result['datetime'] = datetime.fromtimestamp(self.timestamp).isoformat()
        return result


class AILogger:
    """
    Structured logger for AI analysis with multiple output formats.
    
    Provides methods for logging events, state changes, and performance metrics
    with support for JSON and CSV output.
    """
    
    def __init__(self, 
                 name: str = "ai_analysis",
                 min_level: LogLevel = LogLevel.INFO,
                 enable_console: bool = True,
                 enable_json: bool = False,
                 enable_csv: bool = False,
                 json_file: Optional[Union[str, Path]] = None,
                 csv_file: Optional[Union[str, Path]] = None):
        """
        Initialize AI logger.
        
        Args:
            name: Logger name
            min_level: Minimum log level to record
            enable_console: Whether to output to console
            enable_json: Whether to enable JSON logging
            enable_csv: Whether to enable CSV logging
            json_file: Path to JSON log file
            csv_file: Path to CSV log file
        """
        self.name = name
        self.min_level = min_level
        self.enable_console = enable_console
        self.enable_json = enable_json
        self.enable_csv = enable_csv
        
        self.events: List[LogEvent] = []
        self.start_time = time.time()
        
        # Set up console logger
        if self.enable_console:
            self.console_logger = logging.getLogger(f"{name}_console")
            self.console_logger.setLevel(logging.DEBUG)
            
            if not self.console_logger.handlers:
                handler = logging.StreamHandler()
                formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
                handler.setFormatter(formatter)
                self.console_logger.addHandler(handler)
        
        # Set up file outputs
        self.json_file = Path(json_file) if json_file else None
        self.csv_file = Path(csv_file) if csv_file else None
        
        # CSV writer state
        self.csv_writer = None
        self.csv_file_handle = None
        
        # Initialize CSV file with headers if needed
        if self.enable_csv and self.csv_file:
            self._init_csv_file()
    
    def _init_csv_file(self):
        """Initialize CSV file with headers."""
        if self.csv_file:
            self.csv_file.parent.mkdir(parents=True, exist_ok=True)
            self.csv_file_handle = open(self.csv_file, 'w', newline='')
            self.csv_writer = csv.DictWriter(
                self.csv_file_handle,
                fieldnames=['timestamp', 'datetime', 'event_type', 'level', 
                           'scope', 'iteration', 'message', 'data']
            )
            self.csv_writer.writeheader()
    
    def _should_log(self, level: LogLevel) -> bool:
        """Check if event should be logged based on minimum level."""
        level_order = {
            LogLevel.DEBUG: 0,
            LogLevel.INFO: 1, 
            LogLevel.WARNING: 2,
            LogLevel.ERROR: 3
        }
        return level_order[level] >= level_order[self.min_level]
    
    def _log_event(self, event: LogEvent):
        """Internal method to log an event."""
        if not self._should_log(event.level):
            return
        
        # Store event
        self.events.append(event)
        
        # Console output
        if self.enable_console:
            log_func = getattr(self.console_logger, event.level.value.lower())
            scope_info = f"[{event.scope}]" if event.scope else ""
            iter_info = f"(iter {event.iteration})" if event.iteration is not None else ""
            message = f"{scope_info}{iter_info} {event.message}"
            
            if event.data:
                message += f" | Data: {json.dumps(event.data, default=str)}"
            
            log_func(message)
        
        # JSON output
        if self.enable_json and self.json_file:
            self._write_json_event(event)
        
        # CSV output
        if self.enable_csv and self.csv_writer:
            self._write_csv_event(event)
    
    def _write_json_event(self, event: LogEvent):
        """Write event to JSON file."""
        self.json_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Append to JSON file (one JSON object per line)
        with open(self.json_file, 'a') as f:
            json.dump(event.to_dict(), f, default=str)
            f.write('\n')
    
    def _write_csv_event(self, event: LogEvent):
        """Write event to CSV file."""
        if self.csv_writer:
            event_dict = event.to_dict()
            # Convert data dict to JSON string for CSV
            if event_dict['data']:
                event_dict['data'] = json.dumps(event_dict['data'], default=str)
            self.csv_writer.writerow(event_dict)
            self.csv_file_handle.flush()
    
    def log(self, 
            event_type: EventType,
            level: LogLevel = LogLevel.INFO,
            message: str = "",
            scope: Optional[str] = None,
            iteration: Optional[int] = None,
            **data):
        """
        Log an event.
        
        Args:
            event_type: Type of event
            level: Log level
            message: Human-readable message
            scope: Analysis scope (e.g., function name)
            iteration: Analysis iteration number
            **data: Additional structured data
        """
        event = LogEvent(
            timestamp=time.time(),
            event_type=event_type,
            level=level,
            scope=scope,
            iteration=iteration,
            message=message,
            data=data if data else None
        )
        self._log_event(event)
    
    def analysis_start(self, scope: str, **data):
        """Log analysis start event."""
        self.log(EventType.ANALYSIS_START, LogLevel.INFO, 
                f"Starting analysis for scope: {scope}", scope=scope, **data)
    
    def analysis_end(self, scope: str, success: bool = True, **data):
        """Log analysis end event."""
        status = "successfully" if success else "with errors"
        self.log(EventType.ANALYSIS_END, LogLevel.INFO, 
                f"Analysis completed {status} for scope: {scope}", scope=scope, 
                success=success, **data)
    
    def iteration_start(self, scope: str, iteration: int, **data):
        """Log iteration start event."""
        self.log(EventType.ITERATION_START, LogLevel.DEBUG,
                f"Starting iteration {iteration}", scope=scope, iteration=iteration, **data)
    
    def iteration_end(self, scope: str, iteration: int, converged: bool = False, **data):
        """Log iteration end event."""
        status = "converged" if converged else "continuing"
        self.log(EventType.ITERATION_END, LogLevel.DEBUG,
                f"Iteration {iteration} completed ({status})", 
                scope=scope, iteration=iteration, converged=converged, **data)
    
    def fixpoint_reached(self, scope: str, iteration: int, **data):
        """Log fixpoint reached event."""
        self.log(EventType.FIXPOINT_REACHED, LogLevel.INFO,
                f"Fixpoint reached after {iteration} iterations", 
                scope=scope, iteration=iteration, **data)
    
    def widening_applied(self, scope: str, iteration: int, location: str, **data):
        """Log widening application event."""
        self.log(EventType.WIDENING_APPLIED, LogLevel.INFO,
                f"Widening applied at {location}", 
                scope=scope, iteration=iteration, location=location, **data)
    
    def state_change(self, scope: str, iteration: int, variable: str, 
                    old_value: Any, new_value: Any, **data):
        """Log state change event."""
        self.log(EventType.STATE_CHANGE, LogLevel.DEBUG,
                f"Variable {variable} changed", 
                scope=scope, iteration=iteration, variable=variable,
                old_value=str(old_value), new_value=str(new_value), **data)
    
    def transfer_function(self, scope: str, iteration: int, stmt_type: str, 
                         stmt_repr: str, **data):
        """Log transfer function application."""
        self.log(EventType.TRANSFER_FUNCTION, LogLevel.DEBUG,
                f"Transfer function for {stmt_type}: {stmt_repr}",
                scope=scope, iteration=iteration, stmt_type=stmt_type, 
                stmt_repr=stmt_repr, **data)
    
    def join_operation(self, scope: str, iteration: int, location: str, 
                      num_states: int, **data):
        """Log join operation."""
        self.log(EventType.JOIN_OPERATION, LogLevel.DEBUG,
                f"Join operation at {location} with {num_states} states",
                scope=scope, iteration=iteration, location=location, 
                num_states=num_states, **data)
    
    def error(self, scope: str, error_type: str, message: str, 
             iteration: Optional[int] = None, **data):
        """Log error event."""
        self.log(EventType.ERROR_EVENT, LogLevel.ERROR,
                f"{error_type}: {message}", scope=scope, iteration=iteration,
                error_type=error_type, **data)
    
    def performance_metric(self, scope: str, metric_name: str, value: float, 
                          iteration: Optional[int] = None, **data):
        """Log performance metric."""
        self.log(EventType.PERFORMANCE_METRIC, LogLevel.INFO,
                f"{metric_name}: {value}", scope=scope, iteration=iteration,
                metric_name=metric_name, value=value, **data)
    
    def get_events(self, 
                  event_type: Optional[EventType] = None,
                  scope: Optional[str] = None,
                  level: Optional[LogLevel] = None) -> List[LogEvent]:
        """
        Get filtered events.
        
        Args:
            event_type: Filter by event type
            scope: Filter by scope
            level: Filter by log level
            
        Returns:
            List of matching events
        """
        filtered = self.events
        
        if event_type:
            filtered = [e for e in filtered if e.event_type == event_type]
        if scope:
            filtered = [e for e in filtered if e.scope == scope]
        if level:
            filtered = [e for e in filtered if e.level == level]
        
        return filtered
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics of logged events."""
        if not self.events:
            return {"total_events": 0}
        
        total_time = max(e.timestamp for e in self.events) - min(e.timestamp for e in self.events)
        
        # Count by event type
        event_counts = {}
        for event in self.events:
            event_type = event.event_type.value
            event_counts[event_type] = event_counts.get(event_type, 0) + 1
        
        # Count by scope
        scope_counts = {}
        for event in self.events:
            if event.scope:
                scope_counts[event.scope] = scope_counts.get(event.scope, 0) + 1
        
        # Get max iteration per scope
        max_iterations = {}
        for event in self.events:
            if event.scope and event.iteration is not None:
                current_max = max_iterations.get(event.scope, 0)
                max_iterations[event.scope] = max(current_max, event.iteration)
        
        return {
            "total_events": len(self.events),
            "total_time": total_time,
            "event_counts": event_counts,
            "scope_counts": scope_counts,
            "max_iterations": max_iterations,
            "scopes_analyzed": len(scope_counts),
            "errors": len(self.get_events(level=LogLevel.ERROR))
        }
    
    def export_json(self, file_path: Union[str, Path]):
        """Export all events to JSON file."""
        file_path = Path(file_path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        export_data = {
            "logger_name": self.name,
            "start_time": self.start_time,
            "summary": self.get_summary(),
            "events": [event.to_dict() for event in self.events]
        }
        
        with open(file_path, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
    
    def export_csv(self, file_path: Union[str, Path]):
        """Export all events to CSV file."""
        file_path = Path(file_path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(file_path, 'w', newline='') as f:
            writer = csv.DictWriter(
                f, fieldnames=['timestamp', 'datetime', 'event_type', 'level',
                              'scope', 'iteration', 'message', 'data']
            )
            writer.writeheader()
            
            for event in self.events:
                event_dict = event.to_dict()
                if event_dict['data']:
                    event_dict['data'] = json.dumps(event_dict['data'], default=str)
                writer.writerow(event_dict)
    
    def close(self):
        """Close file handles and clean up."""
        if self.csv_file_handle:
            self.csv_file_handle.close()
            self.csv_file_handle = None
            self.csv_writer = None
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


# Global logger instance (can be configured by applications)
_global_logger: Optional[AILogger] = None


def get_logger() -> Optional[AILogger]:
    """Get the global AI logger instance."""
    return _global_logger


def set_logger(logger: AILogger):
    """Set the global AI logger instance."""
    global _global_logger
    _global_logger = logger


def configure_logging(
    enable_console: bool = True,
    enable_json: bool = False,
    enable_csv: bool = False,
    json_file: Optional[Union[str, Path]] = None,
    csv_file: Optional[Union[str, Path]] = None,
    min_level: LogLevel = LogLevel.INFO
) -> AILogger:
    """
    Configure global AI logging.
    
    Args:
        enable_console: Whether to output to console
        enable_json: Whether to enable JSON logging
        enable_csv: Whether to enable CSV logging
        json_file: Path to JSON log file
        csv_file: Path to CSV log file
        min_level: Minimum log level
        
    Returns:
        Configured AILogger instance
    """
    logger = AILogger(
        enable_console=enable_console,
        enable_json=enable_json,
        enable_csv=enable_csv,
        json_file=json_file,
        csv_file=csv_file,
        min_level=min_level
    )
    set_logger(logger)
    return logger


# Convenience functions for common logging operations
def log_analysis_start(scope: str, **data):
    """Log analysis start event using global logger."""
    if _global_logger:
        _global_logger.analysis_start(scope, **data)


def log_analysis_end(scope: str, success: bool = True, **data):
    """Log analysis end event using global logger."""
    if _global_logger:
        _global_logger.analysis_end(scope, success, **data)


def log_iteration(scope: str, iteration: int, **data):
    """Log iteration start using global logger.""" 
    if _global_logger:
        _global_logger.iteration_start(scope, iteration, **data)


def log_fixpoint(scope: str, iteration: int, **data):
    """Log fixpoint reached using global logger."""
    if _global_logger:
        _global_logger.fixpoint_reached(scope, iteration, **data)


def log_widening(scope: str, iteration: int, location: str, **data):
    """Log widening application using global logger."""
    if _global_logger:
        _global_logger.widening_applied(scope, iteration, location, **data)


def log_error(scope: str, error_type: str, message: str, iteration: Optional[int] = None, **data):
    """Log error using global logger."""
    if _global_logger:
        _global_logger.error(scope, error_type, message, iteration, **data)
