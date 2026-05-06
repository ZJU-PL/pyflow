"""
PyTorch Hub and Package Contracts - torch.hub and torch.package

This module provides contracts for PyTorch model hub and packaging:
- torch.hub (pretrained model loading)
- torch.package (model packaging and serialization)

Device Barrier Considerations:
- Hub models can be loaded to specific devices via map_location
- Package handles device placement for serialized models
"""

from typing import Dict, List, Any, Optional
from ..intervals import Interval
from ..contracts import (
    ContractRegistry,
    FunctionContract,
    MethodContract,
    ModuleContract,
)


# ============================================================================
# torch.hub - Model Hub
# ============================================================================

def _register_hub(registry: ContractRegistry) -> None:
    """Register torch.hub contracts."""
    
    # torch.hub.load
    registry.register(FunctionContract(
        name="torch.hub.load",
        qualname="torch.hub.load",
        param_names=["repo_or_dir", "model", "*args", "source", "trust_repo",
                    "force_reload", "verbose", "skip_validation", "**kwargs"],
        param_intervals={},
        return_interval=None,  # Returns model
        preconditions=[
            ("valid_repo", "repo_or_dir must be valid GitHub repo or local path"),
            ("model_exists", "model must exist in repo"),
        ],
        postconditions=[
            ("model_loaded", "Model loaded from hub"),
        ],
        requires_same_device=False,  # Device handled by model
        may_raise=["RuntimeError", "ValueError", "HTTPError"],
        docstring="Load a model from PyTorch Hub",
    ))
    
    # torch.hub.load_state_dict_from_url
    registry.register(FunctionContract(
        name="torch.hub.load_state_dict_from_url",
        qualname="torch.hub.load_state_dict_from_url",
        param_names=["url", "model_dir", "map_location", "progress", "check_hash",
                    "file_name", "weights_only"],
        param_intervals={},
        return_interval=None,  # Returns state dict
        preconditions=[
            ("valid_url", "URL must be accessible"),
        ],
        postconditions=[
            ("state_dict_loaded", "State dict loaded from URL"),
            ("mapped_to_device", "Tensors on specified map_location device"),
        ],
        requires_same_device=False,  # map_location handles device
        may_raise=["RuntimeError", "HTTPError"],
        docstring="Download and load state dict from URL",
    ))
    
    # torch.hub.download_url_to_file
    registry.register(FunctionContract(
        name="torch.hub.download_url_to_file",
        qualname="torch.hub.download_url_to_file",
        param_names=["url", "dst", "hash_prefix", "progress"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_url", "URL must be accessible"),
            ("writable_dst", "Destination must be writable"),
        ],
        postconditions=[
            ("file_downloaded", "File downloaded to destination"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError", "IOError", "HTTPError"],
        docstring="Download file from URL",
    ))
    
    # torch.hub.list
    registry.register(FunctionContract(
        name="torch.hub.list",
        qualname="torch.hub.list",
        param_names=["github", "force_reload", "skip_validation", "trust_repo"],
        param_intervals={},
        return_interval=None,  # Returns list of model names
        preconditions=[
            ("valid_repo", "github must be valid repo string"),
        ],
        postconditions=[
            ("models_listed", "Returns list of available models"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError", "HTTPError"],
        docstring="List available models in a hub repo",
    ))
    
    # torch.hub.help
    registry.register(FunctionContract(
        name="torch.hub.help",
        qualname="torch.hub.help",
        param_names=["github", "model", "force_reload", "skip_validation", "trust_repo"],
        param_intervals={},
        return_interval=None,  # Returns docstring
        preconditions=[
            ("valid_repo", "github must be valid repo string"),
            ("model_exists", "model must exist in repo"),
        ],
        postconditions=[
            ("help_returned", "Returns model docstring"),
        ],
        requires_same_device=False,
        may_raise=["RuntimeError"],
        docstring="Get help for a hub model",
    ))
    
    # torch.hub.get_dir
    registry.register(FunctionContract(
        name="torch.hub.get_dir",
        qualname="torch.hub.get_dir",
        param_names=[],
        param_intervals={},
        return_interval=None,  # Returns path string
        preconditions=[],
        postconditions=[
            ("dir_returned", "Returns hub cache directory"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get hub cache directory",
    ))
    
    # torch.hub.set_dir
    registry.register(FunctionContract(
        name="torch.hub.set_dir",
        qualname="torch.hub.set_dir",
        param_names=["d"],
        param_intervals={},
        return_interval=None,
        preconditions=[
            ("valid_path", "d must be valid directory path"),
        ],
        postconditions=[
            ("dir_set", "Hub cache directory updated"),
        ],
        requires_same_device=False,
        may_raise=["IOError"],
        docstring="Set hub cache directory",
    ))


# ============================================================================
# torch.package - Model Packaging
# ============================================================================

def _register_package(registry: ContractRegistry) -> None:
    """Register torch.package contracts."""
    
    # torch.package.PackageExporter
    registry.register(ModuleContract(
        name="torch.package.PackageExporter",
        qualname="torch.package.PackageExporter",
        init_param_names=["f", "importer"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("file_open", "Package file is open for writing"),
        ],
        docstring="Package exporter for saving models and code",
    ))
    
    # PackageExporter.intern
    registry.register(MethodContract(
        name="torch.package.PackageExporter.intern",
        qualname="torch.package.PackageExporter.intern",
        param_names=["self", "include", "exclude", "allow_empty"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("modules_interned", "Specified modules will be included in package"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Specify modules to include in package",
    ))
    
    # PackageExporter.extern
    registry.register(MethodContract(
        name="torch.package.PackageExporter.extern",
        qualname="torch.package.PackageExporter.extern",
        param_names=["self", "include", "exclude", "allow_empty"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("modules_externed", "Specified modules expected externally"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Specify modules expected to exist externally",
    ))
    
    # PackageExporter.mock
    registry.register(MethodContract(
        name="torch.package.PackageExporter.mock",
        qualname="torch.package.PackageExporter.mock",
        param_names=["self", "include", "exclude", "allow_empty"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("modules_mocked", "Specified modules replaced with mocks"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Replace modules with mocks in package",
    ))
    
    # PackageExporter.deny
    registry.register(MethodContract(
        name="torch.package.PackageExporter.deny",
        qualname="torch.package.PackageExporter.deny",
        param_names=["self", "include", "exclude"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("modules_denied", "Specified modules will cause error if referenced"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Deny specified modules (error if referenced)",
    ))
    
    # PackageExporter.save_pickle
    registry.register(MethodContract(
        name="torch.package.PackageExporter.save_pickle",
        qualname="torch.package.PackageExporter.save_pickle",
        param_names=["self", "package", "resource", "obj", "dependencies"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("pickle_saved", "Object pickled to package"),
        ],
        requires_same_device=False,
        may_raise=["PicklingError"],
        docstring="Save object as pickle in package",
    ))
    
    # PackageExporter.save_module
    registry.register(MethodContract(
        name="torch.package.PackageExporter.save_module",
        qualname="torch.package.PackageExporter.save_module",
        param_names=["self", "module_name", "dependencies"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("module_saved", "Module source saved to package"),
        ],
        requires_same_device=False,
        may_raise=["ImportError"],
        docstring="Save module source to package",
    ))
    
    # PackageExporter.save_text
    registry.register(MethodContract(
        name="torch.package.PackageExporter.save_text",
        qualname="torch.package.PackageExporter.save_text",
        param_names=["self", "package", "resource", "text"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("text_saved", "Text saved to package"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Save text file to package",
    ))
    
    # PackageExporter.save_binary
    registry.register(MethodContract(
        name="torch.package.PackageExporter.save_binary",
        qualname="torch.package.PackageExporter.save_binary",
        param_names=["self", "package", "resource", "binary"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("binary_saved", "Binary data saved to package"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Save binary file to package",
    ))
    
    # PackageExporter.close
    registry.register(MethodContract(
        name="torch.package.PackageExporter.close",
        qualname="torch.package.PackageExporter.close",
        param_names=["self"],
        param_intervals={},
        return_interval=None,
        preconditions=[],
        postconditions=[
            ("closed", "Package file closed and written"),
        ],
        requires_same_device=False,
        may_raise=["IOError"],
        docstring="Close and finalize package",
    ))
    
    # torch.package.PackageImporter
    registry.register(ModuleContract(
        name="torch.package.PackageImporter",
        qualname="torch.package.PackageImporter",
        init_param_names=["file_or_buffer", "module_allowed"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[
            ("file_open", "Package file is open for reading"),
        ],
        docstring="Package importer for loading packaged models",
    ))
    
    # PackageImporter.import_module
    registry.register(MethodContract(
        name="torch.package.PackageImporter.import_module",
        qualname="torch.package.PackageImporter.import_module",
        param_names=["self", "name", "package"],
        param_intervals={},
        return_interval=None,  # Returns module
        preconditions=[
            ("module_in_package", "Module must exist in package"),
        ],
        postconditions=[
            ("module_imported", "Module loaded from package"),
        ],
        requires_same_device=False,
        may_raise=["ImportError"],
        docstring="Import module from package",
    ))
    
    # PackageImporter.load_pickle
    registry.register(MethodContract(
        name="torch.package.PackageImporter.load_pickle",
        qualname="torch.package.PackageImporter.load_pickle",
        param_names=["self", "package", "resource", "map_location"],
        param_intervals={},
        return_interval=None,  # Returns unpickled object
        preconditions=[
            ("resource_exists", "Resource must exist in package"),
        ],
        postconditions=[
            ("pickle_loaded", "Object unpickled from package"),
            ("device_mapped", "Tensors mapped to specified device"),
        ],
        requires_same_device=False,  # map_location handles device
        may_raise=["UnpicklingError"],
        docstring="Load pickled object from package",
    ))
    
    # PackageImporter.load_text
    registry.register(MethodContract(
        name="torch.package.PackageImporter.load_text",
        qualname="torch.package.PackageImporter.load_text",
        param_names=["self", "package", "resource", "encoding"],
        param_intervals={},
        return_interval=None,  # Returns string
        preconditions=[
            ("resource_exists", "Resource must exist in package"),
        ],
        postconditions=[
            ("text_loaded", "Text loaded from package"),
        ],
        requires_same_device=False,
        may_raise=["IOError"],
        docstring="Load text from package",
    ))
    
    # PackageImporter.load_binary
    registry.register(MethodContract(
        name="torch.package.PackageImporter.load_binary",
        qualname="torch.package.PackageImporter.load_binary",
        param_names=["self", "package", "resource"],
        param_intervals={},
        return_interval=None,  # Returns bytes
        preconditions=[
            ("resource_exists", "Resource must exist in package"),
        ],
        postconditions=[
            ("binary_loaded", "Binary data loaded from package"),
        ],
        requires_same_device=False,
        may_raise=["IOError"],
        docstring="Load binary data from package",
    ))
    
    # PackageImporter.id
    registry.register(MethodContract(
        name="torch.package.PackageImporter.id",
        qualname="torch.package.PackageImporter.id",
        param_names=["self"],
        param_intervals={},
        return_interval=None,  # Returns string
        preconditions=[],
        postconditions=[
            ("id_returned", "Returns unique package identifier"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get unique package identifier",
    ))
    
    # PackageImporter.file_structure
    registry.register(MethodContract(
        name="torch.package.PackageImporter.file_structure",
        qualname="torch.package.PackageImporter.file_structure",
        param_names=["self", "include", "exclude"],
        param_intervals={},
        return_interval=None,  # Returns Directory
        preconditions=[],
        postconditions=[
            ("structure_returned", "Returns package file structure"),
        ],
        requires_same_device=False,
        may_raise=[],
        docstring="Get package file structure",
    ))


# ============================================================================
# torch.package Actions
# ============================================================================

def _register_package_actions(registry: ContractRegistry) -> None:
    """Register package action contracts."""
    
    # Action base classes (conceptual contracts)
    registry.register(ModuleContract(
        name="torch.package.Action",
        qualname="torch.package.Action",
        init_param_names=[],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[],
        docstring="Base class for package dependency actions",
    ))
    
    registry.register(ModuleContract(
        name="torch.package.Intern",
        qualname="torch.package.Intern",
        init_param_names=["include", "exclude", "allow_empty"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[],
        docstring="Action to intern modules",
    ))
    
    registry.register(ModuleContract(
        name="torch.package.Extern",
        qualname="torch.package.Extern",
        init_param_names=["include", "exclude", "allow_empty"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[],
        docstring="Action to extern modules",
    ))
    
    registry.register(ModuleContract(
        name="torch.package.Mock",
        qualname="torch.package.Mock",
        init_param_names=["include", "exclude", "allow_empty"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[],
        docstring="Action to mock modules",
    ))
    
    registry.register(ModuleContract(
        name="torch.package.Deny",
        qualname="torch.package.Deny",
        init_param_names=["include", "exclude"],
        init_param_intervals={},
        forward_return_interval=None,
        forward_requires_same_device=False,
        forward_preserves_device=False,
        state_invariants=[],
        docstring="Action to deny modules",
    ))


# ============================================================================
# Registration Entry Point
# ============================================================================

def register_hub_package_contracts(registry: ContractRegistry) -> None:
    """
    Register all torch.hub and torch.package contracts.
    
    Args:
        registry: The contract registry to register with
    """
    _register_hub(registry)
    _register_package(registry)
    _register_package_actions(registry)


# Export
__all__ = [
    "register_hub_package_contracts",
]
