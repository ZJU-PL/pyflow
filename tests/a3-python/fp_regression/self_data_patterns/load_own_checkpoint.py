"""
FP Regression Test: Loading self-saved pickle data.

When a program saves data with pickle.dump() and later loads it with
pickle.load(), this is the user loading their OWN data. This should
NOT be flagged as PICKLE_INJECTION (or should be LOW confidence).

Expected: NO FINDINGS or LOW confidence
"""
import pickle
import tempfile
from pathlib import Path


class ModelCheckpoint:
    """Example ML checkpoint class."""
    
    def __init__(self, weights, config):
        self.weights = weights
        self.config = config


def save_and_load_checkpoint():
    """Save and load own checkpoint - should NOT flag."""
    
    # Create checkpoint
    checkpoint = ModelCheckpoint(
        weights=[0.1, 0.2, 0.3],
        config={"learning_rate": 0.01}
    )
    
    # Save to temp file
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.pkl', delete=False) as f:
        pickle.dump(checkpoint, f)  # User saves
        filepath = f.name
    
    # Load same checkpoint
    with open(filepath, 'rb') as f:
        loaded = pickle.load(f)  # User loads own data - should NOT flag
    
    return loaded


def load_own_trained_model():
    """Load a model trained by the same codebase."""
    
    model_path = Path("models/my_trained_model.pkl")
    
    if model_path.exists():
        with open(model_path, 'rb') as f:
            # This is loading OUR OWN trained model
            # NOT downloading from untrusted source
            model = pickle.load(f)  # Should NOT flag (or LOW)
        return model
    
    return None


def save_cache_load_cache():
    """Cache pattern: save results, load them later."""
    
    cache_dir = Path(".cache")
    cache_file = cache_dir / "computed_results.pkl"
    
    # First run: compute and save
    results = {"key": "value", "number": 42}
    
    cache_dir.mkdir(exist_ok=True)
    with open(cache_file, 'wb') as f:
        pickle.dump(results, f)
    
    # Later: load from cache
    with open(cache_file, 'rb') as f:
        cached = pickle.load(f)  # Loading OWN cache - should NOT flag
    
    return cached


# CONTRAST: These patterns SHOULD be flagged
def load_from_url_for_comparison():
    """Loading pickle from URL - SHOULD flag (but not testing here)."""
    # import requests
    # response = requests.get("http://example.com/model.pkl")
    # model = pickle.loads(response.content)  # SHOULD flag
    pass


def load_user_uploaded_for_comparison():
    """Loading user-uploaded pickle - SHOULD flag (but not testing here)."""
    # from flask import request
    # file = request.files['model']
    # model = pickle.load(file)  # SHOULD flag
    pass


if __name__ == "__main__":
    checkpoint = save_and_load_checkpoint()
    print(f"Loaded checkpoint: {checkpoint.config}")
