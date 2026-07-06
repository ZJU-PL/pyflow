"""
FP Regression Test: joblib dump/load pattern.

joblib is commonly used in scikit-learn for model persistence.
Loading self-saved models should NOT be flagged.

Expected: NO FINDINGS or LOW confidence
"""

# Mock joblib for testing
class joblib:
    @staticmethod
    def dump(obj, filename):
        import pickle
        with open(filename, 'wb') as f:
            pickle.dump(obj, f)
    
    @staticmethod
    def load(filename):
        import pickle
        with open(filename, 'rb') as f:
            return pickle.load(f)


def train_sklearn_model():
    """Train and save a sklearn model."""
    
    # Simulated sklearn model
    class FakeModel:
        def __init__(self):
            self.coef_ = [0.1, 0.2, 0.3]
            self.intercept_ = 0.5
        
        def predict(self, X):
            return [sum(x) for x in X]
    
    model = FakeModel()
    
    # Save model
    joblib.dump(model, 'model.joblib')
    
    return model


def load_sklearn_model():
    """Load trained sklearn model - should NOT flag."""
    
    # Loading OUR OWN model
    model = joblib.load('model.joblib')  # Should NOT flag
    
    return model


def load_with_path_variable():
    """Load model from path variable - still self-data."""
    
    model_path = 'models/classifier.joblib'
    
    # Even with variable, this is loading our own model
    model = joblib.load(model_path)  # Should NOT flag (or LOW)
    
    return model


if __name__ == "__main__":
    train_sklearn_model()
    model = load_sklearn_model()
    print(f"Loaded model with coef: {model.coef_}")
