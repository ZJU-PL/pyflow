"""
FP Regression Test: torch.save/torch.load pattern.

PyTorch's torch.save() and torch.load() use pickle internally.
When loading models that the user trained themselves, this should
NOT be flagged as PICKLE_INJECTION.

Expected: NO FINDINGS or LOW confidence
"""

# Mock torch for testing without the dependency
class torch:
    @staticmethod
    def save(obj, f):
        import pickle
        pickle.dump(obj, f)
    
    @staticmethod
    def load(f, map_location=None):
        import pickle
        return pickle.load(f)


def train_and_save_model():
    """Train a model and save it - user controls the data."""
    
    # Simulated trained model
    model_state = {
        'epoch': 100,
        'state_dict': {'layer1.weight': [0.1, 0.2, 0.3]},
        'optimizer': {'lr': 0.001}
    }
    
    with open('my_model.pth', 'wb') as f:
        torch.save(model_state, f)
    
    return model_state


def load_own_model():
    """Load model that was trained by same codebase."""
    
    # Loading OUR OWN model - should NOT flag
    with open('my_model.pth', 'rb') as f:
        checkpoint = torch.load(f)  # Should NOT flag
    
    return checkpoint


def resume_training():
    """Resume training from checkpoint - common pattern."""
    
    checkpoint_path = 'checkpoints/epoch_50.pth'
    
    # Loading checkpoint to resume training
    with open(checkpoint_path, 'rb') as f:
        checkpoint = torch.load(f, map_location='cpu')  # Should NOT flag
    
    epoch = checkpoint['epoch']
    state_dict = checkpoint['state_dict']
    
    return epoch, state_dict


# CONTRAST: Downloading pre-trained models IS risky
def load_pretrained_for_comparison():
    """Loading pre-trained model from URL - would be risky.
    
    But even this is usually acceptable if from trusted source (HuggingFace, etc.)
    """
    # import requests
    # response = requests.get("https://huggingface.co/model.pth")
    # This would be flagged, but HuggingFace is generally trusted
    pass


if __name__ == "__main__":
    train_and_save_model()
    model = load_own_model()
    print(f"Loaded model: {model.keys()}")
