"""Keras training_generator.py - fixed version (BugsInPy keras#11)."""

from collections.abc import Sequence

def is_sequence(x):
    return isinstance(x, Sequence)

def iter_sequence_infinite(data):
    while True:
        yield from data

def fit_generator(model, generator, validation_data=None, validation_steps=None, workers=0, use_multiprocessing=False):
    use_sequence_api = is_sequence(generator)
    if not use_sequence_api and use_multiprocessing and workers > 1:
        pass  # warning

    val_use_sequence_api = is_sequence(validation_data)
    val_gen = (hasattr(validation_data, 'next') or
               hasattr(validation_data, '__next__') or
               val_use_sequence_api)
    if (val_gen and not val_use_sequence_api and
            not validation_steps):
        raise ValueError('validation_steps=None is only valid for a generator based on Sequence')
