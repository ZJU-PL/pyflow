"""Keras initializers - buggy version (BugsInPy keras#1).

self.seed is used but never incremented in __call__, causing
every call to produce the same random sequence when seed is not None.
"""


class Initializer:
    pass


class RandomNormal(Initializer):
    def __init__(self, mean=0., stddev=0.05, seed=None):
        self.mean = mean
        self.stddev = stddev
        self.seed = seed

    def __call__(self, shape, dtype=None):
        return K.random_normal(shape, self.mean, self.stddev,
                               dtype=dtype, seed=self.seed)

    def get_config(self):
        return {
            'mean': self.mean,
            'stddev': self.stddev,
            'seed': self.seed,
        }


class RandomUniform(Initializer):
    def __init__(self, minval=-0.05, maxval=0.05, seed=None):
        self.minval = minval
        self.maxval = maxval
        self.seed = seed

    def __call__(self, shape, dtype=None):
        return K.random_uniform(shape, self.minval, self.maxval,
                                dtype=dtype, seed=self.seed)

    def get_config(self):
        return {
            'minval': self.minval,
            'maxval': self.maxval,
            'seed': self.seed,
        }


class TruncatedNormal(Initializer):
    def __init__(self, mean=0., stddev=0.05, seed=None):
        self.mean = mean
        self.stddev = stddev
        self.seed = seed

    def __call__(self, shape, dtype=None):
        return K.truncated_normal(shape, self.mean, self.stddev,
                                  dtype=dtype, seed=self.seed)
