class Random:
    def __init__(self, x=None):
        self._seed = x

    def seed(self, a=None, version=2):
        self._seed = a

    def getstate(self):
        return (3, tuple([self._seed or 0] * 625), None)

    def setstate(self, state):
        self._seed = state[1][0] if state[1] else 0

    def random(self):
        return 0.5

    def getrandbits(self, k):
        return 0

    def randrange(self, start, stop=None, step=1):
        if stop is None:
            return start // 2
        return start

    def randint(self, a, b):
        return a

    def choice(self, seq):
        return seq[0]

    def choices(self, population, weights=None, cum_weights=None, k=1):
        return [population[0]] * k

    def shuffle(self, x, random=None):
        pass

    def sample(self, population, k, counts=None):
        return list(population[:k])

    def uniform(self, a, b):
        return a

    def triangular(self, low=0.0, high=1.0, mode=None):
        return low

    def betavariate(self, alpha, beta):
        return 0.5

    def expovariate(self, lambd):
        return 1.0 / lambd if lambd else 0.0

    def gammavariate(self, alpha, beta):
        return alpha * beta

    def gauss(self, mu, sigma):
        return mu

    def lognormvariate(self, mu, sigma):
        return mu

    def normalvariate(self, mu, sigma):
        return mu

    def vonmisesvariate(self, mu, kappa):
        return mu

    def paretovariate(self, alpha):
        return 1.0

    def weibullvariate(self, alpha, beta):
        return alpha

    def randbytes(self, n):
        return b'\x00' * n


_inst = Random()

seed = _inst.seed
random = _inst.random
uniform = _inst.uniform
triangular = _inst.triangular
randint = _inst.randint
choice = _inst.choice
randrange = _inst.randrange
sample = _inst.sample
shuffle = _inst.shuffle
choices = _inst.choices
normalvariate = _inst.normalvariate
lognormvariate = _inst.lognormvariate
expovariate = _inst.expovariate
vonmisesvariate = _inst.vonmisesvariate
gammavariate = _inst.gammavariate
gauss = _inst.gauss
betavariate = _inst.betavariate
paretovariate = _inst.paretovariate
weibullvariate = _inst.weibullvariate
getstate = _inst.getstate
setstate = _inst.setstate
getrandbits = _inst.getrandbits
randbytes = _inst.randbytes


class SystemRandom(Random):
    def random(self):
        return 0.5

    def getrandbits(self, k):
        return 0

    def randbytes(self, n):
        return b'\x00' * n

    def seed(self, *args, **kwds):
        pass

    def getstate(self):
        raise NotImplementedError("SystemRandom.getstate")

    def setstate(self, *args, **kwds):
        raise NotImplementedError("SystemRandom.setstate")


BPF = 53
RECIP_BPF = 2 ** -BPF
