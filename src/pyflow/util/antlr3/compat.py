
set = set
frozenset = frozenset


try:
    reversed = reversed
except NameError:
    def reversed(l):
        l = l[:]
        l.reverse()
        return l


