from pyflow.fuzzer.corpus import Corpus
import unittest


class TestCopy(unittest.TestCase):
    def test_remove(self):
        "test if copy function works as intended in remove operation"

        res = bytearray(b"abcdefg")

        pos0 = 4
        pos1 = 5

        Corpus.copy(res, res, pos1, pos0)

        res = res[:len(res) - (pos1-pos0)]
        self.assertEqual(b"abcdfg", res)
    
    def test_insert(self):
        "test if copy function works as intended in insert operation"

        res = bytearray(b"abcdefg")
        pos = 3
        n = 5

        for k in range(n):
            res.append(0)

        Corpus.copy(res, res, pos, pos + n)

        for k in range(n):
            res[pos+k] = ord('Z')

        self.assertEqual(b"abcZZZZZdefg", res)

    def test_duplicate(self):
        "test if copy function works as intended in duplicate operation"

        res = bytearray(b"abcdefg")

        src = 4
        dst = 5
        n = 2

        tmp = bytearray(n)
        Corpus.copy(res, tmp, src, 0)
        self.assertEqual(b"ef", tmp)

        for k in range(n):
            res.append(0)
        Corpus.copy(res, res, dst, dst+n)
        for k in range(n):
            res[dst+k] = tmp[k]
        self.assertEqual(b"abcdeeffg", res)

    def test_copy(self):
        "test if copy function works as intended in copy operation"

        res = bytearray(b"abcdefg")

        src = 4
        dst = 5
        n = 2

        Corpus.copy(res, res, src, dst, src+n)
        self.assertEqual(b"abcdeef", res)


if __name__ == '__main__':
    unittest.main()
