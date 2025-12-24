"""
Fuzzing Corpus Management.

This module provides the Corpus class for managing seed inputs and generated
test cases in a coverage-guided fuzzer. The corpus stores inputs that have
increased code coverage and uses them as seeds for generating new mutations.

**Corpus Management:**
- Loads seed inputs from files/directories
- Stores inputs that increase coverage
- Generates new inputs by mutating existing corpus inputs
- Saves interesting inputs to disk (if corpus directory specified)

**Mutation Strategies:**
The corpus implements 15 different mutation strategies:
1. Remove range of bytes
2. Insert random bytes
3. Duplicate range of bytes
4. Copy range of bytes
5. Bit flip
6. Set byte to random value
7. Swap two bytes
8. Add/subtract from byte
9. Add/subtract from uint16
10. Add/subtract from uint32
11. Add/subtract from uint64
12. Replace byte with interesting value
13. Replace uint16 with interesting value
14. Replace uint32 with interesting value
15. Replace ASCII digit with another digit

**Interesting Values:**
Predefined sets of "interesting" values that often trigger edge cases:
- INTERESTING8: Common 8-bit values (boundaries, powers of 2)
- INTERESTING16: Common 16-bit values (boundaries, powers of 2)
- INTERESTING32: Common 32-bit values (boundaries, powers of 2)
"""

import os
import math
import random
import struct
import hashlib

from . import dictionnary

try:
    from random import _randbelow
except ImportError:
    from random import _inst
    _randbelow = _inst._randbelow

# Predefined "interesting" values that often trigger edge cases
INTERESTING8 = [-128, -1, 0, 1, 16, 32, 64, 100, 127]
INTERESTING16 = [0, 128, 255, 256, 512, 1000, 1024, 4096, 32767, 65535]
INTERESTING32 = [0, 1, 32768, 65535, 65536, 100663045, 2147483647, 4294967295]


class Corpus(object):
    """
    Manages the fuzzing corpus (seed inputs and generated test cases).
    
    The corpus stores inputs that have increased code coverage and uses them
    as seeds for generating new mutations. It implements various mutation
    strategies to explore the input space efficiently.
    
    **Corpus Lifecycle:**
    1. Initialization: Load seed inputs from files/directories
    2. Seed Phase: Run through all seed inputs first
    3. Mutation Phase: Generate new inputs by mutating corpus inputs
    4. Storage: Save interesting inputs (if corpus directory specified)
    
    **Mutation Strategy:**
    - Selects random input from corpus
    - Applies random number of mutations (exponential distribution)
    - Each mutation is one of 15 different strategies
    - Ensures output doesn't exceed max_input_size
    
    Attributes:
        _inputs: List of bytearray inputs in the corpus
        _dict: Dictionary of interesting keywords/tokens (optional)
        _max_input_size: Maximum size for generated inputs
        _dirs: Directories for loading/saving corpus
        _seed_run_finished: Whether seed phase is complete
        _seed_idx: Current index in seed phase
        _save_corpus: Whether to save interesting inputs to disk
    """
    def __init__(self, dirs=None, max_input_size=4096, dict_path=None):
        """
        Initialize a fuzzing corpus.
        
        Args:
            dirs: List of directories/files to load seed inputs from.
                 First directory is used to save generated test cases.
            max_input_size: Maximum size in bytes for generated inputs
            dict_path: Path to dictionary file (optional)
        """
        self._inputs = []
        self._dict = dictionnary.Dictionary(dict_path)
        self._max_input_size = max_input_size
        self._dirs = dirs if dirs else []
        
        # Load seed inputs from directories/files
        for i, path in enumerate(dirs):
            # Create first directory if it doesn't exist (for saving corpus)
            if i == 0 and not os.path.exists(path):
                os.mkdir(path)

            if os.path.isfile(path):
                self._add_file(path)
            else:
                # Load all files from directory
                for i in os.listdir(path):
                    fname = os.path.join(path, i)
                    if os.path.isfile(fname):
                        self._add_file(fname)
        
        # Seed phase tracking
        self._seed_run_finished = not self._inputs
        self._seed_idx = 0
        self._save_corpus = dirs and os.path.isdir(dirs[0])
        
        # Always start with empty input
        self._inputs.append(bytearray(0))

    def _add_file(self, path):
        """
        Add a file's contents to the corpus.
        
        Args:
            path: Path to file to load
        """
        with open(path, 'rb') as f:
            self._inputs.append(bytearray(f.read()))

    @property
    def length(self):
        """Get the number of inputs in the corpus."""
        return len(self._inputs)

    @staticmethod
    def _rand(n):
        """
        Generate random integer in [0, n).
        
        Args:
            n: Upper bound (exclusive)
            
        Returns:
            Random integer, or 0 if n < 2
        """
        if n < 2:
            return 0
        return _randbelow(n)

    @staticmethod
    def _rand_exp():
        """
        Generate random number with exponential distribution.
        
        Returns n with probability 1/2^(n+1). This is used to determine
        how many mutations to apply to an input (most inputs get few mutations,
        some get many).
        
        Implementation: Count leading zeros in random 32-bit number.
        
        Returns:
            Random number with exponential distribution
        """
        rand_bin = bin(random.randint(0, 2**32-1))[2:]
        rand_bin = '0'*(32 - len(rand_bin)) + rand_bin
        count = 0
        for i in rand_bin:
            if i == '0':
                count +=1
            else:
                break
        return count

    @staticmethod
    def _choose_len(n):
        """
        Choose a length for mutation operations.
        
        Uses a weighted distribution:
        - 90%: Small length (1-8 bytes)
        - 9%: Medium length (1-32 bytes)
        - 1%: Large length (1-n bytes)
        
        Args:
            n: Maximum length
            
        Returns:
            Random length in [1, min(n, max_length)]
        """
        x = Corpus._rand(100)
        if x < 90:
            return Corpus._rand(min(8, n)) + 1
        elif x < 99:
            return Corpus._rand(min(32, n)) + 1
        else:
            return Corpus._rand(n) + 1

    @staticmethod
    def copy(src, dst, start_source, start_dst, end_source=None, end_dst=None):
        """
        Copy bytes from source to destination.
        
        Copies bytes from src[start_source:end_source] to dst[start_dst:end_dst].
        Handles bounds checking to avoid out-of-range access.
        
        Args:
            src: Source bytearray
            dst: Destination bytearray
            start_source: Start position in source
            start_dst: Start position in destination
            end_source: End position in source (None = end of src)
            end_dst: End position in destination (None = end of dst)
        """
        end_source = len(src) if end_source is None else end_source
        end_dst = len(dst) if end_dst is None else end_dst
        byte_to_copy = min(end_source-start_source, end_dst-start_dst)
        dst[start_dst:start_dst+byte_to_copy] = src[start_source:start_source+byte_to_copy]

    def put(self, buf):
        """
        Add an input to the corpus (if it increased coverage).
        
        Adds the input to the corpus and optionally saves it to disk
        (if corpus directory is configured). Uses SHA256 hash as filename
        to avoid duplicates.
        
        Args:
            buf: Bytearray input to add
        """
        self._inputs.append(buf)
        if self._save_corpus:
            m = hashlib.sha256()
            m.update(buf)
            fname = os.path.join(self._dirs[0], m.hexdigest())
            with open(fname, 'wb') as f:
                f.write(buf)

    def generate_input(self):
        """
        Generate the next input to test.
        
        **Seed Phase:**
        First runs through all seed inputs in order to establish baseline.
        
        **Mutation Phase:**
        After seeds are exhausted, generates new inputs by:
        1. Selecting random input from corpus
        2. Mutating it using various strategies
        
        Returns:
            Bytearray input to test
        """
        # Seed phase: run through all seed inputs first
        if not self._seed_run_finished:
            next_input = self._inputs[self._seed_idx]
            self._seed_idx += 1
            if self._seed_idx >= len(self._inputs):
                self._seed_run_finished = True
            return next_input

        # Mutation phase: select random input and mutate it
        buf = self._inputs[self._rand(len(self._inputs))]
        return self.mutate(buf)

    def mutate(self, buf):
        """
        Mutate an input using random strategies.
        
        Applies a random number of mutations (exponentially distributed)
        to the input. Each mutation is one of 15 different strategies
        chosen randomly. The input is truncated to max_input_size if needed.
        
        **Mutation Strategies:**
        0. Remove range of bytes
        1. Insert random bytes
        2. Duplicate range of bytes
        3. Copy range of bytes
        4. Bit flip
        5. Set byte to random value
        6. Swap two bytes
        7. Add/subtract from byte
        8. Add/subtract from uint16
        9. Add/subtract from uint32
        10. Add/subtract from uint64
        11. Replace byte with interesting value
        12. Replace uint16 with interesting value
        13. Replace uint32 with interesting value
        14. Replace ASCII digit with another digit
        
        Args:
            buf: Input bytearray to mutate
            
        Returns:
            Mutated bytearray (may be truncated to max_input_size)
        """
        res = buf[:]
        # Number of mutations to apply (exponentially distributed)
        nm = self._rand_exp()
        i = 0
        while i != nm:
            i += 1
            # Remove a range of bytes.
            x = self._rand(15)
            if x == 0:
                if len(self._inputs) <= 1:
                    i -= 1
                    continue
                pos0 = self._rand(len(res))
                pos1 = pos0 + self._choose_len(len(res) - pos0)
                self.copy(res, res, pos1, pos0)
                res = res[:len(res) - (pos1-pos0)]
            elif x == 1:
                # Insert a range of random bytes.
                pos = self._rand(len(res) + 1)
                n = self._choose_len(10)
                for k in range(n):
                    res.append(0)
                self.copy(res, res, pos, pos+n)
                for k in range(n):
                    res[pos+k] = self._rand(256)
            elif x == 2:
                # Duplicate a range of bytes.
                if len(res) <= 1:
                    i -= 1
                    continue
                src = self._rand(len(res))
                dst = self._rand(len(res))
                while src == dst:
                    dst = self._rand(len(res))
                n = self._choose_len(len(res) - src)
                tmp = bytearray(n)
                self.copy(res, tmp, src, 0)
                for k in range(n):
                    res.append(0)
                self.copy(res, res, dst, dst+n)
                for k in range(n):
                    res[dst+k] = tmp[k]
            elif x == 3:
                # Copy a range of bytes.
                if len(res) <= 1:
                    i -= 1
                    continue
                src = self._rand(len(res))
                dst = self._rand(len(res))
                while src == dst:
                    dst = self._rand(len(res))
                n = self._choose_len(len(res) - src)
                self.copy(res, res, src, dst, src+n)
            elif x == 4:
                # Bit flip. Spooky!
                if len(res) == 0:
                    i -= 1
                    continue
                pos = self._rand(len(res))
                res[pos] ^= 1 << self._rand(8)
            elif x == 5:
                # Set a byte to a random value.
                if len(res) == 0:
                    i -= 1
                    continue
                pos = self._rand(len(res))
                res[pos] ^= self._rand(255) + 1
            elif x == 6:
                # Swap 2 bytes.
                if len(res) <= 1:
                    i -= 1
                    continue
                src = self._rand(len(res))
                dst = self._rand(len(res))
                while src == dst:
                    dst = self._rand(len(res))
                res[src], res[dst] = res[dst], res[src]
            elif x == 7:
                # Add/subtract from a byte.
                if len(res) == 0:
                    i -= 1
                    continue
                pos = self._rand(len(res))
                v = self._rand(2 ** 8)
                res[pos] = (res[pos] + v) % 256
            elif x == 8:
                # Add/subtract from a uint16.
                if len(res) < 2:
                    i -= 1
                    continue
                pos = self._rand(len(res) - 1)
                v = self._rand(2 ** 16)
                if bool(random.getrandbits(1)):
                    v = struct.pack('>H', v)
                else:
                    v = struct.pack('<H', v)
                res[pos] = (res[pos] + v[0]) % 256
                res[pos + 1] = (res[pos] + v[1]) % 256
            elif x == 9:
                # Add/subtract from a uint32.
                if len(res) < 4:
                    i -= 1
                    continue
                pos = self._rand(len(res) - 3)
                v = self._rand(2 ** 32)
                if bool(random.getrandbits(1)):
                    v = struct.pack('>I', v)
                else:
                    v = struct.pack('<I', v)
                res[pos] = (res[pos] + v[0]) % 256
                res[pos + 1] = (res[pos + 1] + v[1]) % 256
                res[pos + 2] = (res[pos + 2] + v[2]) % 256
                res[pos + 3] = (res[pos + 3] + v[3]) % 256
            elif x == 10:
                # Add/subtract from a uint64.
                if len(res) < 8:
                    i -= 1
                    continue
                pos = self._rand(len(res) - 7)
                v = self._rand(2 ** 64)
                if bool(random.getrandbits(1)):
                    v = struct.pack('>Q', v)
                else:
                    v = struct.pack('<Q', v)
                res[pos] = (res[pos] + v[0]) % 256
                res[pos + 1] = (res[pos + 1] + v[1]) % 256
                res[pos + 2] = (res[pos + 2] + v[2]) % 256
                res[pos + 3] = (res[pos + 3] + v[3]) % 256
                res[pos + 4] = (res[pos + 4] + v[4]) % 256
                res[pos + 5] = (res[pos + 5] + v[5]) % 256
                res[pos + 6] = (res[pos + 6] + v[6]) % 256
                res[pos + 7] = (res[pos + 7] + v[7]) % 256
            elif x == 11:
                # Replace a byte with an interesting value.
                if len(res) == 0:
                    i -= 1
                    continue
                pos = self._rand(len(res))
                res[pos] = INTERESTING8[self._rand(len(INTERESTING8))] % 256
            elif x == 12:
                # Replace an uint16 with an interesting value.
                if len(res) < 2:
                    i -= 1
                    continue
                pos = self._rand(len(res) - 1)
                v = random.choice(INTERESTING16)
                if bool(random.getrandbits(1)):
                    v = struct.pack('>H', v)
                else:
                    v = struct.pack('<H', v)
                res[pos] = v[0] % 256
                res[pos + 1] = v[1] % 256
            elif x == 13:
                # Replace an uint32 with an interesting value.
                if len(res) < 4:
                    i -= 1
                    continue
                pos = self._rand(len(res) - 3)
                v = random.choice(INTERESTING32)
                if bool(random.getrandbits(1)):
                    v = struct.pack('>I', v)
                else:
                    v = struct.pack('<I', v)
                res[pos] = v[0] % 256
                res[pos + 1] = v[1] % 256
                res[pos + 2] = v[2] % 256
                res[pos + 3] = v[3] % 256
            elif x == 14:
                # Replace an ascii digit with another digit.
                digits = []
                for k in range(len(res)):
                    if ord('0') <= res[k] <= ord('9'):
                        digits.append(k)
                if len(digits) == 0:
                    i -= 1
                    continue
                pos = self._rand(len(digits))
                was = res[digits[pos]]
                now = was
                while was == now:
                    now = self._rand(10) + ord('0')
                res[digits[pos]] = now

        if len(res) > self._max_input_size:
            res = res[:self._max_input_size]
        return res
