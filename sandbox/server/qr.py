"""QR code encoder (ISO/IEC 18004, model 2), byte mode, rendered as SVG.

Just enough of the standard for the offline confirmation screen: byte mode,
error correction level L or M, versions 1-40, automatic mask selection.
Standard library only, like the rest of the sandbox.
"""

# Error correction codewords per block and number of blocks, indexed by version.
_ECC_PER_BLOCK = {
    'L': (0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28,
          28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30),
    'M': (0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26,
          26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28),
}
_BLOCKS = {
    'L': (0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8,
          8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25),
    'M': (0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16,
          17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49),
}
_FORMAT_BITS = {'L': 1, 'M': 0}


class DataTooLong(ValueError):
    pass


def _raw_modules(version):
    """Modules available for data and error correction."""
    result = (16 * version + 128) * version + 64
    if version >= 2:
        align = version // 7 + 2
        result -= (25 * align - 10) * align - 55
        if version >= 7:
            result -= 36
    return result


def _data_codewords(version, ecl):
    return _raw_modules(version) // 8 - _ECC_PER_BLOCK[ecl][version] * _BLOCKS[ecl][version]


# --- Reed-Solomon over GF(256), polynomial 0x11D ---------------------------------

def _gf_mul(x, y):
    z = 0
    for i in range(7, -1, -1):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z & 0xFF


def _rs_divisor(degree):
    result = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(degree):
            result[j] = _gf_mul(result[j], root)
            if j + 1 < degree:
                result[j] ^= result[j + 1]
        root = _gf_mul(root, 0x02)
    return result


def _rs_remainder(data, divisor):
    result = [0] * len(divisor)
    for byte in data:
        factor = byte ^ result.pop(0)
        result.append(0)
        for i, coef in enumerate(divisor):
            result[i] ^= _gf_mul(coef, factor)
    return result


# --- Encoding -------------------------------------------------------------------------

def _codewords(data, version, ecl):
    count_bits = 8 if version <= 9 else 16
    capacity_bits = _data_codewords(version, ecl) * 8
    bits = [0, 1, 0, 0]  # byte mode
    bits += [(len(data) >> i) & 1 for i in range(count_bits - 1, -1, -1)]
    for byte in data:
        bits += [(byte >> i) & 1 for i in range(7, -1, -1)]
    bits += [0] * min(4, capacity_bits - len(bits))
    bits += [0] * (-len(bits) % 8)
    codewords = [int(''.join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = 0xEC
    while len(codewords) < capacity_bits // 8:
        codewords.append(pad)
        pad ^= 0xEC ^ 0x11

    blocks_count = _BLOCKS[ecl][version]
    ecc_len = _ECC_PER_BLOCK[ecl][version]
    raw = _raw_modules(version) // 8
    short_blocks = blocks_count - raw % blocks_count
    short_len = raw // blocks_count
    divisor = _rs_divisor(ecc_len)
    blocks, k = [], 0
    for i in range(blocks_count):
        size = short_len - ecc_len + (0 if i < short_blocks else 1)
        chunk = codewords[k:k + size]
        k += size
        ecc = _rs_remainder(chunk, divisor)
        if i < short_blocks:
            chunk = chunk + [None]  # aligns short blocks for interleaving
        blocks.append(chunk + ecc)
    result = []
    for i in range(len(blocks[0])):
        for block in blocks:
            if block[i] is not None:
                result.append(block[i])
    return result


def _alignment_positions(version):
    if version == 1:
        return []
    count = version // 7 + 2
    step = (version * 8 + count * 3 + 5) // (count * 4 - 4) * 2
    size = version * 4 + 17
    return [6] + [size - 7 - i * step for i in reversed(range(count - 1))]


class _Matrix:
    def __init__(self, version):
        self.version = version
        self.size = version * 4 + 17
        self.dark = [[False] * self.size for _ in range(self.size)]
        self.reserved = [[False] * self.size for _ in range(self.size)]

    def set(self, x, y, dark):
        self.dark[y][x] = dark
        self.reserved[y][x] = True

    def draw_function_patterns(self):
        n = self.size
        for i in range(n):
            self.set(6, i, i % 2 == 0)
            self.set(i, 6, i % 2 == 0)
        for cx, cy in ((3, 3), (n - 4, 3), (3, n - 4)):
            for dy in range(-4, 5):
                for dx in range(-4, 5):
                    x, y = cx + dx, cy + dy
                    if 0 <= x < n and 0 <= y < n:
                        self.set(x, y, max(abs(dx), abs(dy)) not in (2, 4))
        positions = _alignment_positions(self.version)
        last = len(positions) - 1
        for i, cx in enumerate(positions):
            for j, cy in enumerate(positions):
                if (i, j) in ((0, 0), (0, last), (last, 0)):
                    continue
                for dy in range(-2, 3):
                    for dx in range(-2, 3):
                        self.set(cx + dx, cy + dy, max(abs(dx), abs(dy)) != 1)
        self.draw_format_bits('L', 0)  # reserves the area; rewritten after masking
        if self.version >= 7:
            rem = self.version
            for _ in range(12):
                rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
            bits = self.version << 12 | rem
            for i in range(18):
                bit = (bits >> i) & 1 == 1
                a, b = n - 11 + i % 3, i // 3
                self.set(a, b, bit)
                self.set(b, a, bit)

    def draw_format_bits(self, ecl, mask):
        data = _FORMAT_BITS[ecl] << 3 | mask
        rem = data
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        bits = (data << 10 | rem) ^ 0x5412
        bit = [(bits >> i) & 1 == 1 for i in range(15)]
        n = self.size
        for i in range(6):
            self.set(8, i, bit[i])
        self.set(8, 7, bit[6])
        self.set(8, 8, bit[7])
        self.set(7, 8, bit[8])
        for i in range(9, 15):
            self.set(14 - i, 8, bit[i])
        for i in range(8):
            self.set(n - 1 - i, 8, bit[i])
        for i in range(8, 15):
            self.set(8, n - 15 + i, bit[i])
        self.set(8, n - 8, True)  # always dark

    def draw_codewords(self, codewords):
        n = self.size
        i = 0
        total = len(codewords) * 8
        right = n - 1
        while right >= 1:
            if right == 6:
                right = 5
            for vert in range(n):
                for j in range(2):
                    x = right - j
                    upward = ((right + 1) & 2) == 0
                    y = n - 1 - vert if upward else vert
                    if not self.reserved[y][x] and i < total:
                        self.dark[y][x] = (codewords[i >> 3] >> (7 - (i & 7))) & 1 == 1
                        i += 1
            right -= 2

    def apply_mask(self, mask):
        rule = _MASKS[mask]
        for y in range(self.size):
            for x in range(self.size):
                if not self.reserved[y][x] and rule(x, y):
                    self.dark[y][x] = not self.dark[y][x]


_MASKS = (
    lambda x, y: (x + y) % 2 == 0,
    lambda x, y: y % 2 == 0,
    lambda x, y: x % 3 == 0,
    lambda x, y: (x + y) % 3 == 0,
    lambda x, y: (x // 3 + y // 2) % 2 == 0,
    lambda x, y: x * y % 2 + x * y % 3 == 0,
    lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
    lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0,
)


def _penalty(dark):
    """Mask penalty rules N1-N4 of the standard."""
    n = len(dark)
    score = 0
    lines = dark + [list(col) for col in zip(*dark)]
    finder_like = ([True, False, True, True, True, False, True, False, False, False, False],
                   [False, False, False, False, True, False, True, True, True, False, True])
    for line in lines:
        run, previous = 0, None
        for module in line:
            if module == previous:
                run += 1
            else:
                if run >= 5:
                    score += run - 2
                run, previous = 1, module
        if run >= 5:
            score += run - 2
        for i in range(n - 10):
            if line[i:i + 11] in finder_like:
                score += 40
    for y in range(n - 1):
        for x in range(n - 1):
            if dark[y][x] == dark[y][x + 1] == dark[y + 1][x] == dark[y + 1][x + 1]:
                score += 3
    dark_count = sum(map(sum, dark))
    score += abs(dark_count * 20 - n * n * 10) // (n * n) * 10
    return score


def encode(text, ecl='M'):
    """Returns the module matrix (list of rows, True = dark) for `text`."""
    data = text.encode('utf-8')
    for version in range(1, 41):
        count_bits = 8 if version <= 9 else 16
        if 4 + count_bits + len(data) * 8 <= _data_codewords(version, ecl) * 8:
            break
    else:
        raise DataTooLong(f'{len(data)} bytes do not fit in a QR code at level {ecl}')

    codewords = _codewords(data, version, ecl)
    best = None
    for mask in range(8):
        matrix = _Matrix(version)
        matrix.draw_function_patterns()
        matrix.draw_codewords(codewords)
        matrix.apply_mask(mask)
        matrix.draw_format_bits(ecl, mask)
        score = _penalty(matrix.dark)
        if best is None or score < best[0]:
            best = (score, matrix)
    return best[1].dark


def to_svg(modules, border=4):
    """A compact SVG: one path of horizontal runs, one unit per module, with a quiet zone."""
    size = len(modules) + border * 2
    parts = []
    for y, row in enumerate(modules):
        x = 0
        while x < len(row):
            if row[x]:
                start = x
                while x < len(row) and row[x]:
                    x += 1
                parts.append(f'M{start + border} {y + border}h{x - start}v1H{start + border}z')
            else:
                x += 1
    path = ''.join(parts)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" '
            f'shape-rendering="crispEdges"><rect width="100%" height="100%" fill="#fff"/>'
            f'<path d="{path}" fill="#000"/></svg>')
