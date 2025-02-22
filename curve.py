import warnings
from typing import Tuple, Union

from math_utils import modulu_inverse


class Curve:
    """
    Represents an elliptic curve defined by the equation y² = (x³ + ax + b) mod p.

    Attributes:
        a (int): Coefficient of x.
        b (int): Constant term.
        field (SubGroup): The underlying field parameters.
        name (str): The curve's name.
        g (Point): Generator point of the curve.
    """
    def __init__(self, a: int, b: int, field: 'SubGroup', name: str = "undefined") -> None:
        self.name = name
        self.a = a
        self.b = b
        self.field = field
        self.g = Point(self, self.field.g[0], self.field.g[1])

    def is_singular(self) -> bool:
        """Checks if the curve is singular (invalid for cryptographic use)."""
        return (4 * self.a**3 + 27 * self.b**2) % self.field.p == 0

    def on_curve(self, x: int, y: int) -> bool:
        """Checks if a given point (x, y) lies on the curve."""
        return (y**2 - x**3 - self.a * x - self.b) % self.field.p == 0

    def __eq__(self, other: 'Curve') -> bool:
        if not isinstance(other, Curve):
            return False
        return self.a == other.a and self.b == other.b and self.field == other.field

    def __str__(self) -> str:
        return f'"{self.name}" => y² = (x³ + {self.a}x + {self.b}) mod {self.field.p}'


class SubGroup:
    """
    Represents a subgroup of points on an elliptic curve.

    Attributes:
        p (int): Prime order of the field.
        g (Tuple[int, int]): Generator point.
        n (int): Order of the subgroup.
        h (int): Cofactor of the subgroup.
    """
    def __init__(self, p: int, g: Tuple[int, int], n: int, h: int) -> None:
        self.p = p
        self.g = g
        self.n = n
        self.h = h

    def __eq__(self, other: 'SubGroup') -> bool:
        if not isinstance(other, SubGroup):
            return False
        return self.p == other.p and self.g == other.g and self.n == other.n and self.h == other.h

    def __str__(self) -> str:
        return f"Subgroup => generator {self.g}, order: {self.n}, cofactor: {self.h} on Field => prime {self.p}"


class InfinityPoint:
    """
    Represents the point at infinity, the identity element in elliptic curve operations.

    Attributes:
        curve (Curve): The elliptic curve associated with the point.
    """

    def __init__(self, curve: Curve) -> None:
        self.curve = curve

    def __eq__(self, other: 'InfinityPoint') -> bool:
        return isinstance(other, InfinityPoint) and self.curve == other.curve

    def __add__(self, other: Union['InfinityPoint', 'Point']) -> Union['InfinityPoint', 'Point']:
        if isinstance(other, InfinityPoint):
            return InfinityPoint(self.curve)
        if isinstance(other, Point):
            return other
        raise TypeError(f"Unsupported operand type(s) for +: '{type(other).__name__}' and 'Inf'")

    def __str__(self) -> str:
        return f"Infinity Point on {self.curve}"


class Point:
    """
    Represents a point on an elliptic curve.

    Attributes:
        curve (Curve): The elliptic curve the point belongs to.
        x (int): x-coordinate of the point.
        y (int): y-coordinate of the point.
        p (int): Prime order of the curve field.
        on_curve (bool): Indicates if the point lies on the curve.
    """
    def __init__(self, curve: Curve, x: int, y: int) -> None:
        self.curve = curve
        self.x = x
        self.y = y
        self.p = self.curve.field.p
        self.on_curve = self.curve.on_curve(x, y)
        if not self.on_curve:
            warnings.warn(f"Point ({self.x}, {self.y}) is not on curve '{self.curve}'")

    def __slope(self, p: 'Point', q: 'Point') -> int:
        """Calculates the slope between two points on the curve."""
        if p.x == q.x:
            return (3 * p.x**2 + self.curve.a) * modulu_inverse(2 * p.y, self.p)
        return (p.y - q.y) * modulu_inverse(p.x - q.x, self.p)

    def __eq__(self, other: 'Point') -> bool:
        if not isinstance(other, Point):
            return False
        return self.x == other.x and self.y == other.y and self.curve == other.curve

    def __add__(self, other: Union['Point', 'InfinityPoint']) -> Union['Point', 'InfinityPoint']:
        """Adds two points on the elliptic curve."""
        if isinstance(other, InfinityPoint):
            return self
        if isinstance(other, Point):
            if self.x == other.x and self.y != other.y:
                return InfinityPoint(self.curve)
            if self.curve != other.curve:
                raise ValueError("Cannot add points from different curves")
            m = self.__slope(self, other)
            x_r = (m**2 - self.x - other.x) % self.p
            y_r = (-self.y - m * (x_r - self.x)) % self.p
            return Point(self.curve, x_r, y_r)
        raise TypeError(f"Unsupported operand type(s) for +: '{type(other).__name__}' and 'Point'")

    def __sub__(self, other: 'Point') -> 'Point':
        """Subtracts two points on the elliptic curve."""
        if isinstance(other, Point):
            return self + Point(self.curve, other.x, -other.y % self.p)
        raise TypeError(f"Unsupported operand type(s) for -: '{type(other).__name__}' and 'Point'")
    
    def __mul__(self, other: int) -> Union['Point', 'InfinityPoint']:
        """Performs scalar multiplication of a point on the curve."""
        if isinstance(other, InfinityPoint):
            return InfinityPoint(self.curve)
        if isinstance(other, int):
            if other % self.curve.field.n == 0:
                return InfinityPoint(self.curve)
            if other < 0:
                addend = Point(self.curve, self.x, -self.y % self.p)
            else:
                addend = self
            result = InfinityPoint(self.curve)
            # Iterate over all bits starting by the LSB
            for bit in reversed([int(i) for i in bin(abs(other))[2:]]):
                if bit == 1:
                    result += addend
                addend += addend
            return result
        else:
            raise TypeError(f"Unsupported operand type(s) for *: '{type(other).__name__}' and 'Point'")
        
    def __rmul__(self, other):
        return self.__mul__(other)
 
    def __str__(self) -> str:
        status = "on" if self.on_curve else "off"
        return f"({self.x}, {self.y}) {status} curve {self.curve}"
    

def get_curve(name: str) -> Curve:
    """
    Returns the curve parameters for a given curve name.

    Args:
        name (str): The curve name.

    Returns:
        Curve: The curve object.
    """
    if name == 'secp256k1':
        # Domain parameters from http://www.secg.org/sec2-v2.pdf - 2.4.1
        p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
        n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
        a = 0x0000000000000000000000000000000000000000000000000000000000000000
        b = 0x0000000000000000000000000000000000000000000000000000000000000007
        g = (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
            0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
        h = 1
        return Curve(a, b, SubGroup(p, g, n, h), name)
    raise ValueError(f"Curve '{name}' is not supported")
