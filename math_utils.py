from typing import Tuple


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Extended Euclidean Algorithm to find the greatest common divisor (GCD) of a and b.

    Args:
        a (int): First integer.
        b (int): Second integer.

    Returns:
        Tuple[int, int, int]: GCD and the coefficients for Bézout's identity.
    """
    if a == 0:
        return b, 0, 1
    g, y, x = extended_gcd(b % a, a)
    return g, x - (b // a) * y, y


def modulu_inverse(a: int, p: int) -> int:
    """
    Computes the modular inverse of a % p.

    Args:
        a (int): The integer to invert.
        p (int): The modulus.

    Returns:
        int: The modular inverse.

    Raises:
        ArithmeticError: If the modular inverse does not exist.
    """
    if a < 0:
        return p - modulu_inverse(-a, p)
    g, x, _ = extended_gcd(a, p)
    if g != 1:
        raise ArithmeticError("Modular inverse does not exist")
    else:
        return x % p
