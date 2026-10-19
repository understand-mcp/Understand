"""Uses the helpers above."""

from pkg.math import add, multiply


def total(values):
    result = 0
    for value in values:
        result = add(result, value)
    return result


def main():
    return total([multiply(2, 3), 4])
