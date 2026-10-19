"""Deliberate bug patterns."""


def parse_flag(flag):
    if flag = True:
        return 'on'
    return 'off'


def swallow():
    try:
        return 1 / 0
    except:
        pass


def unreachable():
    return 'value'
