"""Dynamic dispatch and reflection."""


def run(name, registry):
    handler = getattr(registry, name)
    return handler()


def call_via_name(module_name, function_name):
    module = __import__(module_name)
    return getattr(module, function_name)()
