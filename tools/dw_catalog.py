"""Share one parse of the generated function catalog within a source_catalog module.

The frozen compiler's source_catalog.bind/bind_import re-read and re-parse the
94 MB generated/function-catalog.json for every binding. That file is a
recorded recovery input and stays byte-identical, so the prepare steps give
their private module instance this json shim instead. bind and bind_import only
read the catalog; an identical text returns the same parse.
"""

import json


class _CatalogJson:
    def __init__(self):
        self._text = None
        self._value = None

    def __getattr__(self, name):
        return getattr(json, name)

    def loads(self, text, *args, **kwargs):
        if not args and not kwargs and self._text is not None and text == self._text:
            return self._value
        value = json.loads(text, *args, **kwargs)
        if not args and not kwargs and len(text) >= 8 * 1024 * 1024:  # the catalog only
            self._text, self._value = text, value
        return value


def share_catalog(module):
    """Install the shim on one private source_catalog module instance."""
    module.json = _CatalogJson()
    return module
