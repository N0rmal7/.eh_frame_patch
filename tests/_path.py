import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PLUGINS = os.path.join(ROOT, "plugins")
if PLUGINS not in sys.path:
    sys.path.insert(0, PLUGINS)
