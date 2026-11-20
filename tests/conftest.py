import os
import sys

# Permite importar app.py desde la raíz del proyecto y leer archivos relativos a ella.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)
