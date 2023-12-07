import sys
from pathlib import Path
import subprocess as sp
global link

def link(path, shadow_path):
    # links folders. Note if 01_input is already created, just delete folder and this will regenerate it. Only needs to be done once.
    cmd = ['ln', '-s', path, shadow_path]
    sp.run(" ".join(cmd), shell=True, check=True)


