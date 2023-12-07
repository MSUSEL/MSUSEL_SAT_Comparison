#!/usr/bin/env python3

"""
Here we are given a .txt file with a list of Trivy versions from 01_input,
 we download versions and save to 04_product
"""

from GlobalFunctions.Symbolic_Link import link
import os
import sys
import subprocess as sp
from pathlib import Path

# Tips:
# -some versions of Grype and Trivy aren't available for download if you have a version not present it will throw an error
#

def install_trivy_control_database(version):
    """Given a version in string form(vX.XX.X or vX.X.X) downloads the associated Trivy version and save it ."""

    # make file path to save out to
    path = str(Path(sys.path[0]).absolute().parent.parent) + "/01_ToolVersions/04_product/Trivy/"

    # command to install grype version of interest
    cmd = ["curl", "-sSfL", "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh",
           "|", "sh", "-s", "--", "-b", path, version]
    sp.run(" ".join(cmd), shell=True, check=True)

    # command to change the name, so we have the version numbers as the tool title
    cmd = ["mv", path + "trivy", path + version.replace("v", "T").replace(".", "_")]
    sp.run(" ".join(cmd), shell=True, check=True)

    cmd = [path + version.replace("v", "T").replace(".", "_"), "image --reset"]
    sp.run(" ".join(cmd), shell=True, check=True)

    # we replace the database that Trivy downloaded and put on our machine with the static one we downloaded before this point.
    path_database = str(Path(sys.path[0]).absolute().parent.parent) + "/01_ToolVersions/03_incremental/db.tar.gz"
    path_og = str(Path(sys.path[0]).absolute().parent.parent.parent) + "/.cache/trivy/db"
    cmd = ["mkdir -p", path_og]
    sp.run(" ".join(cmd), shell=True, check=True)
    cmd = ["cd", path_og]
    sp.run(" ".join(cmd), shell=True, check=True)
    cmd = ["tar xvf", path_database, "-C", path_og]
    sp.run(" ".join(cmd), shell=True, check=True)

def main():
    """We read in the input txt file with desired Trivy versions and run through our install grype version function"""

    # versionNames should look like a list = ['vx.x.x','vx.xx.x']
    with open(
            str(Path(sys.path[0]).absolute().parent.parent) + "/01_ToolVersions/01_input/TrivyVersions.txt",
            "r") as f:
        versions = f.read().splitlines()

    for version in versions:
        install_trivy_control_database(version)

    # builds a link to the next part of the processes input. Just done once
    path = str(Path(sys.path[0]).absolute().parent.parent) + "/01_ToolVersions/04_product/Trivy"
    shadow_path = str(Path(sys.path[0]).absolute().parent.parent) + "/02_DataAcquisition/01_input/Trivy"
    if not os.path.exists(shadow_path):
        link(path, shadow_path)

main()