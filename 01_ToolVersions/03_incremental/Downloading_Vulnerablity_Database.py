import subprocess as sp
import sys
from pathlib import Path


def install_Grype_control_database():
    """
    here we download all databases possible for grype to use and then could later point to it.
    instead currently we just saved the database from a certain date and use that to compare vulnerabilities.
    We pull Trivy's database from the same date. We saved it by copying the database found here
    str(Path(sys.path[0]).absolute().parent.parent.parent) + "/.cache/grype/" on the specific day 11/03/2023.
    We replace and use this database for all versions to control variables.
    """
    # make file path to save out to
    path = str(Path(sys.path[0]).absolute().parent.parent) + "/01_ToolVersions/01_input"

    # command to install grype version of interest
    cmd = ["curl", "-sSfL", "https://raw.githubusercontent.com/anchore/grype-db/main/install.sh",
           "|", "sh", "-s", "--", "-b", path, "/v0.19.1"]
    sp.run(" ".join(cmd), shell=True, check=True)

    vendors = ['alpine', 'amazon', 'chainguard', 'debian', 'github', 'mariner', 'nvd', 'oracle', 'rhel', 'sles',
               'ubuntu', 'wolfi']

    for v in vendors:

        # pull the database into grype-db
        cmd = [path + "/grype-db", "pull", "-g -p", v]  # ??
        sp.run(" ".join(cmd), shell=True, check=True)

        # build and format that database
        cmd = [path + "/grype-db", "build", "-g", "--dir=" + path + "/build", "-p", v]
        sp.run(" ".join(cmd), shell=True, check=True)

        cmd = [path + "/grype-db", "package", "--dir=" + path + "/build"]
        sp.run(" ".join(cmd), shell=True, check=True)


install_Grype_control_database()

'''
Updated way to download the trivy vulnerability database. 
They collect and store all databases, and can be easily pulled and then pointed to.
We use the database from 11/03/2023 to control variables. 
'''
def install_trivy_control_database():
    # make file path to save out to
    path_here = str(Path(sys.path[0]).absolute())

    cmd = ["oras pull ghcr.io/aquasecurity/trivy-db:2"]
    sp.run(" ".join(cmd), shell=True, check=True)

    cmd = ["rsync -av -e ssh", path_here + "/db.tar.gz"]
    sp.run(" ".join(cmd), shell=True, check=True)


install_trivy_control_database()