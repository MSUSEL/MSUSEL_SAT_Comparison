#!/usr/bin/env python3

"""
Here we run every docker image,
through every version of Grype and save the json files,
which contain info, specifically a list of vulnerabilities.
"""

import os
import subprocess as sp
import sys
from pathlib import Path
from GlobalFunctions.Symbolic_Link import link

class GrypeImageProcessing:
    """class where we process images through grype versions, You need to already have downloaded docker image at this point"""
    def __init__(self):
        # list of the different Grype versions
        self.GVs = os.listdir(str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/")

        # list of the different images (note this comes out as a list of bytes)
        self.images = sp.check_output("docker images --format '{{.Repository}}:{{.Tag}}'", shell=True).splitlines()


    def processing(self):
        """goes through each version of Grype and runs every docker image through it. Saves output as json"""
        # I have docker files on my local computer under latest, I don't want them included in the analysis.
        # Here you can add any other specific restriction of docker files you don't want included in you analysis.
        self.images = [x for x in self.images if not x.decode('utf-8').__contains__("latest")]

        # for each grype version
        for g in self.GVs:
            print(g) # just to see what version your at, step takes time.
            grype_version_filepath = str(Path(sys.path[0]).absolute().parent) + "/01_input/Grype/" + g

            # for each docker image
            for i in self.images:
           # for z in range(0, 50): # just a check, if you don't want to process the whole thang.
                # i = self.images[z]
                # image comes out as a byte, and we need string form
                image = i.decode('utf-8')

                # if the directory doesn't exist yet create it
                if not os.path.exists(str(Path(sys.path[0]).absolute().parent) + '/04_product/Grype/' + g):
                    os.makedirs(str(Path(sys.path[0]).absolute().parent) + '/04_product/Grype/' + g)

                # where we want to save the json that contains vulnerability info from the image run through the grype version
                output_path = str(
                    Path(sys.path[0]).absolute().parent) + "/04_product/Grype/" + g + "/" + image + ".json"

                if not os.path.exists(
                        output_path):  # remove if you want to run all images, only here to save time and not rerun data say if a version crashes.
                    # command line to run the image through the grype version
                    cmd = [grype_version_filepath, image, "--scope all-layers -o json>", output_path]
                    sp.run(" ".join(cmd), shell=True, check=True)


def main():
    GI = GrypeImageProcessing()
    GI.processing()

    # link this output to the input of next step iff not already done, which we check by seeming if shadow folder exists because it's created when linked
    path = str(Path(sys.path[0]).absolute().parent) + "/04_product/Grype"
    shadow_path = str(Path(sys.path[0]).absolute().parent.parent) + "/03_Processing/01_input/Grype"
    if not os.path.exists(shadow_path):
        link(path, shadow_path)


main()