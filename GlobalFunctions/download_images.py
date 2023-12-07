import subprocess as sp
import sys
from pathlib import Path


'''
this function will generate a list of the docker images on your computer and save to a txt file'''
def write_docker_image_names_to_file():
    # list of the different images (note this comes out as a list of bytes)
    images = sp.check_output("docker images --format '{{.Repository}}:{{.Tag}}'", shell=True).splitlines()
    images_proc = [x.decode('utf-8') for x in images if not x.decode('utf-8').__contains__("latest")]

    with open(str(Path(sys.path[0]).absolute()) + "/research_images.txt", "w") as output:
        output.write(str(images_proc))

'''
This is a function to download docker images. I have a text file of 
all the docker images I want to download and the versions.
'''
def main():

    with open(
            str(Path(sys.path[0]).absolute()) + "/research_images.txt",
            "r") as f:
        versions = (f.read().splitlines()[0]).split(",")

    for i in versions:
        try:
            cmd = ['docker image inspect', i]
            check = sp.check_output(" ".join(cmd), shell=True).splitlines()
        except:
            check = None

        if check is None and i.__contains__('none') != True:
            cmd = ['docker', 'pull', i]
            sp.run(" ".join(cmd), shell=True, check=True)

        else:
            print(i)



main()