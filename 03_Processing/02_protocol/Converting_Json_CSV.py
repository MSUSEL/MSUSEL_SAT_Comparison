"""
This is a parent class that just has helpful functions that can be used in the processing of either tools .json file
Here helps sort the versions and their set of images vulnerability sets. It also holds a function to write the data frames to a csv file.
"""

import os
import json
import sys
import pandas as pd
from pathlib import Path
import requests

from GlobalFunctions.Symbolic_Link import link


class Json_To_CSV:
    df_json = pd.DataFrame()

    def __init__(self, path):
        self.df_json = self.version_image_json(path)

    @staticmethod
    def version_image_json(path: str):
        # gets list of versions
        version_list = os.listdir(path)

        version_image_json_list = list()  # list of each version's list of jsons created by running each image
        for v in version_list:
            # gets all jsons in this versions folder
            path_to_json_files = path + v
            image_jsons_list = [filename for filename in os.listdir(path_to_json_files) if filename.endswith('.json')]

            json_per_image_list = list()  # list of all the json texts for one version
            for image_json in image_jsons_list:
                try:
                    # open this version, this images json file that holds info about the vuln this versions found in this image
                    with open(os.path.join(path_to_json_files, image_json), 'r') as json_file:
                        a = json.loads(json_file.read())
                        json_per_image_list.append(a)
                except:
                    print(os.path.join(path_to_json_files, image_json))
            version_image_json_list.append(json_per_image_list)

        # creating a data frame with the versions and their corresponding list(list()) of each images json.
        df = pd.DataFrame(list(zip(version_list, version_image_json_list)),
                          columns=['version', 'json_list'])

        return df

    @staticmethod
    def vuln_relation_investigation(df, difference_array):
        """
        Here we look into the vulns from either grype or trivy and investigate how they handle them/ mainly grype
        :param difference_array:
        :param df:pd.DataFrame(columns=['image_name', 'vuln_id', 'severity', 'count'])
        """
        for i, vuln in df.iterrows():  # for each vuln in the image
            if 'CVE' not in vuln['vuln_id'] and 'NA' not in vuln[
                'vuln_id']:  # we want cve form and na is fine as well so skip over if vuln is one
                # if 'NA' not in vuln['vuln_id']:
                # gets info on the vuln from the open source vulnerabilities databases
                response = requests.get("https://api.osv.dev/v1/vulns/" + vuln['vuln_id']).text
                if 'aliases' in response:  # if there is an aliases for this vuln, we want to replace this vuln with its aliases or at least check it out
                    list_things = response.split(",")  # response long string of info about the vuln
                    for s in list_things:
                        if 'aliases' in s:  # we only want to info about related vulns
                            # just the tedious work of splitting a string
                            aliases_list = (s.split(":", 1)[1]
                                            .replace('[', '').replace(']', '')
                                            .replace('"', '')
                                            .split(','))
                            if len(aliases_list) > 1:
                                print(aliases_list)  # just a check if there ever is multiple aliases for the same vuln
                            for a in aliases_list:  # occasionally there is more than one aliases for the same vuln, we go through all of them
                                # if this goes off then the same vuln might be getting reported under different names
                                if a in df.values:
                                    index_vuln_id = df[df['vuln_id'] == a].index
                                    current_vuln = df.loc[index_vuln_id]

                                    # for a bar graph counting quantities at different disagreements, we add 50 because that's where the "zero" count will be.
                                    difference_array[50 + vuln['count'] - current_vuln['count'].values[0]] = \
                                        difference_array[50+vuln['count'] - current_vuln['count'].values[0]] + 1
                                    if vuln['count'] != current_vuln['count'].values[
                                        0]:  # I expected same number but might not be true.
                                        print("vuln:    " + str(vuln['vuln_id']) + " count: " + str(vuln['count']))
                                        print("aliases: " + current_vuln['vuln_id'].values[0] + " count: " + str(
                                            current_vuln['count'].values[0]))
                                        print(" ")

                else:
                    pass
                    # print(vuln['vuln_id'] + " has no aliases")
            else:
                pass
                # print(vuln['vuln_id'])
        return difference_array

    @staticmethod
    def save_data_to_file(v: str, tool: str, df: pd.DataFrame,):

        outpath_directory = str(Path(sys.path[0]).absolute().parent) + '/04_product/' + tool + '/'

        # if the directory doesn't exist yet create it
        if not os.path.exists(outpath_directory):
            os.makedirs(outpath_directory)

        df.to_csv(outpath_directory + v + '.csv')

        # link this output to the input of next step iff not already done, which we check by seeming if shadow folder exists because it's created when linked
        path = str(Path(sys.path[0]).absolute().parent) + '/04_product/' + tool + '/'
        shadow_path = str(Path(sys.path[0]).absolute().parent.parent) + "/04_DataAnalysis/01_input/"+tool
        if not os.path.exists(shadow_path):
            link(path, shadow_path)