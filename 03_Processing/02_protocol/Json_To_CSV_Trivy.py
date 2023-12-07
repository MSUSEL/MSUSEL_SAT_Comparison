import sys
from pathlib import Path
import pandas as pd
from Converting_Json_CSV import Json_To_CSV
import numpy as np


class Json_To_CSV_Trivy(Json_To_CSV):
    df_CSV = pd.DataFrame()  # image, name, id, severity, count

    def __init__(self, path):
        super().__init__(path)
        self._create_data_frame(self.df_json)

    def _create_data_frame(self, df_json):

        for index, row in df_json.iterrows():  # goes through each version
            # each version will get dataframe with all vuln info combined from every version
            df_t = pd.DataFrame(columns=['image_name', 'vuln_id', 'severity', 'count'])

            for i in row['json_list']:  # for each image go through results

                df_image = self._image_vuln_info(i)

                name_list = [i['ArtifactName']] * len(df_image)
                df_image.insert(0, 'image_name', np.array(name_list), True)
                df_t = pd.concat([df_t, df_image])

            self.save_data_to_file(row['version'], "Trivy",
                                   df_t)  # for each version save the data frame out to csv file

    @staticmethod
    def _image_vuln_info(i):
        df_image = pd.DataFrame(columns=['vuln_id', 'severity', 'count'])

        if 'Results' in i:

            for r in i['Results']:

                if "Vulnerabilities" in r:  # results get split into two categories. If ones blank not a big deal
                    # if 'Vulnerabilities' in r:  # if we found vuln's
                    for v in r['Vulnerabilities']:  # go through each vuln found in each image

                        if v['VulnerabilityID'] in df_image.values:  # if we already found this vuln in this image, just update the count

                            index_vuln_id = df_image[df_image['vuln_id'] == v['VulnerabilityID']].index
                            current_vuln_count = df_image.loc[index_vuln_id]['count'].values[0]
                            df_image.loc[index_vuln_id] = [v['VulnerabilityID'], v['Severity'], current_vuln_count + 1]

                            if v['Severity'] != df_image.loc[index_vuln_id]['severity'].values[0]:
                                print("wtf")  # a check for later if this ever happens got to go back and change this statement
                        else:
                            # making a new row of our data frame with vuln id, severity and the total count of times it was found in this image
                            new_row = [v['VulnerabilityID'], v['Severity'], int(1)]
                            df_image.loc[len(df_image.index)] = new_row
                else:
                    pass

        else:
            df_image.loc[0] = ['NA', 'NA', 'NA']

        return df_image


def main():
    Json_To_CSV_Trivy(str(Path(sys.path[0]).absolute().parent) + "/01_input/Trivy/")


main()