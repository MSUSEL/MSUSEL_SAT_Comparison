import os
import sys
from pathlib import Path

import pandas as pd
import numpy as np


def reformatting_to_match_given_csvs(path,tool):
    # matching data collected from CVE bin tool a
    # List of csv's where each one has the image a vulnerability was found, the vuln id, severity
    # and number of occurrences in the image.
    # We have a csv for each version of the tool we are studying.
    versions_csv = os.listdir(path)

    tsum = []
    mean = []
    sd = []
    ll = []
    ul = []
    Version = []

    maxf = []
    minf = []

    for v in versions_csv:
        # go through each version and store data.
        proc_data = pd.read_csv(path + v)

        # this is total vulnerabilities found in benchmark repository(all the docker images we are using) for one version.
        count = Count_Per_Image(proc_data.values)[0]
        tsum.append(count.sum())

        mean.append(np.average(count))
        sd.append(count.std())
        ul.append(count.mean() + count.std())
        ll.append(count.mean() - count.std())

        minf.append(Count_Per_Image(proc_data.values)[1])
        maxf.append(Count_Per_Image(proc_data.values)[2])

        v_temp = v[:v.index(".") + len(".") - 1]
        v_temp = v_temp.replace("_",".")
        Version.append(v_temp)  # parsing sting to just have version

    results = pd.DataFrame()

    results['sum'] = tsum
    results['mean'] = mean
    results['sd'] = sd
    results['ll'] = ll
    results['ul'] = ul
    results['Version'] = Version
    results['min'] = minf
    results['max'] = maxf
    # Save the dataframe to a CSV file
    results.to_csv(str(Path(sys.path[0]).absolute().parent)+"/03_incremental/"+tool+'.csv', index=False)

    return results


def Count_Per_Image(data):
    count_per_image = list()
    current_image = data[0][1];
    count_one_image = 0
    min = 999999
    max = 0
    for d in data:
        if d[1].__contains__(current_image):  # adding up counts in each image
            count_one_image = count_one_image + d[4]  # add count of vulnerability to image
        else:
            if count_one_image < min:
                min = count_one_image
            if count_one_image > max:
                max = count_one_image
            count_per_image.append(count_one_image)
            current_image = d[1]
            count_one_image = 0

    return np.array(count_per_image), min, max


def main():
    path_Grype = str(Path(sys.path[0]).absolute().parent) + "\\01_input\\Grype\\"
    reformatting_to_match_given_csvs(path_Grype, "Grype")

    path_Grype = str(Path(sys.path[0]).absolute().parent) + "\\01_input\\Trivy\\"
    reformatting_to_match_given_csvs(path_Grype, "Trivy")

main()