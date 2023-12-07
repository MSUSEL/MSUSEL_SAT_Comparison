import sys
from pathlib import Path

import numpy as np
import pandas as pd
from matplotlib import pyplot as plt


def plot_versions2(data0, data1, data2, data3):
    tool_versions0 = data0['Version'].values
    sum_values0 = data0['sum'].values
    u0 = np.arange(min(sum_values0) - min(sum_values0) % 1000, max(sum_values0) + 10000, 10000)

    tool_versions1 = data1['Version'].values
    sum_values1 = data1['sum'].values
    ug1 = np.arange(min(sum_values1) - min(sum_values1) % 10000, (int)(max(sum_values1) + 25000), 25000)

    tool_versions2 = data2['Version'].values
    sum_values2 = data2['sum'].values
    ug2 = np.arange((int)(min(sum_values2) - min(sum_values2) % 1000), (int)(max(sum_values2) + 1000), 1000)

    tool_versions3 = data3['Version'].values
    sum_values3 = data3['sum'].values
    ug3 = np.arange((int)(min(sum_values3) - min(sum_values3) % 1000), (int)(max(sum_values3) + 2000), 2000)

    # Plotting
    fig, ax = plt.subplots(2, 2, figsize=(18, 16))  # Increase figure size

    plt.subplots_adjust(left=.12, bottom=.15, right=.95, top=.9, wspace=.4, hspace=0.5)  # Adjust layout parameters

    ax[0, 0].plot(tool_versions0, sum_values0, marker='o', markersize=13, linestyle='-',
                  color="green", alpha=0.6, markerfacecolor="green", markeredgecolor="black", linewidth=8)
    ax[0, 0].set_title("(A) CVE Binary Tool", fontsize="40", loc='left')  # Left-align the title
    ax[0, 0].set_xticks(tool_versions0)
    ax[0, 0].set_xticklabels(tool_versions0, fontsize=20, rotation=50)
    ax[0, 0].set_yticks(u0)
    ax[0, 0].set_yticklabels(u0, fontsize=20, rotation=45)

    ax[0, 1].plot(tool_versions1, sum_values1, marker='o', markersize=13, linestyle='-',
                  color="green", alpha=0.6, markerfacecolor="green", markeredgecolor="black", linewidth=8)
    ax[0, 1].set_title("(B) CWE Checker", fontsize="40", loc='left')  # Left-align the title
    ax[0, 1].set_xticks(tool_versions1)
    ax[0, 1].set_xticklabels(tool_versions1, fontsize=20, rotation=50)
    ax[0, 1].set_yticks(ug1)
    ax[0, 1].set_yticklabels(ug1, fontsize=20, rotation=50)

    ax[1, 0].plot(tool_versions2, sum_values2, marker='o', markersize=13, linestyle='-',
                  color="blue", alpha=0.6, markerfacecolor="blue", markeredgecolor="black", linewidth=8)
    ax[1, 0].set_title("(C) Trivy", fontsize="40", loc='left')  # Left-align the title
    ax[1, 0].set_xticks(tool_versions2[::2])
    ax[1, 0].set_xticklabels(tool_versions2[::2], fontsize=20, rotation=70)
    ax[1, 0].set_yticks(ug2)
    ax[1, 0].set_yticklabels(ug2, fontsize=20, rotation=50)

    ax[1, 1].plot(tool_versions3, sum_values3, marker='o', markersize=13, linestyle='-',
                  color="blue", alpha=0.6, markerfacecolor="blue", markeredgecolor="black", linewidth=8)
    ax[1, 1].set_title("(D) Grype", fontsize="40", loc='left')  # Left-align the title
    ax[1, 1].set_xticks(tool_versions3[::2])
    ax[1, 1].set_xticklabels(tool_versions3[::2], fontsize=20, rotation=70)
    ax[1, 1].set_yticks(ug3)
    ax[1, 1].set_yticklabels(ug3, fontsize=20, rotation=50)

    fig.text(0.5, 0.04, 'Version', va='center', ha='center', fontsize=40)
    fig.text(0.04, 0.5, 'Total Count Of Findings', va='center', ha='center', rotation='vertical', fontsize=40)
    plt.savefig(str(Path(sys.path[0]).absolute().parent)+"/04_product/test.png")  # dpi
    plt.show()

    return


def main():
    # CVE and CWE were collected in different program by Ann Marie Reinhold
    cve_data = pd.read_csv(str(Path(sys.path[0]).absolute().parent)+"/03_incremental/"+"cve_ver_smry.csv",
                           usecols=['sum', 'mean', 'sd', 'll', 'ul', 'Version'])

    cwe_data = pd.read_csv(str(Path(sys.path[0]).absolute().parent)+"/03_incremental/"+"cwe_ver_smry.csv",
                           usecols=['sum', 'mean', 'sd', 'll', 'ul', 'Version'])

    Grype_data = pd.read_csv(str(Path(sys.path[0]).absolute().parent)+"/03_incremental/"+"Grype_smry.csv")

    Trivy_data = pd.read_csv(str(Path(sys.path[0]).absolute().parent)+"/03_incremental/"+"Trivy_smry.csv")

    plot_versions2(cve_data, cwe_data, Trivy_data, Grype_data)


main()

