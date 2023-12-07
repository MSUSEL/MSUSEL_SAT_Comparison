# SAT_comparison
A basic comparison of static analysis tools, Grype and Trivy, over versions. 

Set up to run:
Step One:
First, download the Docker Images you want to investigate; we used the Docker Images found here: https://docs.google.com/spreadsheets/d/1sAnFsmPLqTu9od7Hvh9Y5mlzUGNf6Dcq4-OepRYX83Y/edit?usp=drive_link .
Global Function contains download_images.py that can assist in this process. 

Step Two: 
Create a .txt file with the version of each tool Grype and Trivy that you want to investigate. We uploaded the versions we used in 01_ToolVersions/01_input for both Grype and Trivy. 

Step Three:
Download your static databases for each tool, 01_ToolVersions/03_incremental has functions to help, or use our static databases collected on 11/03/2023. 
Trivy Database: https://drive.google.com/file/d/1PxFNMYe2x49_F-Z2QvtxrZJNPBJPuyhj/view?usp=drive_link
Grype Database: https://drive.google.com/drive/folders/1ljZh7k8---i7zahbJttfL_fMzZpjoM3K?usp=drive_link
We put Trivy's database in 01_ToolVersions/03_incremental and Grypes on our local machine; just make sure you point in Grype_Versions_Download and Trivy_Versions_Download that you point to the correct database location. 

Step Four:
Just run through the pipeline scripts that need to run in the protocol folders. 


Goals: 
This program can download different versions of the tools Grype and Trivy and, given a list of Docker Images, download those as well. It runs each image through each version of each tool. We process the tool's output JSON files and collect info about vulnerability IDs, images found in, severities, and the total count of vulnerabilities in versions. The goal is to investigate and understand the two tools better, specifically their differences and the effects of those differences. We also hope to gain insight into the challenges these tools' developers face.

Note:
In the 04_DataAnalysis/02_protocol the graphing section we pulled in info from previous work on CVE-Bin Tool and CWE Checker as well to study.
