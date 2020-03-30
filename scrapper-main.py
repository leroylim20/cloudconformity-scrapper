import datetime
import os
import time

import pandas as pd
import requests
from bs4 import BeautifulSoup

# Compliance Constants
CIS = 0
APRA = 1
MAS = 2
PCI_DSS = 3
NIST = 4
HIPAA = 5
GDPR = 6

# List all files in a directory using scandir()
fileNames = [entry.path for entry in os.scandir(".") if entry.is_file()]
i = 1
for file in fileNames:
    print(str(i) + file)
    i += 1

# Get file path
choice = input("Select file: ")
file_path = fileNames[int(choice) - 1]

# Get output file name
output_filename = input("Input output file name (without .csv) [Default: output.csv if blank]: ")
if not output_filename:
    output_filename = "output.csv"
else:
    output_filename = output_filename + ".csv"

# Read source report
cc_report_df = pd.read_csv(file_path)

# Filter by failures
cc_report_failures_df = cc_report_df[cc_report_df['Check Status'] == "FAILURE"]

# Free up memory
del fileNames
del choice
del cc_report_df

# Remove duplicate in working set
resolution_link_df = cc_report_failures_df[["Resolution Page"]].drop_duplicates()

resolution_list = []
last_key = resolution_link_df.last_valid_index()

# Iterate all rows
print("Collecting remediation steps...")
print("Estimated time: " + str(datetime.timedelta(seconds=len(resolution_link_df.index) * 2)))
for key, link in resolution_link_df[["Resolution Page"]].iterrows():
    # Get remediation step from URL
    url = link["Resolution Page"]
    response = requests.get(url)
    rule = BeautifulSoup(response.text, "html.parser")
    try:
        resolution = rule.select("#sub-header > div > div > div > div.box.text > p:nth-child(3)")[0].get_text().strip()
    except IndexError:
        resolution = rule.select("#sub-header > div > div > div > div.box.text > p")[0].get_text().strip()
        print("Extraction URL: " + url)
    # Get compliance from URL
    compliance_list = [0] * 7
    compliance = rule.select("#sub-header > div > div > div > div.box.text > ul > li")
    for compliance_item in compliance:
        compliance_text = compliance_item.get_text().strip()
        if compliance_text == "The Center of Internet Security AWS Foundations Benchmark":
            compliance_list[CIS] = 1
        elif compliance_text == "APRA":
            compliance_list[APRA] = 1
        elif compliance_text == "Payment Card Industry Data Security Standard (PCI DSS)":
            compliance_list[PCI_DSS] = 1
        elif compliance_text == "MAS":
            compliance_list[MAS] = 1
        elif compliance_text == "National Institute of Standards and Technology (NIST)":
            compliance_list[NIST] = 1
        elif compliance_text == "Health Insurance Portability and Accountability Act (HIPAA)":
            compliance_list[HIPAA] = 1
        elif compliance_text == "General Data Protection Regulation (GDPR)":
            compliance_list[GDPR] = 1
        else:
            print("No labels identified - " + compliance_text)
    # Append to working list
    list_item = [url, resolution]
    list_item.extend(compliance_list)
    resolution_list.append(list_item)
    print("{:0.2f}%\n".format(key / last_key * 100))
    time.sleep(2)  # Pause to prevent being blocked, 2 secs for good measure

# Merge into df
print("Exporting...")
resolution_df = pd.DataFrame(resolution_list,
                             columns=["Resolution Page", "Remediation", "CIS", "APRA", "PCI_DSS", "MAS", "NIST",
                                      "HIPAA", "GDPR"])
merged_df = pd.merge(cc_report_failures_df, resolution_df, on="Resolution Page", how="outer")
# Export to csv
merged_df.to_csv(output_filename)
