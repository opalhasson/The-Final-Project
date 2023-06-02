import os
import re
from os import listdir
from os.path import isfile, join
import canvas
import pandas as pd
import zipfile
import json
import requests
import platform
from datetime import datetime
from sklearn import linear_model
from torSearch import CVEsInTOR

# Specify the base directory where you want to store the downloaded and extracted files
base_dir = "nvd"
components_on_pc_file = "components_on_pc.txt"
components_in_NVD_db_file = "components_in_NVD_db.txt"
components_after_comparison_file = "components_after_comparison.txt"
match_found_CVEs_file = "match_found_CVEs.txt"


# todo: what it spouse to do?
def predicted_cve_score(cve_dict_list, found_cves):
    data = []
    for cve in found_cves:

        match = re.findall(r'\d+', cve)
        x = int(match[0])
        y = int(match[1])

        cve_item = cve_dict_list[x]['CVE_Items'][y]
        cve_id = cve_item['cve']['CVE_data_meta']['ID']
        problemtype = cve_item.get('cve', {}).get('problemtype', {})
        if problemtype:
            problemtype_data = problemtype.get('problemtype_data', [])
            if problemtype_data:
                cwe_id_list = problemtype_data[0].get('description', [])
                if cwe_id_list:
                    cwe_id = cwe_id_list[0].get('value', None)
                else:
                    cwe_id = None
            else:
                cwe_id = None
        else:
            cwe_id = None
        impact = cve_item.get('impact', {})
        base_metric_v2 = impact.get('baseMetricV2', {})
        cvss_v2 = base_metric_v2.get('cvssV2', {})
        base_score = cvss_v2.get('baseScore', None)
        exploitability_score = base_metric_v2.get('exploitabilityScore', None)
        impact_score = base_metric_v2.get('impactScore', None)
        severity = base_metric_v2.get('severity', None)
        data.append(
            [cve_id, base_score,
             exploitability_score, impact_score, severity])

    # Create the dataframe
    df = pd.DataFrame(data, columns=['cve_id', 'base_score', 'exploitability_score', 'impact_score', 'severity'])

    # Write the dataframe to a CSV file
    df.to_csv('mydata.csv', index=False)

    # Read the CSV file into a new dataframe
    df_new = pd.read_csv('mydata.csv')

    # Set display options for Pandas
    pd.set_option('display.max_rows', None)
    pd.set_option('display.max_columns', None)
    pd.set_option('colheader_justify', 'center')

    # Get the string representation of the dataframe with aligned columns
    table_string = df.to_string(index=False, header=True)

    # Write the table string to the output file
    with open('mydata.txt', 'w') as f:
        f.write(table_string)

    # Read the CSV file into a pandas dataframe
    df = pd.read_csv('mydata.csv')

    # Write the updated dataframe back to the CSV file
    df.to_csv('mydata.csv', index=False)

    # Multiple Regression

    # Load data from CSV file
    df = pd.read_csv("mydata.csv")

    # Convert the severity field to numerical form
    df['severity'] = df['severity'].map({'LOW': 0, 'MEDIUM': 5, 'HIGH': 10})

    # Convert all variables in X to int and replace NaN with 0
    X = df[['exploitability_score', 'impact_score', 'severity']].fillna(0).astype(int)

    # Select target variable y
    y = df['base_score'].fillna(0).astype(int)

    regr = linear_model.LinearRegression()
    regr.fit(X, y)
    y_pred = regr.predict(X)

    df['predicted_cve_score'] = y_pred

    df.to_csv("predicted_mydata.csv", index=False)


def predicted_computer_score(cve_dict_list, found_cves):
    # calculate the average of predicted_cve_score
    predicted_cve_score(cve_dict_list, found_cves)
    df = pd.read_csv("predicted_mydata.csv")
    avg_score = df['predicted_cve_score'].mean()
    return avg_score


def riskAssessmentWay(scanType, cve_dict_list):
    found_cves = readFromFile("fileToLiran.txt")
    if scanType == 'TotalRiskAssessment':
        cves = []
        for cve in found_cves:
            cves.append(cve.split(':')[1].strip())
        return predicted_computer_score(cve_dict_list, cves)
    else:
        found_cves.sort()
        component = found_cves[0].split(':')[0].strip()
        cves = []
        cves_per_comp = []
        for cve in found_cves:
            comp = cve.split(':')[0].strip()
            if component != comp:
                cves.append(component)
                cves.append(predicted_computer_score(cve_dict_list, cves_per_comp))
                cves_per_comp = []
                component = comp
                cves_per_comp.append(cve.split(':')[1].strip())
            else:
                cves_per_comp.append(cve.split(':')[1].strip())
        return cves


def downloadNVDdbFiles():
    r = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
    for filename in re.findall("nvdcve-1.1-202[1-3]\.json\.zip", r.text):
        print(filename)

        r_file = requests.get("https://static.nvd.nist.gov/feeds/json/cve/1.1/" + filename, stream=True)
        with open(join(base_dir, filename), 'wb') as f:
            for chunk in r_file:
                f.write(chunk)


def NVDdbFilesToJson():
    files = [f for f in listdir(base_dir) if isfile(join(base_dir, f))]
    files.sort()
    cve_dict_list = []
    for file in files:
        archive = zipfile.ZipFile(join(base_dir, file), 'r')
        jsonfile = archive.open(archive.namelist()[0])
        cve_dict = json.loads(jsonfile.read())
        jsonfile.close()
        cve_dict_list.append(cve_dict)
    return cve_dict_list


def componentsOnPC(os_name):
    if os_name == 'Darwin':
        writeComponentsOnPCtxt(os.popen("find / -iname '*.app'").read().splitlines())
    elif os_name == 'Windows':
        writeComponentsOnPCtxt(os.popen('dir /s /b "C:\*.exe"').read().splitlines())
    else:
        return None


def writeComponentsOnPCtxt(output):
    with open(components_on_pc_file, "w") as f:
        for line in output:
            app_name = os.path.basename(line.strip())[:-4]
            f.write(app_name + "\n")

    with open(components_on_pc_file, 'r') as f:
        program_names = list(set(line.strip() for line in f))

    with open(components_on_pc_file, 'w') as f:
        f.write('\n'.join(program_names))


def readFromFile(fileName):
    try:
        with open(fileName, "r") as file:
            components = [line.strip() for line in file]
            return components
    except FileNotFoundError:
        return ""


def componentsInNVD(cve_dict_list):
    f = open(components_in_NVD_db_file, "w")
    for cve_dict in cve_dict_list:
        num_of_CVEs = len(json.loads(json.dumps(cve_dict['CVE_Items'])))

        for i in range(num_of_CVEs):
            if (len(json.loads(json.dumps(cve_dict['CVE_Items'][i]['configurations']['nodes']))) != 0):
                num_of_cpe_match = len(
                    json.loads(json.dumps(cve_dict['CVE_Items'][i]['configurations']['nodes'][0]['cpe_match'])))
            else:
                num_of_cpe_match = 0

            for k in range(num_of_cpe_match):
                f.write(json.dumps(
                    cve_dict['CVE_Items'][i]['configurations']['nodes'][0]['cpe_match'][k]['cpe23Uri']).split(":")[
                            3] + "\n")
                f.write(json.dumps(
                    cve_dict['CVE_Items'][i]['configurations']['nodes'][0]['cpe_match'][k]['cpe23Uri']).split(":")[
                            4] + "\n")

    with open(components_in_NVD_db_file, 'r') as f:
        program_names = [line.strip() for line in f]

    # Remove duplicates
    unique_program_names = set(program_names)

    # Write unique program names back to file
    with open(components_in_NVD_db_file, 'w') as f:
        f.write('\n'.join(unique_program_names))


def comparisonNVDcomponentsToPCcomponents():
    with open(components_in_NVD_db_file, 'r') as f:
        program_names = [line.strip() for line in f]
    print("opal")

    with open(components_on_pc_file, 'r') as f:
        pc_program = [line.strip() for line in f]

    programs = []
    for comp in program_names:
        for prog in pc_program:
            if len(comp) > 3 and comp.lower() in prog.lower():
                programs.append(comp)

    setPrograms = set(programs)
    with open(components_after_comparison_file, 'w') as f:
        f.write('\n'.join(setPrograms))


def SearchCVEsForComponents(components, cve_dict_list):
    f = open(match_found_CVEs_file, "w")
    fl = open("fileToLiran.txt", "w")

    cts = []

    print("start search")
    p = 1
    cves_path = []
    # Search for vulnerabilities in the NVD database for each component
    for cve_dict in cve_dict_list:
        matches = []
        # f.write("\nMatched vulnerabilities in 202" + p._str_() + ":\n")
        p += 1
        num_of_CVEs = len(json.loads(json.dumps(cve_dict['CVE_Items'])))

        for i in range(num_of_CVEs):
            if (len(json.loads(json.dumps(cve_dict['CVE_Items'][i]['configurations']['nodes']))) != 0):
                num_of_cpe_match = len(
                    json.loads(json.dumps(cve_dict['CVE_Items'][i]['configurations']['nodes'][0]['cpe_match'])))
            else:
                num_of_cpe_match = 0

            for k in range(num_of_cpe_match):
                for comp in components:
                    if comp in json.dumps(
                            cve_dict['CVE_Items'][i]['configurations']['nodes'][0]['cpe_match'][k]['cpe23Uri']):
                        matches.append(json.dumps(
                            cve_dict['CVE_Items'][i]['cve']['CVE_data_meta']['ID']).replace("\"", ""))
                        cts.append(comp)
                        cves_path.append(
                            comp + " : cve_dict_list[" + (p - 2)._str() + "]['CVE_Items'][" + i.str_() + "]")
        f.write('\n'.join(set(matches)))
        fl.write('\n'.join(cves_path))
    # components = set(components)
    print('\n'.join(set(cts)))


def convert_txt_to_pdf(txt_file_path, pdf_file_path):
    # Create a new PDF file and set its metadata
    pdf = canvas.Canvas(pdf_file_path)
    pdf.setTitle("Converted PDF")

    # Open the text file and read its contents
    with open(txt_file_path, "r") as f:
        txt_content = f.read()

    # Set the font size and leading (line spacing)
    pdf.setFont("Helvetica", 12)
    leading = 14

    # Split the text into lines and draw them on the PDF
    lines = txt_content.split("\n")
    y = 800  # Starting y position
    for line in lines:
        pdf.drawString(50, y, line)
        y -= leading

    # Save the PDF file and close it
    pdf.save()


def genarateReportFrum(risk_assessment_way, cve_dict_list):
    f = open("report.txt", "w")
    f.write("Risk Assessment\n\nDate of assessment : " + datetime.today().__str__() + "\n")
    result = riskAssessmentWay(risk_assessment_way,cve_dict_list)
    if risk_assessment_way == 'TotalRiskAssessment' :
        f.write("The total risk assessment of your pc is " + result.__str__() + "\n")
    else :
        f.write("The Risk Assessment Per Component of your pc is \n")
        for i in range(0, len(result), 2):
            name = result[i]
            value = result[i + 1]
            f.write(f"{name}: {value}\n")

    f.write("CVEs the were found relevent to your pc's components:\n")
    cves_list = readFromFile(match_found_CVEs_file)

    num_columns = 6
    row_format = '{:<15}' * num_columns

    for i in range(0, len(cves_list), num_columns):
        row = cves_list[i:i + num_columns]
        f.write(row_format.format(*row) + '\n')

    CVEsInTOR = readFromFile("CVEsInTOR.txt")
    f.write("\nCVEs that were mentioned in the darkweb :\n")
    for i in range(0, len(CVEsInTOR), num_columns):
        row = CVEsInTOR[i:i + num_columns]
        f.write(row_format.format(*row) + '\n')

    f.close()


def NVDsearch(risk_assessment_way):
    dir = os.listdir(base_dir)
    print(dir)

    if len(dir) == 1:
        print("Empty directory\n")
        downloadNVDdbFiles()
    else:
        print("Not empty directory\n")

    # list of the NVD database  by years
    cve_dict_list = NVDdbFilesToJson()

    # scan the computer:
    # Determine operating system
    os_name = platform.system()
    if (os_name != 'Windows' and os_name != 'Darwin'):
        f = open("report.txt", "w")
        f.write("Risk Assessment\n\nDate of assessment : " + datetime.today().__str__() + "\n")
        f.write(
            "Unfortunately, our system does not support your operating system. Windows and macOS support systems.\n")
        f.close()
    else:
        components = readFromFile(components_after_comparison_file)
        if components == "":
            if readFromFile(components_on_pc_file) == "":
                componentsOnPC(os_name)
                print("System components written to " + components_on_pc_file)
            if readFromFile(components_in_NVD_db_file) == "":
                componentsInNVD(cve_dict_list)
                print("System components written to " + components_in_NVD_db_file)
            comparisonNVDcomponentsToPCcomponents()
            print("System components written to " + components_after_comparison_file)
            components = readFromFile(components_after_comparison_file)

        # search for vulnerabilities associated with a list of components installed on your computer
        if readFromFile(match_found_CVEs_file) == "":
            SearchCVEsForComponents(components, cve_dict_list)

        CVEsInTOR()
        genarateReportFrum(risk_assessment_way, cve_dict_list)

def test():
    lines = []

    with open('components_in_NVD_db.txt', 'r') as file:
        for line in file:
            if line != "mail\n" and line != "panel\n" and line != "discovery\n" and line != "hive\n" \
                    and line != "view\n" and line != "rooms\n" and line != "google\n" and line != "reminder\n" and line != "rust\n" and line != "count\n":
                lines.append(line)

    with open('components_in_NVD_db.txt', 'w') as f:
        f.write(''.join(lines))


