import os
import pyevtx
import argparse
import csv
import yaml
import xmltodict, json
import pandas as pd
from pandas.io.json import json_normalize
from bs4 import BeautifulSoup

if __name__ == "__main__":
    cols = [
    "Provider_Name", "Provider_GUID", 
    "EventID", "Version", "Level", "Task", "Opcode", "Keywords", 
    "TimeCreated", "EventRecordID", "Correlation_ActivityID", "Correlation_RelatedActivityID", 
    "Execution_ProcessID", "Execution_ThreadID",
    "Channel", "Computer", "Security_UserID", 
    "RuleName", "UtcTime", "ProcessId", "Image", "FileVersion", "Description", "Product", 
    "Company", "OriginalFileName", "CommandLine",
    "CurrentDirectory", "User", "LoginGuid", 
    "LogonId", "TerminalSessionId", "IntegrityLevel",
    "Hashes", "ParentProcessGuid", "ParentProcessId",
    "ParentImage", "ParentCommandLine"
    ]
    
    # argparse
    help_msg = "python evtxIOC_prototype.py -f /dir/file"
    parser = argparse.ArgumentParser(description=help_msg, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-f', '--file', type=str, required=True, help="/dir/file.evtx")
    parser.add_argument('-r', '--rule', type=str, required=True, help="/dir/file.yml")

    args = parser.parse_args()

    # Setup of Evtx Dataframe columns : may want to include filepath of event entry to faciliate easier tracking of flagged out IOC
    evtxDF = pd.DataFrame(columns=cols)


    file_object = open(args.file, "rb")
    evtx_file = pyevtx.file()
    evtx_file.open_file_object(file_object)
    
    # Getting all fields in Evtx event entry
    for i in range(0, evtx_file.get_number_of_records()):
        # event Entry has 2 components: System and EventData
        record_dict = {}
        
        evtx_record = evtx_file.get_record(i) # evtx_record = event entry
        # evtx_record = xmltodict.parse(evtx_record.get_xml_string())

        evtx_record = evtx_record.get_xml_string()
        # Get all System's sub elements
        soup = BeautifulSoup(evtx_record, 'xml')
        
        provName = soup.System.Provider['Name']
        provGUID = soup.System.Provider['Guid']
        eventID = soup.System.EventID
        version = soup.System.Version
        level = soup.System.Level
        task = soup.System.Task
        opcode = soup.System.Opcode
        keywords = soup.System.Keywords
        timeCreated = soup.System.TimeCreated['SystemTime']
        eventRecID = soup.System.EventRecordID
        correlation = soup.System.Correlation
        execPID = soup.System.Execution['ProcessID']
        execTID = soup.System.Execution['ThreadID']
        channel = soup.System.Channel
        computer = soup.System.Computer
        securityUID = soup.System.Security['UserID']

        # eventData_arr = soup.EventData.findAll('Data')
        print(soup.EventData.Data.string)
        # print(eventData_arr)
        # Colidate variables into a dictionary before inserting to datafrace

    # Parsing and normalizing yml data to json
    with open(args.rule) as r:
        rule = yaml.load(r, Loader=yaml.FullLoader)
    # print(rule)
    sigmaData = json_normalize(rule)
    # print(sigmaData)

    # Creating pandas DataFrame to emulate sigma database
    sigmaDF = pd.DataFrame(sigmaData)
    # print(sigmaDF.to_string())
