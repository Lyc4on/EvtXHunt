import os
import pyevtx
import Evtx.Evtx as evtx
import argparse
import csv
import yaml
import xmltodict, json
import pandas as pd
from pandas.io.json import json_normalize
import re

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
        evtx_record = evtx_file.get_record(i) # evtx_record = event entry
        evtx_record = xmltodict.parse(evtx_record.get_xml_string())

        # Get all System's sub elements
        systemData = {}
        for i in range(0, len(evtx_record['Event']['System'].values())):
            # Check if System[i] is a dict or just a single element
            if isinstance(evtx_record['Event']['System'].values()[i], dict):
                if len(evtx_record['Event']['System'].values()[i].values()) > 1:
                    print(evtx_record['Event']['System'].values()[i].keys()[0])
                    print(evtx_record['Event']['System'].values()[i].values()[0])
                    print(evtx_record['Event']['System'].values()[i].keys()[1])
                    print(evtx_record['Event']['System'].values()[i].values()[1])
                else:
                    print(evtx_record['Event']['System'].values()[i].keys()[0])
                    print(evtx_record['Event']['System'].values()[i].values()[0])
            else:
                print(evtx_record['Event']['System'].keys()[i])
                print(evtx_record['Event']['System'].values()[i])

        # print(systemData)
        print("\n")

        # Fix cmd output -> {u'4760': u'6844'} || JSON ->Execution : {@ProcessID: 4760, @ThreadID: 6844}
        # print(evtx_record['Event']['System'].values()[10].keys()[0]) # Prints out @ProcessID

        # Get all EventData's sub elements, every event entry in evtx has diff len of EventData, hence a loop is used
        eventData = {}
        for i in range(0, len(evtx_record['Event']['EventData']['Data'])):
            key = evtx_record['Event']['EventData']['Data'][i].values()[0]

            # Check if evtx_record['Event']['EventData']['Data'][i].values() has @Name and #text
            if len(evtx_record['Event']['EventData']['Data'][i].values()) > 1:
                val = evtx_record['Event']['EventData']['Data'][i].values()[1]
                eventData[key] = val
            else:
                eventData[key] = ""
        # print(eventData)

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
