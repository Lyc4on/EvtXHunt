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
    "EventData_RuleName", "EventData_EventTime", "EventData_Process_GUID", "EventData_ProcessID",
    "EventData_Image", "EventData_FileVersion", "EventData_Description", "EventData_Product", 
    "EventData_Company", "EventData_OriginalFileName", "EventData_CommandLine",
    "EventData_CurrentDirectory", "EventData_User", "EventData_LoginGUID", 
    "EventData_LogonId", "EventData_TerminalSessionID", "EventData_IntegrityLevel",
    "EventData_Hashes", "EventData_ParrentProcessGUID", "EventData_ParentProcessID",
    "EventData_ParentImage", "EventData_ParrentCommandLine"
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
    # No provide_identifier and no strings
    for i in range(0, evtx_file.get_number_of_records()):
        evtx_record = evtx_file.get_record(i)
        evtx_record = xmltodict.parse(evtx_record.get_xml_string())
        # evtx_record['Event']['@xmlns']
        provName = evtx_record['Event']['System']['Provider']['@Name']
        provGUID = evtx_record['Event']['System']['Provider']['@Guid']
        sysEventID = evtx_record['Event']['System']['EventID']
        version = evtx_record['Event']['System']['Version']
        level = evtx_record['Event']['System']['Level']
        task = evtx_record['Event']['System']['Task']
        opcode = evtx_record['Event']['System']['Opcode']
        keywords = evtx_record['Event']['System']['Keywords']
        timecreated = evtx_record['Event']['System']['TimeCreated']['@SystemTime']
        eventRecID = evtx_record['Event']['System']['EventRecordID']
        
        if evtx_record['Event']['System']['Correlation'] != None:
            if evtx_record['Event']['System']['Correlation'][0] != None:
                cor_activityID = evtx_record['Event']['System']['Correlation'][0]
            else:
                cor_activityID = ""

            if evtx_record['Event']['System']['Correlation'][1] != None:
                cor_relatedActID = evtx_record['Event']['System']['Correlation'][1]
            else:
                cor_relatedActID = ""
        else:
            cor_activityID = ""
            cor_relatedActID = ""

        exec_pid = evtx_record['Event']['System']['Execution']['@ProcessID']
        exec_tid = evtx_record['Event']['System']['Execution']['@ThreadID']
        
        channel = evtx_record['Event']['System']['Channel']
        computer = evtx_record['Event']['System']['Computer']
        sec_uid = evtx_record['Event']['System']['Security']['@UserID']        

        if len(evtx_record['Event']['EventData']['Data'][0]) > 1:
            #print(evtx_record['Event']['EventData']['Data'][0])
            rulename = evtx_record['Event']['EventData']['Data'][0]
        else:
            rulename = ""

        
        # for e in evtx_record['Event']['EventData']['Data']:
        #     if e == None:
        #         print("Null")
        #     else: print(e.values())
        #print(evtxDF.to_string())


    # Parsing and normalizing yml data to json
    with open(args.rule) as r:
        rule = yaml.load(r, Loader=yaml.FullLoader)
    # print(rule)
    sigmaData = json_normalize(rule)
    # print(sigmaData)

    # Creating pandas DataFrame to emulate sigma database
    sigmaDF = pd.DataFrame(sigmaData)
    # print(sigmaDF.to_string())
