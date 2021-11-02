import os
import pyevtx
import argparse
import csv
import yaml
import xmltodict
import pandas as pd
from bs4 import BeautifulSoup
from pandas.io.json import json_normalize


if __name__ == "__main__":    
    # argparse
    help_msg = "python evtxIOC_prototype.py -f /dir/file"
    parser = argparse.ArgumentParser(description=help_msg, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-f', '--file', type=str, required=True, help="evtx_Folder")
    parser.add_argument('-r', '--rule', type=str, required=True, help="rules_Folder")
    args = parser.parse_args()
    # Setup of Evtx Dataframe columns : may want to include filepath of event entry to faciliate easier tracking of flagged out IOC
    evtxDF = pd.DataFrame()

    evtx_dir = args.file

    dir_list = [d[0] for d in os.walk(evtx_dir)] # Get all dir and sub dir path into a list
    evtx_dict = {path : [] for path in dir_list} # Init dict to hold {'relative path':[list of files], ...}

    for path in dir_list:
        for file in os.listdir(path):
            if not os.path.isdir(path + '\\' + file):
                evtx_dict[path].append(file)
    # print(evtx_dict)
    # Open all the files in evtx_dict
    for path in evtx_dict:
        print(path)
        for file in evtx_dict[path]:
            print(file)
            file_object = open(path + '\\' + file, "rb")
            evtx_file = pyevtx.file()
            evtx_file.open_file_object(file_object)
    
            # Getting all fields in Evtx event entry
            for i in range(0, evtx_file.get_number_of_records()):
                # event Entry has 2 components: System and EventData
                record_dict = {} # each iteration will build a dict(row for evtxDF)
                evtx_record = evtx_file.get_record(i) # evtx_record = event entry
                evtx_record = evtx_record.get_xml_string()

                # Get all System's sub elements
                soup = BeautifulSoup(evtx_record, 'xml')
                # System attribute in record, always check if key/value exist in the attribute, if not then assign empty string
                record_dict['s.Provider_Name'] = soup.System.Provider['Name']
                record_dict['s.Provider_Guid'] = soup.System.Provider['Guid']
                record_dict['s.EventID'] = soup.System.EventID.string
                record_dict['s.Version'] = soup.System.Version.string
                record_dict['s.Level'] = soup.System.Level.string
                record_dict['s.Task'] = soup.System.Task.string
                record_dict['s.Opcode'] = soup.System.Opcode.string
                record_dict['s.Keywords'] = soup.System.Keywords.string
                record_dict['s.TimeCreated_SystemTime'] = soup.System.TimeCreated['SystemTime']
                record_dict['s.EventRecordID'] = soup.System.EventRecordID.string
                record_dict['s.Correlation'] = soup.System.Correlation.string
                record_dict['s.Execution_ProcessID'] = soup.System.Execution['ProcessID']
                record_dict['s.Execution_ThreadID'] = soup.System.Execution['ThreadID']
                record_dict['s.Channel'] = soup.System.Channel.string
                record_dict['s.Computer'] = soup.System.Computer.string
                record_dict['s.Security_UserID'] = soup.System.Security['UserID'] if 'UserID' in soup.System.Security else ''

                # EventData attribute in record
                # print(type(soup.EventData))
                for e in soup.findAll('Data'):
                    key = 'e.' + e.get('Name')
                    value = e.string
                    record_dict[key] = value

                evtxDF = evtxDF.append(record_dict, ignore_index=True) # record_dict is the row
                # print(record_dict)

    # Sigma dict will be used to hold each yaml signature before adding to the sigmaDF as a row
    # Note that some yaml will not use all the fields (eg. title, etc) so leave blank if it is the case 
    root_dir = args.rule

    dir_list = [d[0] for d in os.walk(root_dir)] # Get all dir and sub dir path into a list
    rule_dict = {path : [] for path in dir_list} # Init dict to hold {'relative path':[list of files], ...}

    for path in dir_list:
        for file in os.listdir(path):
            if not os.path.isdir(path + '\\' + file):
                rule_dict[path].append(file)

    # Creating pandas DataFrame to emulate sigma database
    sigmaDF = pd.DataFrame()

    # Find all detection distinct keys
    dist_keys = []
    sqlDF = pd.DataFrame()

    # Open all the files in rule_dict
    for path in rule_dict:
        for file in rule_dict[path]:
            with open(path + '\\' + file) as rule:
                rule = yaml.load(rule, Loader=yaml.FullLoader)
                # print(path + '\\' + file)
                # print(type(rule['detection']['selection']))
                # print(rule['detection']['selection'])
                d = rule['detection']
                
                if 'selection' not in d:
                    # query_row = json_normalize(d, sep='_')
                    # query_row = query_row.to_dict(orient='records')[0]
                    # print(query_row.keys())
                    print(path + '\\' + file)
                    print(d.keys())
                    print('\n')

                # if rule['detection'].keys() not in dist_keys:
                #     dist_keys.append(rule['detection'].keys())

                # print('File Location : ' + path + '\\' + file)
                # Sigma structure can be found at https://github.com/SigmaHQ/sigma/wiki/Specification
                sigma_dict = {
                    'title':'', 'id':'', 'related':'',
                    'status':'', 'description':'', 'author':'',
                    'references':'', 'logsource':'', 'detection':'',
                    'fields':'', 'falsepositives':'', 'level':'', 'tags':''
                }
                for key, value in rule.items():
                    # print(key + ' :: ' + str(value))
                    sigma_dict[key] = value
                sigmaDF = sigmaDF.append(sigma_dict, ignore_index=True) # sigma_dict is the row
                # print(sigma_dict.keys())
            # print('\n')

    print(dist_keys)
    sqlDF.to_csv('sqlDF.csv', encoding='utf-8') 
    # evtxDF.to_csv('evtxDF.csv', encoding='utf-8')
    # sigmaDF.to_csv('sigmaDF.csv', encoding='utf-8')