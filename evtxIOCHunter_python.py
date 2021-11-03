#!python2
import string
import os
import pyevtx
import argparse
import csv
import yaml
import xmltodict
import pandas as pd
import json
import numpy as np
from pandasql import sqldf
from collections import OrderedDict
from bs4 import BeautifulSoup


if __name__ == "__main__":
	# argparse
	help_msg = "python evtxIOC_prototype.py -f /dir/file"
	parser = argparse.ArgumentParser(description=help_msg, formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument('-f', '--file', type=str, required=True, help="evtx_Folder")
	parser.add_argument('-r', '--rule', type=str, required=True, help="folder containing JSON rules")
	parser.add_argument('-o', '--output', type=str, required=True, help="absolute path to directory")
	args = parser.parse_args()

	eventlog = pd.DataFrame() # DataFrame to store all processes EVTX event entries as a row

	evtx_dir = args.file

	dir_list = [d[0] for d in os.walk(evtx_dir)] # Get all dir and sub dir path into a list
	evtx_dict = {path : [] for path in dir_list} # Init dict to hold {'relative path':[list of files], ...}

	# Setup EVTX folder recursively
	for path in dir_list:
		for file in os.listdir(path):
			if not os.path.isdir(path + '\\' + file):
				evtx_dict[path].append(file)
    
    # Open all the files in evtx_dict
	for path in evtx_dict:
		for file in evtx_dict[path]:
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
				record_dict['FileName'] = file
				record_dict['Provider_Name'] = soup.System.Provider['Name']
				record_dict['Provider_Guid'] = soup.System.Provider['Guid']
				record_dict['EventID'] = soup.System.EventID.string
				record_dict['Version'] = soup.System.Version.string
				record_dict['Level'] = soup.System.Level.string
				record_dict['Task'] = soup.System.Task.string
				record_dict['Opcode'] = soup.System.Opcode.string
				record_dict['Keywords'] = soup.System.Keywords.string
				record_dict['TimeCreated_SystemTime'] = soup.System.TimeCreated['SystemTime']
				record_dict['EventRecordID'] = soup.System.EventRecordID.string
				record_dict['Correlation'] = soup.System.Correlation.string
				record_dict['Execution_ProcessID'] = soup.System.Execution['ProcessID']
				record_dict['Execution_ThreadID'] = soup.System.Execution['ThreadID']
				record_dict['Channel'] = soup.System.Channel.string
				record_dict['Computer'] = soup.System.Computer.string
				record_dict['Security_UserID'] = soup.System.Security['UserID'] if 'UserID' in soup.System.Security else ''
	
                # EventData attribute in record
				for e in soup.findAll('Data'):
					key = string.capwords(e.get('Name'))
					value = e.string
					record_dict[key] = value

				eventlog = eventlog.append(record_dict, ignore_index=True) # record_dict is the row

	output_path = args.output # absolute path eg. C:\Users\nic\Desktop\SIT_Local\evtxIOC\temp\sub
	if not os.path.exists(output_path):
		os.makedirs(output_path)

    # Create dataframe to store a summary of the analysis
	analysisDF = pd.DataFrame()

	json_file = args.rule

	dir_list = [d[0] for d in os.walk(json_file)] # Get all dir and sub dir path into a list
	rule_dict = {path : [] for path in dir_list} # Init dict to hold {'relative path':[list of files], ...}

	# Setup rule folder recursively
	for path in dir_list:
		for file in os.listdir(path):
			if not os.path.isdir(path + '\\' + file):
				rule_dict[path].append(file)

    # Open the JSON file in rule_dict
	print("Hunting for IOC in specified EVTX...\n")
	for path in rule_dict:
		for file in rule_dict[path]:
			with open(path + '\\' + file) as rule:
				# print('Checking EVTX against rules specified in ' + file + '...')
				data=json.load(rule)
			    	# Extract the SQL query for each rule
				for i in range(len(data)):
					unquery = data[i]['rule']
					# Preprocess every SQL query
					cleanquery = str(unquery).replace('[','').replace(']','').replace('\\\\','\\').replace(r"\'\\'",r"'\'").replace(r"(\'",r"('")
					query = cleanquery[2:-1]

					# Try to query the dataframe. If error due to missing columns, pass and move on to the next query.
					try:
						analysis_dict = {
							'Title':'', 'Description':'', 'Count':''
						}
						# Perform SQL query of each rule on evtxDF
						output = sqldf(query,locals())
						output['SIGMA Rule'] = data[i]['title']
						output['SIGMA Description'] = data[i]['description']
						# For each rule that has 1 or more matches, we will create a CSV file containing the relevant log entries 
						if len(output) > 1:
							print(data[i]['title']+": " + str(len(output)) + " matches")
							analysis_dict['Title'] = data[i]['title']
							analysis_dict['Description'] = data[i]['description']
							analysis_dict['Count'] = str(len(output))
							analysisDF = analysisDF.append(analysis_dict, ignore_index=True)
							output.to_csv(os.path.join(output_path,data[i]['title']+'.csv'), encoding='utf-8') 
					except Exception:
						pass

	# Format DataFrame output
    # Sort columns of analysisDF dataframe
	print("\n====================================Final Summary Report====================================\n")
	analysisDF = analysisDF.reindex(columns=['Title','Description','Count'])
	analysisDF.index = analysisDF.index + 1
	print(analysisDF)

    # Write analysisDF to csv file
	analysisDF.to_csv(os.path.join(output_path,'Summary.csv'), encoding='utf-8')
    # Write eventlog dataframe to csv file
	eventlog.to_csv(os.path.join(output_path,'eventlog.csv'), encoding='utf-8')