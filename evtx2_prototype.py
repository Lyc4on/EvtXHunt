import os
import sys
import pyevtx
import argparse

help_msg = "python evtxIOC_prototype.py -f /dir/file"
parser = argparse.ArgumentParser(description=help_msg, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-f', '--file', type=str, required=True, help="/dir/file.evtx")

args = parser.parse_args()

file_object = open(args.file, "rb")
evtx_file = pyevtx.file()
evtx_file.open_file_object(file_object)

Event_IDs = [4616, 4634]

for i in range (0, evtx_file.get_number_of_records()):
        evtx_record = evtx_file.get_record(i)
        if evtx_record.get_event_identifier() in Event_IDs:
                print(evtx_record.get_computer_name())
                print(evtx_record.get_event_identifier())
                print(evtx_record.get_event_identifier_qualifiers())
                print(evtx_record.get_event_level())
                print(evtx_record.get_identifier())
                print(evtx_record.get_offset())
                print(evtx_record.get_source_name())
                print(evtx_record.get_user_security_identifier())
                print(evtx_record.get_written_time())
                event_string=""
                print(evtx_record.get_number_of_strings())
                for x in range (0, evtx_record.get_number_of_strings()):
                        print(evtx_record.get_string(x))
                print("\n")
