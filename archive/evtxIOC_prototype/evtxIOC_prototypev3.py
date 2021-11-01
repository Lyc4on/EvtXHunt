import os
import pyevtx
import argparse
import csv

if __name__ == "__main__":
    # argparse
    cols = ["Event Name","EventID","Level","Time","Computer Name","User ID","Event Data"]
    help_msg = "python evtxIOC_prototype.py -f /dir/file"
    parser = argparse.ArgumentParser(description=help_msg, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-f', '--file', type=str, required=True, help="/dir/file.evtx")
    
    args = parser.parse_args()

    file_object = open(args.file, "rb")
    evtx_file = pyevtx.file()
    evtx_file.open_file_object(file_object)

    f = open("Event_Records.csv", "w")
    writer = csv.writer(f)
    writer.writerow(cols)
    for i in range (0, evtx_file.get_number_of_records()):
        row =[]
        evtx_record = evtx_file.get_record(i)
        row.extend([evtx_record.get_source_name(),evtx_record.get_event_identifier(),evtx_record.get_event_level(),evtx_record.get_written_time(),evtx_record.get_computer_name(),evtx_record.get_user_security_identifier(),
        evtx_record.get_identifier(),evtx_record.get_event_identifier_qualifiers(),evtx_record.get_identifier()])
        for x in range (0, evtx_record.get_number_of_strings()):
            row.append(evtx_record.get_string(x))
        writer.writerow(row)
    
    f.close()
    


        
