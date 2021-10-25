import Evtx.Evtx as evtx
import os
from bs4 import BeautifulSoup
import argparse
import csv

if __name__ == "__main__":
    # argparse
    cols = ["Event Name","EventID","Level","Time","Computer Name","User ID","Event Data"]
    help_msg = "python evtxIOC_prototype.py -f /dir/file"
    parser = argparse.ArgumentParser(description=help_msg, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-f', '--file', type=str, required=True, help="/dir/file.evtx")
    
    args = parser.parse_args()

    f = open("Events.csv", "w")
    writer = csv.writer(f)
    writer.writerow(cols)
    with evtx.Evtx(args.file) as log:
        for record in log.records():
            row =[]
            soup = BeautifulSoup(record.xml(), 'xml')
            row.extend([soup.Event.name,soup.EventID.string,soup.Level.string,soup.TimeCreated['SystemTime'],soup.Computer.string,soup.Security['UserID'],soup.EventData.string])
            writer.writerow(row)
    
    f.close()
    


        
