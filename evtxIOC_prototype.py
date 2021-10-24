import Evtx.Evtx as evtx
import os
from bs4 import BeautifulSoup
import argparse

if __name__ == "__main__":
    # argparse
    help_msg = "python evtxIOC_prototype.py -f /dir/file"
    parser = argparse.ArgumentParser(description=help_msg, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-f', '--file', type=str, required=True, help="/dir/file.evtx")
    
    args = parser.parse_args()

    with evtx.Evtx(args.file) as log:
        for record in log.records():
            soup = BeautifulSoup(record.xml(), 'xml')
            if (soup.EventID.string == "4688"): print(soup)
            if (soup.EventID.string == "4670"): print(soup)
            if (soup.EventID.string == "4672"): print(soup)
            if (soup.EventID.string == "1006"): print(soup)
            if (soup.EventID.string == "1007"): print(soup)
            if (soup.EventID.string == "11"): print(soup)