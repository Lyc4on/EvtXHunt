import Evtx.evtx as evtx
import os
from bs4 import BeautifulSoup


if __name__ == "__main__":
    with evtx.Evtx("/mnt/e/Desktop/Security.evtx") as log:
        for record in log.records():
            soup = BeautifulSoup(record.xml(), 'xml')
            if (soup.EventID.string == "4688"): print(soup)
            if (soup.EventID.string == "4670"): print(soup)
            if (soup.EventID.string == "4672"): print(soup)
            if (soup.EventID.string == "1006"): print(soup)
            if (soup.EventID.string == "1007"): print(soup)
            
        
