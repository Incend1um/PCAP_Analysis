#Search for the suspected website

import re
import codecs
import binascii

file = "C:\\Users\\edvin\\OneDrive\\Desktop\\Cyber Sec\\CyberSecurity.pcap"
pcapfile = open(file, "rb")

suspsite = []
#Creates a list of strings which end with '.top'

for b in pcapfile:
    mypattern = re.compile(r".*\.top")
    mymatch = mypattern.findall(str(b))
    if mymatch != []:
        suspsite.append(mymatch)
    
for match in suspsite:
    print(match)
    print("\n")


#According to the outputted data, it become appearant that
#The suspected website is "p27dokhpz2n7nvgr.1jw2lx.top"

    






