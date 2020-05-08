#Search for the suspected browser and the keywords used

import re
import codecs
import binascii

file = "C:\\Users\\edvin\\OneDrive\\Desktop\\Cyber Sec\\CyberSecurity.pcap"
pcapfile = open(file, "rb")

suspbrowser = []
#produces a list of strings in the pcap file which start with 'www.' - basically web sites

for i in pcapfile:
    mypattern = re.compile(r"www\..*")
    mymatch = mypattern.findall(str(i))
    if mymatch != []:

        suspbrowser.append(mymatch)
for match in suspbrowser:
    print(match)
    print("\n")

#According to the outputted data, the browser used was http://www.bing.com
    
#The keywords used can be derived from this link:
#www.bing.com/search?q=home+improvement+remodeling+your+kitchen&qs=n&form=QBLH&sp=-1&pq=home+improvement+remodeling+your+kitchen&sc=0-40&sk=&cvid=194EC908DA65455B9E9A98285A33132B\\r\\n'

#The site accessed by the user was:
#www.homeimprovement.com and all of its sub-domains, e.g.:
#www.homeimprovement.com/remodeling-your-kitchen-cabinets.html
