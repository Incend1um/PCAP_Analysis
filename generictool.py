#A generic tool for security threat search
#To use any of these 2 regular expressions, the other has to be commented out(alt+3)

import re

file = "C:\\Users\\edvin\\OneDrive\\Desktop\\Cyber Sec\\CyberSecurity.pcap"
pcapfile = open(file, "rb")

#what websites were accessed?
#The list can be manually searched through
########################################
##accessedwebsites = []
##
##for b in pcapfile:
##    mypattern = re.compile(r"www\..*")
##    mymatch = mypattern.findall(str(b))
##    if mymatch != []:
##
##        accessedwebsites.append(mymatch)
##for e in accessedwebsites:
##    print(e)
##    print("\n")
##   
########################################

matches = []
keywords = ['1ubuntu4']
#some key-words to search for could be 'cookie', 'script', 'credit', 'SSID', 'PHP', 'ID', etc,

for word in keywords:
    for b in pcapfile:
        mypattern = re.compile(r".*" + word + ".*")
        mymatch = mypattern.findall(str(b))
        if mymatch != []:
            matches.append(mymatch)
        
for e in matches:
    print(e)
    print("\n")

########################################

#A potential security threat could be exposed cookies; one interesting result exposes it in plain text:
#   ["b'Set-Cookie: __cfduid=d71ccd28c86be89b01677d353cf24ee741485557681; expires=Sat, 27-Jan-18 22:54:41 GMT; path=/; domain=.homeimprovement.com; HttpOnly\\r\\n'"]

#And these ones even expose the session ID:
##    ["b'Cookie: __cfduid=d71ccd28c86be89b01677d353cf24ee741485557681;
##    _ga=GA1.2.848499079.1485557681;
##    _gat=1; __utma=53806513.848499079.1485557681.1485557681.1485557681.1;
##    __utmb=53806513.1.10.1485557681;
##    __utmc=53806513;
##    __utmz=53806513.1485557681.1.1.utmcsr=bing|utmccn=(organic)|utmcmd=organic|utmctr=home%20improvement%20remodeling%20your%20kitchen;
##    __utmt=1;
##    PHPSESSID=29rqt67qj95ph1amhahrtnhd54\\r\\n'"]

##  ["b'Cookie: MUIDB=003CA726089165B33E0CAD3109166461;
##  SRCHUID=V=2&GUID=328AC2369BA44E7395F7823C6BFFB0F8;
##   _EDGE_V=1; MUID=003CA726089165B33E0CAD3109166461;
##   SRCHHPGUSR=CW=878&CH=530&DPR=1.25&UTC=-300;
##   SRCHD=AF=NOFORM;
##   SRCHUSR=DOB=20170127;
##   _RwBf=s=70&o=16;
##   _SS=SID=0FFD251DF21D620C39032F0AF39A63A5&R=20&bIm=164&HV=1485557633;
##   _EDGE_S=SID=0FFD251DF21D620C39032F0AF39A63A5;
##   _UR=D=1\\r\\n'"]

#Also possibly the OS was running as a virtual machine which might indicate something suspicious:
#   ["b'X-Powered-By: PHP/5.5.9-1ubuntu4.14\\r\\n'"]
