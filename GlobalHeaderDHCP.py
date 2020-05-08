import codecs
import datetime, time

file = "C:\\Users\\edvin\\OneDrive\\Desktop\\Cyber Sec\\CyberSecurity.pcap"
pcapfile = open(file, "rb")

def reverse(data):                  #function for reversing the bytes and for translating them into hexadecimals
    rev_data = bytearray(data)
    rev_data.reverse()
    final = codecs.encode(rev_data, 'hex')
    print(final)

################################## global header
print("The global header is 24 bytes long (4/2/2/4/4/4/4).")
print("\n")
 
magic = pcapfile.read(4)
print("Magic num: ")
print(codecs.encode(magic, 'hex'))
print("The magic number indicates it's the Little Endian format -> Order of following bytes is reversed.")
print("The data is in hexadecimals and reversed.")
print("\n")
    
majorversion = pcapfile.read(2)
print("Major version: ")
reverse(majorversion)

minorversion = pcapfile.read(2)
print("Minor version: ")
reverse(minorversion)

timezone = pcapfile.read(4)
print("Timezone: ")
reverse(timezone)

timestamp = pcapfile.read(4)
print("Timestamp: ")
reverse(timestamp)

snaplen = pcapfile.read(4)
print("Snaplen: ")
reverse(snaplen)

linktype = pcapfile.read(4)
print("Linktype: ")
reverse(linktype)
print("\n")

header = magic + majorversion + minorversion + timezone + timestamp + snaplen + linktype
headerSize = len(header) # 24 bytes

#################################### dhcp packet with 16byte header
print("The header of the first DHCP frame - 16 bytes.")
print("\n")

tssec = pcapfile.read(4)
print("Seconds from 1970: ")
reverse(tssec)

tsusec = pcapfile.read(4)
print("Microseconds:")
reverse(tsusec)


time_ms_deci = 1485557588.210137
gmttime = datetime.datetime.fromtimestamp(time_ms_deci)

print("The actual GMT time of this packet is " + str(gmttime))
print("\n")

datapacketlength= pcapfile.read(4)
print("Length of this DHCP frame is: ")
reverse(datapacketlength)
print("Lenght in decimals is - 348 bytes")
print("\n")

packetSize= pcapfile.read(4)
print ("Lenght of the packet is: ")
reverse(packetSize)
print("Lenght in decimals is - 348 bytes")
print("\n")

####################################
sourceMAC = pcapfile.read(6)
print("Source Mac: ")
reverse(sourceMAC)

destMAC = pcapfile.read(6)
print("Destination Mac: ")
reverse(destMAC)
print("\n")

sourceIP = pcapfile.read(4)
print("Source IP: ")
reverse(sourceIP)
print("SourceIP decimal - 192.69.0.8")

destIP = pcapfile.read(4)
print("Destination IP: ")
reverse(destIP)
print("DestinationIP decimal - 173.153.78.1")
print("\n")

print ("The name of the PC is: Stewie-PC")
#found in pcap file by translating hexadecimals into ascii
