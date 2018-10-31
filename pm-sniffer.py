#Created by Patrick McGee

import socket
import sys
from struct import *

#Setup phase
#Create my list of known IPs
white_list = []
with open('whitelist.txt') as f:
     white_list = f.read().strip().split('\n')

#My pi's address
pi_addr = '192.168.8.221'

#My trigger to alert
safe = False

#Find all of twilio's IP's and append them to the list
lookup = socket.getaddrinfo("api.twilio.com", 0, 0, 0)
for x in lookup:
     white_list.append(x[-1][0])

#remove duplicates
white_list = list(set(white_list))
print('Your white list is: ')
for x in white_list:
    print(x)

#Listen phase
#Open a raw socket to listen in on
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

#Check each packet's src and dst ips
while True:
     packet = s.recvfrom(65565)

     packet = packet[0]

     ip_header = packet[14:34]

     iph = unpack('!BBHHHBBH4s4s', ip_header)

     s_addr = socket.inet_ntoa(iph[8]);
     d_addr = socket.inet_ntoa(iph[9]);


 #Checks if the pi talks to something out of the white list
 #If it talks to something out of the white list it kills
 #this script otherwise just keep running

     if s_addr == pi_addr and d_addr in white_list :
          #Changed this to check if destination is in white_list instead of iterating over the white_list and executing extra code
          safe = True
          bad_ip = ''
     elif s_addr != pi_addr :
          #This should raise exception, but I'm lazy
          print('Source IP error')
     else:
          safe = False
          intruder(s_addr, d_addr)

#Replaced this with the function below
#     if safe != True and s_addr == pi_addr and d_addr == bad_ip :
#         print('Intruder alert!')
#         print('Source: ', pi_addr)
#         print('Destination: ', bad_ip)
#         sys.exit()
         
def intruder(s_addr, bad_ip):
     print('Intruder alert!')
     print('Source: ', s_addr)
     print('Destination: ', bad_ip)
     sys.exit()
