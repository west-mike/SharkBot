# SharkBot

## Purpose
This is a Discord Bot that uses PyShark to  sniff the network using tshark and provide network information at the command of a Discord user in a server where the bot is installed. 

## Functionalities
More information on the PyShark methods uses can be found here: https://github.com/KimiNewt/pyshark

#### Live Capturing
This uses pyshark's method LiveCapture with the chanegable parameters being the interface it scans on, and an optional output file if desired. 

#### Capturing from a .pcap file
This uses pyshark's FileCapture method to read a .pcap file and grab information from it like a LiveCapture would provide.
