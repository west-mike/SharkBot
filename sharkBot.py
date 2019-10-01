import pyshark
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import geoip2.database as geo
import geoip2
import asyncio
class scanner:
	def capturePacketsByCount(self, interface="en0", packet_count=100, tshark_path="/Applications/Wireshark.app/Contents/MacOS/tshark", output_file=None):
		#capture specified number of packets 
		self.capture = pyshark.LiveCapture(tshark_path=tshark_path, interface=interface, output_file=output_file)
		self.capture.sniff(packet_count=packet_count)
		self.caplen = len(self.capture)
		#capture packets for given amount of time
		return self.capture
	def readCaptureFile(self, filename):
		self.capture = pyshark.FileCapture(filename)
		self.caplen = len(self.capture)
		return self.capture
	def getInfo(self, capture):
		#Create lists for storing IP addresses
		i = 0
		self.dst = list()
		self.src = list()
		self.packetswithips = list()
		self.caplen = len(capture)
		#Go through every packet, and if it has an IP address add it to the lists
		while (i < self.caplen):
			ip1 = capture[i]
			if 'IP' in ip1:
				self.dst.append(ip1['ip'].dst)
				self.src.append(ip1['ip'].src)
				self.packetswithips.append(i)
			i += 1
		#Create lists for storing UDP information
		i = 0
		self.chcksum = list()
		self.dstport = list()
		self.port = list()
		self.srcport = list()
		self.packetswithudp = list()
		#Go through every packet, and if it has an IP address add it to the lists
		while (i < self.caplen):
			udp1 = capture[i]
			if 'UDP' in udp1:
				self.dstport.append(udp1['udp'].dstport)
				self.srcport.append(udp1['udp'].srcport)
				self.port.append(udp1['udp'].port)
				self.chcksum.append(udp1['udp'].checksum)
				self.packetswithudp.append(i)
			i += 1
	def capturePacketsByTime(self, interface, timeout, tshark_path=None, output_file=None):
		self.capture = pyshark.LiveCapture(tshark_path=tshark_path, interface=interface, output_file=output_file)
		self.capture.sniff(timeout=timeout)
		self.caplen = len(self.capture)
		return self.capture
class capture:
	def plot_AverageLenOfLayer(self, capture):
		i = 0
		#Create a Datframe and lists to store our values that we read from the packet
		df = pd.DataFrame()
		layer = list()
		#Create a dictionary that will store our average values by layer
		averages = {}
		caplen = len(capture)
		#Loop that steps through each packet and grabs all unique layers and each individual length value
		while (i < caplen):
			dns1 = capture[i]
			#This loop checks to see if the layer has already been added to the layers list, if not it adds it
			if dns1.highest_layer not in layer:
				layer.append(dns1.highest_layer)
				df[dns1.highest_layer] = 0
			i += 1
		i = 0
		#This loop creates a column for each layer and then adds it's respective length values
		while (i < caplen):
			dns1 = capture[i]
			df = df.append({dns1.highest_layer: int(dns1.length)}, ignore_index=True)
			i += 1
		#This loop gets the average of each column then adds it to a dictionary with the corresponding layer value to plot later
		for column in df:
			averages[column] = df[column].mean(skipna=True)
		#The bar values are determined by the values of the dictionary
		plt.bar(range(len(averages)), list(averages.values()), align='center')
		#The X labels are determined by the labels of the layers, also known as the keys
		#Example: {'MDNS': 450} would plot a bar going to a y value of 450 with the label on the X axis being MDNS
		plt.xticks(range(len(averages)), list(averages.keys()))
		fname = "Len_Of_Layer.png"
		return plt.save(fname)
	def listOfIPs(self, filename, ):
		i = 0
		#Write the IPs for each packet to a .txt file for future use
		while (i < len(self.src)):
			f = open(filename, "a")
			towrite = "Capture: " + str(self.caplen) + "\n" + "Packet Number: " + str(self.packetswithips[i]) + "\n    " + "Source IP: " + self.src[i] + "\n    " + "Destination IP: " + self.dst[i] + "\n"
			f.write(towrite)
			f.close()
			i += 1
	def getProtocol(self, capture, packetnum):
		if 'protocol' in capture[packetnum]:
			protocol = capture[packetnum]['protocol']
			print(protocol)
		else:
			print("Error: packet has no attribute 'protocol'")
	def listOfUDPs(self, filename, capnum):
		#Write the UDPs for each packet to a .txt file for future use
		while (i < len(self.packetswithudp)):
			f = open(filename, "a")
			towrite = "Capture: " + str(capnum) + "\n" + "Packet Number: " + str(self.packetswithudp[i]) + "\n    " + "Checksum: " + chcksum[i]  + "\n    " + "Port: " + port[i] +  "\n    " + "Source Port: " + srcport[i] + "\n    " + "Destination Port: " + dstport[i] + "\n"
			f.write(towrite)
			f.close()
			i += 1
	def SecurityList(self, filename):
		#A loop that for each source ip, checks if it is in the country database
		reader = geo.Reader('/Users/cooldude/Downloads/GeoLite2-Country_20190430/GeoLite2-Country.mmdb')
		f = open(filename, "a")
		for ip in self.src:
			#If IP is found, print our associated country
			try:
				response = reader.country(ip)
				if response.country.name != 'United States':
					to_write = "Source: ", ip, response.country.name
					f.write(to_write)
			#If country is not found, just keep going
			except geoip2.errors.AddressNotFoundError as error:
				pass
		#A loop that for each destination ip, checks if it is in the country database
		for ip in self.dst:
			#If IP is found, print our associated country
			try:
				response = reader.country(ip)
				if response.country.name != 'United States':
					to_write = "Source: ", ip, response.country.name
					f.write(to_write)
			#If country is not found, just keep going
			except geoip2.errors.AddressNotFoundError as error:
				pass
		f.close()
	def SecurityResponse(self, capture):
		#A loop that for each source ip, checks if it is in the country database then returns lists that we can spit out on the discord
		#Create lists for storing IP addresses
		i = 0
		dst = list()
		src = list()
		caplen = len(capture)
		#Go through every packet, and if it has an IP address add it to the lists
		while (i < caplen):
			ip1 = capture[i]
			if 'IP' in ip1:
				dst.append(ip1['ip'].dst)
				src.append(ip1['ip'].src)
			i += 1
		reader = geo.Reader('/Users/cooldude/Downloads/GeoLite2-Country_20190430/GeoLite2-Country.mmdb')
		foreigns = []
		for ip in src:
			#If IP is found, print our associated country
			try:
				response = reader.country(ip)
				if response.country.name != 'United States':
					foreigns.append("Source: " + ip + ": " + response.country.name + "\n")
			#If country is not found, just keep going
			except geoip2.errors.AddressNotFoundError as error:
				pass
		#A loop that for each destination ip, checks if it is in the country database
		for ip in dst:
			#If IP is found, print our associated country
			try:
				response = reader.country(ip)
				if response.country.name != 'United States':
					foreigns.append("Destination: " + ip + response.country.name + "\n")
			#If country is not found, just keep going
			except geoip2.errors.AddressNotFoundError as error:
				pass
		return foreigns
	def DNSList(self, filename, capture):
		f = open(filename, "a")
		for packet in capture:
			if packet.dns.qry_name in packet:
				f.write("DNS:", packet.dns.qry_name)
