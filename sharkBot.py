import pyshark
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import geoip2.database as geo
import geoip2
class sharkBot:
	def capturePacketsByCount(self, interface, packet_count, tshark_path, output_file=None):
		#capture specified number of packets 
		self.capture = pyshark.LiveCapture(tshark_path=tshark_path, interface=interface, output_file=output_file)
		self.capture.sniff(packet_count=packet_count)
		self.caplen = len(self.capture)
		#Create lists for storing IP addresses
		i = 0
		self.dst = list()
		self.src = list()
		self.packetswithips = list()
		#Go through every packet, and if it has an IP address add it to the lists
		while (i < self.caplen):
			ip1 = self.capture[i]
			if 'IP' in ip1:
				self.dst.append(ip1['ip'].dst)
				self.src.append(ip1['ip'].src)
				self.packetswithips.append(i)
			i += 1
		#capture packets for given amount of time
		return self.capture
	def capturePacketsByTime(self, interface, timeout, tshark_path, output_file=None):
		self.capture = pyshark.LiveCapture(tshark_path=tshark_path, interface=interface, output_file=output_file)
		self.capture.sniff(timeout=timeout)
		self.caplen = len(self.capture)
		#Create lists for storing IP addresses
		i = 0
		self.dst = list()
		self.src = list()
		self.packetswithips = list()
		#Go through every packet, and if it has an IP address add it to the lists
		while (i < self.caplen):
			ip1 = self.capture[i]
			if 'IP' in ip1:
				self.dst.append(ip1['ip'].dst)
				self.src.append(ip1['ip'].src)
				self.packetswithips.append(i)
			i += 1
		return self.capture
	def plot_AverageLenOfLayer(self):
		i = 0
		#Create a Datframe and lists to store our values that we read from the packet
		df = pd.DataFrame()
		layer = list()
		#Create a dictionary that will store our average values by layer
		averages = {}
		#Loop that steps through each packet and grabs all unique layers and each individual length value
		while (i < self.caplen):
			dns1 = self.capture[i]
			#This loop checks to see if the layer has already been added to the layers list, if not it adds it
			if dns1.highest_layer not in layer:
				layer.append(dns1.highest_layer)
				df[dns1.highest_layer] = 0
			i += 1
		i = 0
		#This loop creates a column for each layer and then adds it's respective length values
		while (i < self.caplen):
			dns1 = self.capture[i]
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
		plt.show()
	def listOfIPs(self, filename, capnum):
		i = 0
		#Write the IPs for each packet to a .txt file for future use
		while (i < len(self.src)):
			f = open(filename, "a")
			towrite = "Capture: " + str(capnum) + "\n" + "Packet Number: " + str(self.packetswithips[i]) + "\n    " + "Source IP: " + self.src[i] + "\n    " + "Destination IP: " + self.dst[i] + "\n"
			f.write(towrite)
			f.close()
			i += 1
	def getProtocol(self, packetnum):
		if 'protocol' in  self.capture[packetnum]:
			protocol = self.capture[packetnum]['protocol']
			print(protocol)
		else:
			print("Error: packet has no attribute 'protocol'")
	def listOfUDPs(self, filename, capnum):
		#Create lists for storing UDP information
		i = 0
		chcksum = list()
		dstport = list()
		port = list()
		srcport = list()
		packetswithudp = list()
		#Go through every packet, and if it has an IP address add it to the lists
		while (i < self.caplen):
			udp1 = self.capture[i]
			if 'UDP' in udp1:
				dstport.append(udp1['udp'].dstport)
				srcport.append(udp1['udp'].srcport)
				port.append(udp1['udp'].port)
				chcksum.append(udp1['udp'].checksum)
				packetswithudp.append(i)
			i += 1
		i = 0
		#Write the IPs for each packet to a .txt file for future use
		while (i < len(packetswithudp)):
			f = open(filename, "a")
			towrite = "Capture: " + str(capnum) + "\n" + "Packet Number: " + str(packetswithudp[i]) + "\n    " + "Checksum: " + chcksum[i]  + "\n    " + "Port: " + port[i] +  "\n    " + "Source Port: " + srcport[i] + "\n    " + "Destination Port: " + dstport[i] + "\n"
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
	def DNSList(self, filename):
		f = open(filename, "a")
		for packet in self.capture:
			if packet.dns.qry_name in packet:
				f.write("DNS:", packet.dns.qry_name)
bot = sharkBot()
bot.capturePacketsByCount(interface="en0", tshark_path="/Applications/Wireshark.app/Contents/MacOS/tshark", packet_count=250)
bot.plot_AverageLenOfLayer()