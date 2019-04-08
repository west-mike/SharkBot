import pyshark
import matplotlib.pyplot as plt
import pandas as pd
class sharkBot:
	def capturePacketsByCount(self, interface, packet_count, tshark_path):
		#capture specified number of packets 
		self.capture = pyshark.LiveCapture(tshark_path=tshark_path, interface=interface)
		self.capture.sniff(packet_count=packet_count)
		self.caplen = len(self.capture)
		#capture packets for given amount of time
	def capturePacketsByTime(self, interface, timeout, tshark_path):
		self.capture = pyshark.LiveCapture(tshark_path=tshark_path, interface=interface)
		self.capture.sniff(timeout=timeout)
		self.caplen = len(self.capture)
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
		dst = list()
		src = list()
		packetswithips = list()
		while (i < self.caplen):
			ip1 = self.capture[i]
			if 'IP' in ip1:
				dst.append(ip1['ip'].dst)
				src.append(ip1['ip'].src)
				packetswithips.append(i)
			i += 1
		i = 0
		while (i < len(src)):
			f = open(filename, "a")
			pnum = packetswithips[i] + 1
			towrite = "Capture: " + str(capnum) + "\n" + "Packet Number: " + str(packetswithips[i]) + "\n    " + "Source IP: " + src[i] + "\n    " + "Destination IP: " + dst[i] + "\n"
			f.write(towrite)
			f.close()
			i += 1

bot = sharkBot()
bot.capturePacketsByCount(interface='en0', packet_count=1000, tshark_path='/Applications/Wireshark.app/Contents/MacOS/tshark')
bot.listOfIPs("/Users/cooldude/Documents/PySharkStuff/ips4-8-19.txt", 2)