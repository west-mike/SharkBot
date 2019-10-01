#This file scans the network to a capture file for the specified period of time
import sys
import pyshark
import sharkBot
bot = sharkBot.scanner()
bot.capturePacketsByTime(timeout=int(sys.argv[1]), output_file=sys.argv[2], interface="en0")
