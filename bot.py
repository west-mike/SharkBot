import discord
import pyshark
from discord.ext import commands
#Bot Token
TOKEN = 'NTc1NzcxNDc0NjY1Nzk5NzA5.XNXJag.XdFLK81EUpGvg8ZZCCRKCpBFRZw'
#Create a Bot
prefix = "?"
bot = commands.Bot(command_prefix=prefix)
@bot.event
async def on_message(message):
	if message.author == bot.user:
		await process_commands(message)
def cap(params):
	print(params)
def read(params):
	print(params)
def ping():
	latency = bot.latency
	await (bot.send(latency))
def process_commands(message):
	if message.content.starts_with('!'):
		list(message)
		message.remove(0)
		commands = {1: 'cap', 2: 'read', 3:'ping'}
		cmd, space, params = message.split(' ')
		params = params.split('-')
		func = commands.get(cmd, "Invalid command")
		if (func == 'cap'):
			await (cap(params))
		elif (func == 'read'):
			await (read(params))
		elif (func == 'ping'):
			await (ping())
bot.run('NTc1NzcxNDc0NjY1Nzk5NzA5.XNXJag.XdFLK81EUpGvg8ZZCCRKCpBFRZw')