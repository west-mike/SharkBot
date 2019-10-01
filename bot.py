from discord.ext import commands
import discord 
import pyshark
import sharkBot 
import asyncio
import os
import time
bot = commands.Bot(command_prefix='!', help_command=None)
#client Token
TOKEN = "******"
scanner= sharkBot.scanner()
capture = sharkBot.capture()
#Process commands to see what the user has requested
@bot.command()
async def read (ctx, *args):
    #Strip Value from command if it has one
    for arg in args:
        value = arg[arg.find("(")+1:arg.find(")")]
        sep = '('
        arg = arg.split(sep, 1)[0]
        #Perform the Specified Commands
        print(arg)
        tried = False
        if (arg == "file"):
            try:
                tried = True
                x = scanner.readCaptureFile(value)
                await ctx.send(x)
            except FileNotFoundError:
                tried = True
                await ctx.send("Error: File not found")
        if (arg == "plot"):
            if (x in locals()):
                await ctx.send_file(capture.plot_AverageLenOfLayer(x))
                print("WE tried...")
                tried = True
        elif (tried == False):
            await ctx.send("Error invalid operation requested, refer to !help read for more information.")
@bot.command()
async def help (ctx, *args):
    #Help only provides help on one command
    if (len(args) > 1):
        await ctx.send("Too many parameters passed, at this time help only takes one parameter, the command name you need help with.")
    else:
        #Provides help based on the command that help was asked for
        arg = args[0]
        if (arg == "read"):
            await ctx.send("I see you need help with the read function, here is how it works:")
            await ctx.send("!read file(<FILE NAME HERE>)")
            await ctx.send("Read only takes one parameter, file, and returns a capture object for use, in the future it will take other functions as well.")
        if (arg == "help"):
            await ctx.send("I see you need help with the help function, here is how it works:")
            await ctx.send("!help <COMMAND TO GET HELP WITH HERE>")
            await ctx.send("Read only takes one parameter, a command, and provides info on how to use it.")   
        if (arg == "cap"):
            await ctx.send("I see you need help with the capture function, here is how it works:")
            await ctx.send("!cap <TIME> <FILENAME.cap> <ANALYSIS>")
            await ctx.send("Currently, capture scans the network for the specified amount of time, saves it to a file and performs analysis on it.")
            await ctx.send("The only analysis available right now is security, which returns a list of foreign destination and source addresses.")
@bot.command()
async def cap (ctx, *args):
    #Rejects too many arguments
    if (len(args) > 3):
        await ctx.send("Too many parameters passsed, at this time cap only takes three parameters")
    elif (len(args) < 3):
        #Create a command to run in a shell that will perform a cpature based on the provided parameters
        filename = str(args[1])
        script_start = "python3 botcapture.py " + args[0] + " " + filename
        os.system(script_start)
        #Wait for the capture to finish, in the future will be used as a wait to perform analysis in the confines of this command
        time.sleep(int(args[0]))
        message = "Capture is done, analytical operations may now be performed, the file name is: " + filename
        await ctx.send(message)
    elif (args[2] == "security"):
        captured = capture.readCaptureFile(filename)
        capture.getInfo(filename - ".cap" + "info.txt")
        capture.listOfIPs(filename - ".cap" + "ips.txt")
        foreigns = capture.SecurityResponse(captured)
        await ctx.send("Foreign addresses: " + "\n" + foreigns)
    elif (args[2] != "security"):
        await ctx.send("Whoops, looks like you wanted us to do something we can't do yet, please try again and remember that the only analysis able to be performed at this time is security which you can call by using 'security'")
bot.run(TOKEN)
