##Outside libraries
import requests
import argparse
import sys
import os
from datetime import datetime
##Other snake classes: 
from ClassDetector import cDetector
#################################
##### Snake: cCommand class #####
#################################
##This class handles the commands inputted by the user
class cCommand:
    ##Constructor:
    def __init__(self) -> None:
        self.folder = 'pythonFiles/' #the folder holding the files downloaded
        self.numFilesDownloaded = 0 #the number of files downloaded
        self.detector = cDetector() #class for detecting malicious files in python scripts
    def startArgparse(self): ##sets up the argparse stuff
        parser = argparse.ArgumentParser(prog="snake") ##create the parser, passes the name of the program
        parser.add_argument(
            "-g", ##The flag
            "--github",
            dest = "githubDirectory", ##the destination of the user's input (ie the github repo)
            help = "Download code from a Github repository. Please note, you must use a repository's raw GitHub URL, not its standard one. Raw GitHub urls look like the following: https://raw.githubusercontent.com/user/repo/branch/[subfolders]/file ",# message for the help page
            required=False #This flag is not required
        )
        parser.add_argument(
            "-l", ##the flag
            "--library",
            dest="libRepo",
            help="Parse a library already downloaded from PyPi on your device. Needs the directory the library is saved in to work. \n You can choose for this to be a single file of the code, or for the entire directory to be scanned",
            required=False
        )
        parser.add_argument(
            "-t",
            "--textfile",
            dest="textFileDirectory",
            help = "Read and parse code from a text file",
            required = False
        )
        parser.add_argument(
            "-w",
            "--write",
            dest="writeFile",
            help = "Write output to a text file",
            required = False
        )
        parser.add_argument(
            "-v", ##For if the user wants a verbose output
            "--verbose",
            action="store_true",
            dest="verbose",
            help = "Show a verbose output",
            required=False
        )
        args = parser.parse_args() 
        print(f"Processing {sys.argv} ")
        self.parseCommand(args) ##parse the arguments
    ##Func for parsing user commands
    def parseCommand(self, args):
        gitRepo = args.githubDirectory
        libRepo = args.libRepo
        textDirectory = args.textFileDirectory
        writeFile = args.writeFile
        verbose = args.verbose
        if gitRepo != None:
            ##if the entered something for github
            self.github(gitRepo) #get the github repo and parse it
        if libRepo != None:
            ##If the user wants to parse a pypi library
            self.pypi(libRepo)
        if textDirectory != None:
            ##If the user wants to parse a text file
            self.text(textDirectory)
        ##Now print the output, passing the verbose argument 
        self.print(verbose)
        if writeFile != None:
            ##The user wants to write the output to a file
            self.write(writeFile)
    ##func for getting data grom github
    def github(self, repo):
        file = self.makeRequest(repo)
        self.parseFile(file)
    ##func for reading a library from PyPi
    def pypi(self, directory):
        files = directory
        ##Code addapted from https://www.geeksforgeeks.org/how-to-iterate-over-files-in-directory-using-python/
        #Now iterate through files in that directory
        for filename in os.listdir(files):
            f = os.path.join(directory, filename)
            ##Check if it is a file (not a folder)
            if os.path.isfile(f):
                print("Parsing... " + f)
                self.parseFile(f) ##parse the file
    ##func for reading from a text file
    def text(self, file):
        self.parseFile(file) ##just parse the file lol
    ##func for writing to a file
    def write(self, file):
        self.detector.writeReportForFile
        time = datetime.now() ##get the current date and time
        timeString = time.strftime("%d_%m_%Y_%H_%M_%S") ##convert the date into a string
        fileWrite = open(file, 'w') ##open the file
        text = "Snake Output - written on " + timeString + "\n --------------------------------------------------"
        text = text + self.detector.ReportTable.get_string() + "\n --------------------------------------------------"
        for parsedFile in self.detector.files.values(): ##loop through all the files:
            text = text + "\n ============================================================== "+ parsedFile.report
        fileWrite.writelines(text)
        print ("Written to file " + file)
    ##func for making URL requests using the Requests library
    def makeRequest(self, url):
        ##NOTE: users need to use the RAW github url, not the standard url
        #Raw urls look like this: "https://raw.githubusercontent.com/user/repo/branch/[subfolders]/file"
        ##Source: https://stackoverflow.com/questions/14120502/how-to-download-and-write-a-file-from-github-using-requests
        response = requests.get(url) #make a request to the url
        ##check if the request was successful
        code = response.status_code
        time = datetime.now() ##get the current date and time
        timeString = time.strftime("%d_%m_%Y_%H_%M_%S") ##convert the date into a string
        if code == 200:
            print("Request successful!")
            filename = self.folder + 'snake_github_file_' + timeString + '.txt' ##The file name is made unique by the date and time
            with open(filename, 'w', encoding="utf-8") as f:
                f.write(response.content.decode()) #write the github code to a file)
                print("Downloaded file successfully")
        elif code == 400:
            print ("400 Bad request")
            filename = 'ERROR'
        elif code == 401:
            print ("401 Unauthorized")
            filename = 'ERROR'
        elif code == 404:
            print("404 not found")
            filename = 'ERROR'
        return filename
    ##func for parsing downloaded files
    def parseFile(self, file):
        self.detector.parseFile(file) ##parses the file
    ##func for printing the output file
    def print(self, verbose):
        if verbose != False:
            ##print the verbose output (eg the cFile stored output)
            self.detector.printVerboseReport()
        else:
            ##print the normal output
            self.detector.printReport()