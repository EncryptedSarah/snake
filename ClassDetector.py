##Outside libraries
import csv
from prettytable import PrettyTable
##Other classes from Snake
from BoyerMoreAlgorithm import cBoyerMoore
from ClassFile import cFile
class cDetector:
    MaliciousDatabase = {} #a dictiionary of lists holding info about the code
    ReportTable = PrettyTable(["Line Number", "Contains", "Description", "Malicious Reasoning"])
    def __init__(self) -> None:
        self.files = {} # dict of files read in
        self.readInDatabase()
    def readInDatabase(self):
        with open('CodeDatabase.csv', 'r') as file:
            csvreader = csv.reader(file)
            for line in csvreader:
                #So the MaliciousDatabase List is in the order: 0: Description, 1: Mal Reasioning, 2: Notes 3: source
                self.MaliciousDatabase[line[0]] = [line[1], line[2],line[3], line[4]]
    def parseFile(self, file):
        #### STEP 2: TAKE IN FILE
        newFile = cFile(file) ##create a new file instanciation
        searcher = cBoyerMoore #Creates a new searching algorithm object#
        lineNum = 0
        with open(file, 'r') as reader:
            for line in reader: #uses the Boyer-Moore algorithm
            #Now searching for imported libraries:
                if searcher.search(searcher, line, "import") == True:
                ##If one is found, add the library to the file object
                ##Passing through: library, lineNum
                    newFile.addLibrary(line, lineNum)
            ##searching for variables
                if searcher.search(searcher, line, "=") == True:
                ##Add to the file object in the order: codeLine, lineNum
                    newFile.addVariable(line, lineNum)
            ##Now searching for known malicious code:
                for Word in self.MaliciousDatabase:##Loop through the entire database
                    if searcher.search(searcher, line, Word) == True: # Gives the pattern and text to the algorithm
                        self.addLineToReport(lineNum, Word)
                    ##Save the finding of the code to the file object
                    #passed in the order of: codeLine, malBit, description, reason, source, lineNum
                    ##In this order: self, codeLine, malBit, description, reason, source, lineNum
                        newFile.addMaliciousCode(line, Word, self.MaliciousDatabase[Word][0],self.MaliciousDatabase[Word][1], self.MaliciousDatabase[Word][3], lineNum)
                lineNum = lineNum +1
        self.files[newFile.filename] = newFile #appends the file object onto the files list
        self.writeReportForFile(newFile.filename)
    def addLineToReport(self, lineNum, Word):
        #Table headings:["Line Number", "Contains", "Description", "Malicious Reasoning"])
        #First, get the description and reasoning from the malicious database map:
        Description = self.MaliciousDatabase[Word][0]
        MaliciousReason = self.MaliciousDatabase[Word][1]
        #Second, add the information to the table:
        self.ReportTable.add_row([lineNum, Word, Description, MaliciousReason])
    ##func for writing the final report
    def writeReportForFile(self, filename):
        theFile = self.files[filename]
        theFile.report = theFile.report + "//////////////////////////////////////////////////////////////////" + "\n"
        theFile.report = theFile.report +  "FILE: " + theFile.report + theFile.filename + "\n"
        theFile.report = theFile.report + "----------------------------------------------" + "\n"
        theFile.report = theFile.report + "MALICIOUS CODE: " + "\n"
        theFile.report = theFile.report + "--------------------" + "\n"
        theFile.report = theFile.report + "These lines of code were detected to be malicious by Snake. Please analyse them carefully! Reasonings have been included here too" + "\n"
        theFile.report = theFile.report + "In total, Snake found " + str(len(theFile.malCode)) + " lines of malicious code" + "\n"
        theFile.report = theFile.report + "--------------------" + "\n"
        for text in theFile.malCode:
            theFile.report = theFile.report + text + "\n"
        theFile.report = theFile.report + "----------------------------------------------" + "\n"
        theFile.report = theFile.report + "IMPORTED LIBRARIES: " + "\n"
        theFile.report = theFile.report + "--------------------" + "\n"
        theFile.report = theFile.report + "Please note: Malicious scripts often make use of malicious libraries to execute their malicous code, allowing them to stay undetected" + "\n"
        theFile.report = theFile.report + "Because of this, it is highly recommeneded you ensure the libraries imported by this program are legitimate - this can be done by looking them up on PyPi or Github" + "\n"
        theFile.report = theFile.report + "Snake found " + str(len(theFile.libs)) + " libraries in use in this code" + "\n"
        theFile.report = theFile.report + "--------------------" + "\n"
        for x in theFile.libs:
            theFile.report = theFile.report + x + "\n"
        theFile.report = theFile.report + "----------------------------------------------" + "\n"
        theFile.report = theFile.report + "VARIABLES:" + "\n"
        theFile.report = theFile.report + "--------------------" + "\n"
        theFile.report = theFile.report + "The following are variables detected by Snake. These are just for your own information - they may not all be malicious!" + "\n"
        theFile.report = theFile.report + "Snake found " + str(len(theFile.variables)) + " variables in use in this code" + "\n"
        theFile.report = theFile.report + "--------------------" + "\n"
        for x in theFile.variables:
            theFile.report = theFile.report + x + "\n"
    def printReport(self): ##Writes the outputted report file
        print(self.ReportTable)
    def printVerboseReport(self): ##prints a verbose report
        ##loop through all the saved files
        for file in self.files.values():
            print(file.report) #prints that file's report
    def writeToFile(self, file): ##writes the report to a file
        f = open(file, "w")
        f.write("This report begins with a summary of findings, after which there is a more verbose report:")
        f.write(self.ReportTable)
        f.close()
