##############################
##### Snake: cFile class #####
##############################
#Stores information about a file, eg its imported libraries, lines of malicious code, etc etc
class cFile:
    def __init__(self, name) -> None:
        self.libs = [] ##for holding imported libraries
        self.malCode = [] ##for holding malicious code found in the file
        self.variables = [] ## for holding variables found
        self.filename = name
        self.report = "" ##the file's report
    ##Func for adding a new line of malicous code
    def addMaliciousCode(self, codeLine, malBit, description, reason, source, lineNum):
        ##use the inputs to make the line of text
        x = str(lineNum)
        text = "On line " + x + " malicious code was detected, containing " + malBit + ":\n" + "DESCRIPTION:  " + description + "\n and is thought to be malicious because " + reason + "/n SOURCE: ( " + source + " )\n" + codeLine
        self.malCode.append(text) ##append the new text to the list of malicious code
    def addLibrary(self, library, lineNum):
        ##use the passed strings to make up the line of text
        x = str(lineNum)
        text = "A library was imported by the program on line " + x + ": \n" + library
        self.libs.append(text) ##save the string to the libraries list
    def addVariable(self, codeLine, lineNum):
        ##Use the passed strings to make up the text
        x = str(lineNum)
        text = "A variable was found on the line " + x + ":\n" + codeLine
        self.variables.append(text) ##add the text to the variables library