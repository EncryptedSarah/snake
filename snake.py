###############################################################
##### Snake: A script for detecting malicious python code #####
###############################################################
#                            ____
#   ________________________/ O  \___/ -hsssss
#  <888888888888888888888888_____/   \
## startup art taken from: https://asciiart.website/index.php?art=animals/reptiles/snakes 
##Classes from other files
from ClassCommand import cCommand
def main():
    
    #Printing the snake logo
    ##credits to startup art go to: https://asciiart.website/index.php?art=animals/reptiles/snakes
    image = "snakeImg.txt"
    file = open(image)
    file_contents = file.read()
    file.close()
    print(file_contents)
    print("Welcome to Snake!")
    interpreter = cCommand()
    interpreter.startArgparse()
if __name__=="__main__":
    main()


