import os


#This class has all the information of a client
class Client:

    def __init__(self,username):
        self.id = os.urandom(12)
        self.username = username


    def setUsername(self,username):
        self.username = username