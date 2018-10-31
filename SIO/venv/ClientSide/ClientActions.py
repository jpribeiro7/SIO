import os


#this class has all the possible messages to comunicate with the server
class ClientActions:



    def Login(self,client):

        return "login"

    def createAuction(self,client):
        return "createAuction"

    def setBidValidation(self):
        return "setBidValidation"

    def terminateAuction(self, client,auction):
        return "terminateAuction"

    def bid(self,client, auction,value):
        return "bid"

