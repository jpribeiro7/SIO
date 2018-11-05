import os


#this class has all the possible messages to comunicate with the server
class ClientActions:

    def Login(self, client):
        message = "{ \"type\" : \"login\",\n"
        message += "\"client_credentials\" : \"" + client.credentials + "\" }"
        return message

    def createAuction(self,client):
        message = "{ \"type\" : \"create_auction\",\n"
        message += "\"client\" : \""+client.id + "\" }"
        return message

    def setBidValidation(self):
        message = "{ \"type\" : \"create_auction\",\n"
        message += "\"???\" : \"" + 777 + "\" }"
        return message

    def terminateAuction(self, client, auction):
        message = "{ \"type\" : \"terminate_auction\",\n"
        message += "\"client\" : \"" + client.id + "\", \n "
        message += "\"auction\" : \"" + auction + "\"}"
        return message

    def bid(self, client, auction, value):
        message = "{ \"type\" : \"bid\",\n"
        message += "\"client\" : \"" + client.id + "\", \n "
        message += "\"auction\" : \"" + auction + "\", \n"
        message += "\"value\" : \"" + value + "\"}"
        return message

