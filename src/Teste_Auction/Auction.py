from Teste_Auction.blockchain import *
import uuid


class Auction:

    def __init__(self, type, time_limit, description, name=None):
       self.name = name
       self.id = uuid.uuid1()
       self.type = type
       self.blockchain = BlockChain()
       self.time_limit = time_limit
       self.description = description


    def get_blockchain(self):
        return self.blockchain

    def getID(self):
        return self.id