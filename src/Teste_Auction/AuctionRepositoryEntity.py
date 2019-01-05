from Teste_Auction import Auction

# This class will have all attributes of the server.
class AuctionRepositoryEntity:

    def __init__(self):
        self.private_key = None
        self.public_key = None
        # Session key with the other server
        self.session_key_server = None
        self.session_key_clients = []
        self.auctions = {}

    def createAcution(self, type, time_limit, description, name=None):
        auct = Auction(time_limit,description,name)
        self.auctions[auct.getID()] = auct

