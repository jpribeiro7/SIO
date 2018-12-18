# This class will have all attributes of the server.
class AuctionManagerEntity:

    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.session_key = None
        self.session_clients = [("Client", "Session Key")]

