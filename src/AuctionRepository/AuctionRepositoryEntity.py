class AuctionRepositoryEntity:

    def __init__(self):
        self.private_key = None
        self.public_key = None

        # Session key with the other server
        self.session_key_server = None

        # (Client, SessionKey)
        self.session_key_clients = {}
