class AuctionManagerEntity:

    def __init__(self):
        # Key Pair
        self.private_key = None
        self.public_key = None
        # (Client, SessionKey)
        self.session_clients = {}
        # Session key with repository
        self.session_key_repository = None
        # Public key Repos
        self.public_repository_key = None





