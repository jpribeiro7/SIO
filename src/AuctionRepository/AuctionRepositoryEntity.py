from AuctionRepository.Auction import Auction


class AuctionRepositoryEntity:

    count = 0

    def __init__(self):
        self.private_key = None
        self.public_key = None

        # Session key with the other server
        self.session_key_server = None

        # (Client, SessionKey)
        self.session_key_clients = {}

        # (Auction_ID, Auction)
        self.auctions = {}

    def addAuction(self, auction):
        self.auctions[auction.id] = auction
        AuctionRepositoryEntity.count += 1

    def listAuctions(self):
        string = [k + ":" + v.description for k, v in self.auctions.items()]
        return string

    def makeBid(self, auction_id, bidder):
        auction = self.auctions[auction_id]
        auction.makeBid()