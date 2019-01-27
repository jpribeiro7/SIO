from AuctionRepository.Auction import Auction
import pickle
from App.app import *
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

        # Server pub key
        self.manager_public = None

    def addAuction(self, auction):
        self.auctions[str(auction.id)] = auction
        AuctionRepositoryEntity.count += 1

    def listAuctions(self):
        auction_list = []
        for k, v in self.auctions.items():
            if v.type == ENGLISH_AUCTION:
                auction_list.append(str(k) + ":\n\tNome: " + v.auction_name + "\n\tDesc: " + v.description + "\n\tOpen:" + str(v.open) + "\n\tLast Bid: " + str(v.get_last_bid()))
            else:
                auction_list.append("\n" + str(k) + ":\n\tNome: " + v.auction_name + "\n\tDesc: " + v.description + "\n\tOpen:" + str(v.open))

        return auction_list

    def makeBid(self, auction_id, bidder):
        auction = self.auctions[str(auction_id)]
        return auction.makeBid()
