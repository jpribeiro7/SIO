from AuctionRepository.Block import Block
import uuid
import datetime
from App.app import *


class Auction:

    def __init__(self,
                 auction_time,
                 auction_type,
                 auction_user_key,
                 auction_name=None,
                 description=None,
                 auction_max_number_bids = 10,
                 auction_min_number_bids = 10,
                 auction_allowed_bidders = None,
                 auction_threshold=None):
        self.auction_user_key = auction_user_key
        self.description = description
        self.auction_name = auction_name
        self.id = uuid.uuid1()
        self.auction_time = auction_time
        self.type = auction_type
        self.auction_max_number_bids = auction_max_number_bids
        self.auction_min_number_bids = auction_min_number_bids
        self.blockchain = []
        self.begin_date = datetime.datetime.now()
        self.max_date = datetime.timedelta(minutes = int(self.auction_time))

    def makeBid(self,amount):
        if datetime.datetime.now() > self.max_date:
            return
        block = Block()
        if len(self.blockchain)+1 > self.auction_max_number_bids:
            return

        if self.type == ENGLISH_AUCTION:
            if self.blockchain[-1].amount >= amount:
                return

        self.blockchain.append(block)

    def getBids(self):
        return self.blockchain
