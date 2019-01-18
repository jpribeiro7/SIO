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
        self.auction_max_number_bids = int(auction_max_number_bids)
        self.auction_min_number_bids = int(auction_min_number_bids)
        self.blockchain = []
        self.begin_date = datetime.datetime.now()
        self.max_date = datetime.datetime(year = self.begin_date.year,
                                 month = self.begin_date.month,
                                 day = self.begin_date.day,
                                 hour = self.begin_date.hour + int(auction_time))


    def makeBid(self, username, amount, signature):
        if (self.max_date - datetime.datetime.now()).total_seconds() < 0:
            return False
        if len(self.blockchain)+1 > self.auction_max_number_bids:
            return False
        if self.type == ENGLISH_AUCTION:
            if self.blockchain[-1].amount >= int(amount):
                return False

        if self.blockchain == []:
            previous_hash = None
        else:
            previous_hash = self.blockchain[-1].hash

        block = Block(previous_hash , int(amount), signature, username)
        self.blockchain.append(block)
        return True

    def get_blokchain(self):
        return self.blockchain

    @classmethod
    def validate_blockchain(cls,chain):
        # validate blockchain
        for i in range(1, len(chain)):
            previous_block = chain[i-1]
            current_block = chain[i]
            # validate hash
            if current_block.previous_hash != previous_block.hash:
                return False
        return True



