from enum import Enum

AM_ADDRESS = ('localhost', 10050)
AR_ADDRESS = ('localhost', 10000)

class AUCTION_TYPE(Enum):
    ENGLISH = 1
    BLIND = 2