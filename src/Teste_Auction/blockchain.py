from Teste_Auction.block import *


class BlockChain:

    def __init__(self, max_blocks):
        self.chain = []
        self.current_block= 0
        if max_blocks == 0:
            self.max_blocks = 999
        else:
            self.max_blocks = max_blocks

    def add(self, amount, description, cc, pubkey):

        if self.chain == []:
            b = Block(0, amount, description, cc, pubkey)
            self.chain.append(b)
        elif self.current_block +1  < self.max_blocks:
            b = Block(self.chain[self.current_block].getBlockHash(), amount, description, cc, pubkey)
            self.chain.append(b)
            self.current_block += 1


    def print(self):
        for block in self.chain:
            print(block.getBlockHash())
            print(block.previous_hash)


#some = BlockChain(max_blocks = 3)
#some.add(20, "aa",12,12)
#some.add(20, "asdas",12,12)
#some.add(20, "asdasd",12,12)
#some.add(20, "aa",12,12)
#some.print()












