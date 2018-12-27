class Auction:

    def __init__(self, auc_id, auc_type, auc_creator, auc_max_bids=None, auc_min_price_bid=None, auc_threshold=None):
        self.auc_id = auc_id
        self.auc_type = auc_type # Blind or normal
        self.auc_creator = auc_creator
        self.auc_min_price_bid = auc_min_price_bid
        self.auc_threshold = auc_threshold # e.g: "5,1992" between 5 and 1992
        self.auc_max_bids = auc_max_bids