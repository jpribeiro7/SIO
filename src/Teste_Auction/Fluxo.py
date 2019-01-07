
# CRIAR AUCTION


#TODO cliente envia pedido de criaçao de auction ao AUCTION MANAGER

# qualquer cliente que tenha uma auction tem que criar um par de chaves assimétricas exclusivo para os auctions
#
# client.createAuction(time_limit,              tempo limite para fazer bids      --
#                       description,            descriçao possivel do auction     -- Tratado em Auction
#                       name=None,              nome possivel para o auction      --
#                       allowed_bidders = []    users que podem fazer bids a este auction (estou a pensar enviar lista de usernames)  --
#                       bids_per_bidder         numero max de bids feitas por um bidder                                               -- Validado em Manager
#                       )
#
# client.desencriptAuction
# enviar chaves publica para o auction para que todas as bids submetidas sejam encriptadas com a chaves publica do mesmo
# quando se quiser libertar o auction tem que ser o criador a desencriptar a blockchain com a chave privada


# @@@@-------- >>>>>> No create auction ter numero max de bids?
#                     Bid minima (começar em 1000$)?
#



#TODO validar auction em auctionManager

# manager.validateAuction(allowed_bidders, bids_per_bidder)     #validar através de código dinâmico


# SUBMETER BID

#TODO cliente envia nova bid

# client.tryBid(auction_name,
#                value
#                )
#
# devolver também assinatura do cliente
# depois do auct_manager validar, recebe a blockchain, valida-a e tenta resolver o cryptopuzzle
# se não válida não submete a bid, caso contrário submete


#TODO Modificar campos da bid, sem mudar o pretendido originalmente ou Encriptar informaçao da bid

# manager.encript(Auction)      sugiro criar um novo par de chaves assimétricas (nao usar o mesmo das mensagens)
#                               encriptar com chave pública

# manager.desencript(blockchain)
#                               na altura de mostrar as bids, desencriptar blockchain com chave privada chave privada
#                               enviar blockchain ao criador da auction para ele desencriptar a info restante
#

