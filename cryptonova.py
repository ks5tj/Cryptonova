import sys
import rsa
import hashlib
import binascii
from datetime import datetime
import os

def hashFile(filename):
    h = hashlib.sha256()
    with open(filename, 'rb', buffering=0) as f:
        for b in iter(lambda : f.read(128*1024), b''):
            h.update(b)
    return h.hexdigest()

# given an array of bytes, return a hex reprenstation of it
def bytesToString(data):
    return binascii.hexlify(data)

# given a hex reprensetation, convert it to an array of bytes
def stringToBytes(hexstr):
    return binascii.a2b_hex(hexstr)

# Load the wallet keys from a filename
def loadWallet(filename):
    with open(filename, mode='rb') as file:
        keydata = file.read()
    privkey = rsa.PrivateKey.load_pkcs1(keydata)
    pubkey = rsa.PublicKey.load_pkcs1(keydata)
    return pubkey, privkey

# save the wallet to a file
def saveWallet(pubkey, privkey, filename):
    # Save the keys to a key format (outputs bytes)
    pubkeyBytes = pubkey.save_pkcs1(format='PEM')
    privkeyBytes = privkey.save_pkcs1(format='PEM')
    # Convert those bytes to strings to write to a file (gibberish, but a string...)
    pubkeyString = pubkeyBytes.decode('ascii')
    privkeyString = privkeyBytes.decode('ascii')
    # Write both keys to the wallet file
    with open(filename, 'w') as file:
        file.write(pubkeyString)
        file.write(privkeyString)
    return
def fundWallet(destinationtag, amount, transfile):
    sourceid = "bigfoot"
    dt = datetime.now().strftime("%a %b %d %H:%M:%S EDT %Y")
    transtatement = f"Funded wallet {destinationtag} with {amount} Cryptonova on {dt}"
    entry = f"From: {sourceid}\nTo: {destinationtag}\nAmount: {amount}\nDate: {dt}\n"
    with open(transfile, "w") as file:
        file.write(entry)
    return transtatement
def transferFunds(sourcewalletfile, destinationtag, amount, transfile):
    _, privkey = loadWallet(sourcewalletfile)
    sourcepubkey, _ = loadWallet(sourcewalletfile)
    sourcepubkeypem = sourcepubkey.save_pkcs1(format='PEM')
    sourcewallettag = hashlib.sha256(sourcepubkeypem).hexdigest()[:16]

    dt = datetime.now().strftime("%a %b %d %H:%M:%S EDT %Y")

    entry = f"from: {sourcewallettag}\nTo: {destinationtag}\nAmount: {amount}\nDate: {dt}\n"
    signature = signTransaction(entry, privkey)
    entry += f"{signature}\n"
    transtatement = f"Transfered {amount} from {sourcewalletfile} to {destinationtag} and the statement to {transfile} on {dt}"
    with open(transfile, "a") as file:
        file.write(entry)
    return transtatement
def checkBalance(walletfile=None, wallettag=None):
    if walletfile:
        pubkey, _ = loadWallet(walletfile)
        pubkeypem = pubkey.save_pkcs1(format='PEM')
        pubkeyhash = hashlib.sha256(pubkeypem).hexdigest()
        wallettag = pubkeyhash[:16]

    balance = 0
    def updateBalance(line, wallettag):
        nonlocal balance
        parts = line.split()

        if len(parts) >= 5 and parts[1] == 'transferred':
            if parts[0] == wallettag:
                balance -= int(parts[2])
            elif parts[4] == wallettag:

                balance += int(parts[2])
    b = 1
    while True:
        blockfile = f"block_{b}.txt"
        try:
            with open(blockfile, "r") as file:
                next(file)
                for line in file:
                    if 'nonce:' in line:
                        break
                    updateBalance(line, wallettag)

            b += 1
        except FileNotFoundError:
            break
    try:
        with open('mempool.txt', 'r') as file:
            for line in file:
                print(line)
                updateBalance(line, wallettag)
    except FileNotFoundError:
        pass
    return balance
def signTransaction(transaction_info, privkey):
    signature = rsa.sign(transaction_info.encode('ascii'), privkey, 'SHA-256')
    return bytesToString(signature).decode()
def verifyTrasactions(walletfile, transfile):
    with open(transfile, "r") as file:
        lines = file.readlines()
    transinfo = ''.join(lines[:-1])
    signature = lines[-1].strip()

    if "From: bigfoot" in transinfo:
        amountline = lines[2]
        amount = int(amountline.split(':')[1].strip())
        fromtag = lines[0].split(':')[1].strip()
        totag = lines[1].split(':')[1].strip()
        dt = lines[3][6:].strip()
        entry = f"{fromtag} transferred {amount} to {totag} on {dt}\n"
        with open('mempool.txt', 'a') as mempool:
            mempool.write(entry)
        return "Any funding request (i.e., from bigfoot) is considered valid; written to the mempool"
    # Regular transaction, we need to verify signature
    else:
        pubkey, _ = loadWallet(walletfile)

        try:
            sigbytes = stringToBytes(signature)
            rsa.verify(transinfo.encode('ascii'), sigbytes, pubkey)
        except rsa.VerificationError:
            print("RSA verification error: Signature does not match.")
            return False
        except ValueError:
            print("ValueError: Signature has incorrect value.")
            return False
        except binascii.Error as e:
            print(f"Binascii error converting signature to bytes: {e}")
            return False

        if not verifySignature(transinfo, signature, pubkey):
            return "Transaction verification failed"
        amount = int(transinfo.split('\n')[2].split(':')[1].strip())

        pubkey, _ = loadWallet(walletfile)
        pubkeypem = pubkey.save_pkcs1(format='PEM')
        pubkeyhash = hashlib.sha256(pubkeypem).hexdigest()
        wallettag = pubkeyhash[:16]

        if checkBalance(wallettag=wallettag) >= amount:

            with open('mempool.txt', 'a') as mempool:
                fromtag = lines[0].split(':')[1].strip()
                totag = lines[1].split(':')[1].strip()
                dt = lines[3].split('Date:')[1].strip()
                entry = f"{fromtag} transferred {amount} to {totag} on {dt}\n"
                mempool.write(entry)
            return "Transaction verified and added to mempool"
        else:
            return "Insufficent funds"

def verifySignature(transinfo, signature, pubkey):
    try:
        sigbytes = stringToBytes(signature)
        rsa.verify(transinfo.encode('ascii'), sigbytes, pubkey)
        return True
    except rsa.VerificationError:
        print("rsa verification error")
        return False
    except binascii.Error as e:
        print(f"Error converting signature to bytes: {e}")
        return False
def mineBlock(difficulty):
    nonce = 0
    target = '0' * difficulty
    lastblocknumber = getLastBlockNumber() - 1
    last_block_file = f"block_{lastblocknumber}.txt"

    lastblockhash = ''

    if lastblocknumber == 0:
        with open(last_block_file, 'r') as file:
            genesiscontent = file.read()
        lastblockhash = hashlib.sha256(genesiscontent.encode('ascii')).hexdigest()
    else:
        with open(last_block_file, 'r') as file:
            lastblockhash = file.readline().strip()
    with open('mempool.txt', 'r') as mempool:
        mempooltransactions = mempool.read()
    while True:
        combinedinfo = lastblockhash + '\n' + mempooltransactions + '\n' + 'nonce: ' + str(nonce)
        blockhash = hashlib.sha256((combinedinfo).encode('ascii')).hexdigest()
        # print(f"Generated Hash: {blockhash}, Difficulty: {difficulty}")
        if blockhash.startswith(target):
            break
        nonce += 1

    blockfilename = f"block_{getLastBlockNumber()}.txt"
    with open(blockfilename, 'w') as file:
        file.write(combinedinfo)
    open('mempool.txt', 'w').close()

    return f"Mempool transactions moved to {blockfilename} and mined with difficulty {difficulty} and nonce {nonce}"

def getLastBlockNumber():
    block_no = 0
    while os.path.exists(f"block_{block_no}.txt"):
        block_no += 1
    return block_no
# Check if the user has passed in any arguments
if len(sys.argv) > 1:
    # Check if the user has passed in the argument "name"
    if sys.argv[1] == "name":
        print("Cryptonova")
    # Check if the user has passed in the argument "genesis"
    elif sys.argv[1] == "genesis":
    # create a geneis block by creating a text file called block_0.txt if one does not exist
        try:
            with open("block_0.txt", "x") as f:
                f.write("This is the genesis block")
                print("Genesis block created in block_0.txt")
        except:
            print("Genesis block already exists")
    # Check if the user has passed in the argument "generate"
    elif sys.argv[1] == "generate":
        walletfilename = sys.argv[2]
        (pubkey, privkey) = rsa.newkeys(1024)
        saveWallet(pubkey, privkey, walletfilename)
        pubkeypem = pubkey.save_pkcs1(format='PEM')
        pubkeyhash = hashlib.sha256(pubkeypem).hexdigest()
        wallettag = pubkeyhash[:16]
        print("New wallet generated in '" + walletfilename + "' with tag " + wallettag)
    elif sys.argv[1] == "address":
        walletfilename = sys.argv[2]
        pubkey, _ = loadWallet(walletfilename)
        pubkeypem = pubkey.save_pkcs1(format='PEM')
        pubkeyhash = hashlib.sha256(pubkeypem).hexdigest()
        wallettag = pubkeyhash[:16]
        print(wallettag)
    elif sys.argv[1] == "fund":
        desttag = sys.argv[2]
        amount = sys.argv[3]
        transfile = sys.argv[4]
        transinfo = fundWallet(desttag, amount, transfile)
        print(transinfo)
    elif sys.argv[1] == "transfer":
        sourcewalletfile = sys.argv[2]
        destinationtag = sys.argv[3]
        amount = sys.argv[4]
        transfile = sys.argv[5]
        transinfo = transferFunds(sourcewalletfile, destinationtag, amount, transfile)
        print(transinfo)
    elif sys.argv[1] == "balance":
        wallettag = sys.argv[2]
        balance = checkBalance(wallettag=wallettag)
        print(balance)
    elif sys.argv[1] == "verify":
        walletfile = sys.argv[2]
        transfile = sys.argv[3]
        verifresult = verifyTrasactions(walletfile, transfile)
        print(verifresult)
    elif sys.argv[1] == "mine":
        difficulty = int(sys.argv[2])
        mineresult = mineBlock(difficulty)
        print(mineresult)
    elif sys.argv[1] == "validate":
        def validateBlockchain():
            blockno = 1
            valid = True
            while True:
                currblock = f"block_{blockno}.txt"
                previous = f"block_{blockno - 1}.txt"
                if not os.path.exists(currblock):
                    break
                with open(currblock, 'r') as file:
                    contents = file.readlines()
                previoushash = contents[0].strip()
                if blockno > 1:
                    with open(previous, 'rb') as file:
                        prevcontents = file.readlines()
                        calculatedhash = hashlib.sha256(prevcontents).hexdigest()
                    if previoushash != calculatedhash:
                        valid = False
                        break
                blockno += 1
            return valid
        print(validateBlockchain())
