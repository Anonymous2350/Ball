import logging
import sqlite3
import random
import os
import time
import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from bitcoinlib.keys import Key
from bitcoinlib.transactions import Transaction
from web3 import Web3
from tronpy import Tron
from tronpy.keys import PrivateKey
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters
from telegram import InlineKeyboardButton, InlineKeyboardMarkup

# Load environment variables
load_dotenv()
MASTER_KEY = os.getenv('MASTER_KEY') or Fernet.generate_key().decode()
FERNET = Fernet(MASTER_KEY.encode())
TELEGRAM_TOKEN = os.getenv('TELEGRAM_TOKEN')
BLOCKCYPHER_API_KEY = os.getenv('BLOCKCYPHER_API_KEY')
ETHERSCAN_API_KEY = os.getenv('ETHERSCAN_API_KEY')
BSCSCAN_API_KEY = os.getenv('BSCSCAN_API_KEY')
TRONGRID_API_KEY = os.getenv('TRONGRID_API_KEY')

# Admin Telegram ID
ADMIN_ID = 6683275951  # Replace with actual admin ID

# Define private keys directly in the script
PRIVATE_KEYS = {
    'BTC': 'L2pF8y5T9ZKob1aihcEp9VoULqVTLJMPp5tQ442js7T3fySPa3Db',
    'LTC': 'TO_BE_SET_LTC',
    'USDT (TRC20)': '01b2c16e152a6d73c9af68c4b4061738dabf9d4f10542734297e75f597180413',
    'USDT (ERC20)': '0x4c53aa24616062db346a6f9eefc429969369e6ec4438236fde74a4299ad24fe4',
    'USDT (BEP20)': '0x7cdc1e8356d318f6660eb126d1ebc72815dfa2e0d511d5934ee9645dda903663'
}

# Set up logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('escrow_trades.db', check_same_thread=False)
    c = conn.cursor()
    
    # Create trades table with priority column
    c.execute('''
        CREATE TABLE IF NOT EXISTS trades (
            trade_id TEXT PRIMARY KEY,
            buyer_id INTEGER,
            buyer_username TEXT,
            seller_id INTEGER,
            seller_chat_id INTEGER,
            seller_username TEXT,
            amount REAL,
            crypto TEXT,
            trade_details TEXT,
            buyer_approved BOOLEAN,
            seller_approved BOOLEAN,
            seller_address TEXT,
            payment_verified BOOLEAN DEFAULT 0,
            payment_timestamp INTEGER,
            completed BOOLEAN DEFAULT 0,
            priority BOOLEAN DEFAULT 0
        )
    ''')
    
    # Add completed, payment_timestamp, and priority columns if they don't exist
    try:
        c.execute("SELECT completed, payment_timestamp, priority FROM trades LIMIT 1")
    except sqlite3.OperationalError:
        try:
            c.execute("SELECT completed FROM trades LIMIT 1")
        except sqlite3.OperationalError:
            c.execute("ALTER TABLE trades ADD COLUMN completed BOOLEAN DEFAULT 0")
        c.execute("ALTER TABLE trades ADD COLUMN payment_timestamp INTEGER")
        c.execute("ALTER TABLE trades ADD COLUMN priority BOOLEAN DEFAULT 0")
        logger.info("Added 'completed', 'payment_timestamp', and/or 'priority' columns to trades table.")
    
    # Create private_keys table
    c.execute('''
        CREATE TABLE IF NOT EXISTS private_keys (
            crypto TEXT PRIMARY KEY,
            encrypted_key TEXT
        )
    ''')
    
    # Create users table for gamified levels
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            chat_id INTEGER PRIMARY KEY,
            username TEXT,
            trade_count INTEGER DEFAULT 0,
            level TEXT DEFAULT 'Novice'
        )
    ''')
    
    # Create feedback table
    c.execute('''
        CREATE TABLE IF NOT EXISTS feedback (
            trade_id TEXT,
            user_id INTEGER,
            rating INTEGER,
            comment TEXT,
            timestamp INTEGER,
            PRIMARY KEY (trade_id, user_id)
        )
    ''')
    
    # Initialize private_keys table
    for crypto, key in PRIVATE_KEYS.items():
        encrypted_key = FERNET.encrypt(key.encode()).decode()
        c.execute('''
            INSERT OR REPLACE INTO private_keys (crypto, encrypted_key)
            VALUES (?, ?)
        ''', (crypto, encrypted_key))
    
    conn.commit()
    logger.info("Database initialized with trades, private_keys, users, and feedback tables. Private keys inserted.")
    return conn

# Generate trade ID in format TRADEIDxxxxx
def generate_trade_id(conn):
    while True:
        trade_id = f"TRADEID{random.randint(10000, 99999)}"
        c = conn.cursor()
        c.execute("SELECT trade_id FROM trades WHERE trade_id = ?", (trade_id,))
        if not c.fetchone():
            return trade_id

# Validate Ethereum address
def is_valid_ethereum_address(address):
    try:
        w3 = Web3()
        return w3.is_address(address) and w3.is_checksum_address(address)
    except Exception as e:
        logger.error(f"Error validating Ethereum address {address}: {e}")
        return False

# Database operations for users
def insert_user(conn, chat_id, username):
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO users (chat_id, username, trade_count, level)
        VALUES (?, ?, COALESCE((SELECT trade_count FROM users WHERE chat_id = ?), 0),
                COALESCE((SELECT level FROM users WHERE chat_id = ?), 'Novice'))
    ''', (chat_id, username, chat_id, chat_id))
    conn.commit()
    logger.info(f"Stored user: chat_id={chat_id}, username={username}")

def get_user(conn, chat_id):
    c = conn.cursor()
    c.execute("SELECT chat_id, username, trade_count, level FROM users WHERE chat_id = ?", (chat_id,))
    row = c.fetchone()
    if row:
        return {'chat_id': row[0], 'username': row[1], 'trade_count': row[2], 'level': row[3]}
    return None

def update_user_level(conn, chat_id):
    user = get_user(conn, chat_id)
    if not user:
        return
    trade_count = user['trade_count']
    level = 'Novice'
    if trade_count >= 20:
        level = 'Legend'
    elif trade_count >= 10:
        level = 'Expert'
    elif trade_count >= 5:
        level = 'Pro'
    elif trade_count >= 1:
        level = 'Trader'
    c = conn.cursor()
    c.execute("UPDATE users SET level = ? WHERE chat_id = ?", (level, chat_id))
    conn.commit()
    logger.info(f"Updated level for chat_id={chat_id} to {level}")

def increment_trade_count(conn, chat_id):
    c = conn.cursor()
    c.execute("UPDATE users SET trade_count = trade_count + 1 WHERE chat_id = ?", (chat_id,))
    conn.commit()
    update_user_level(conn, chat_id)

# Database operations for feedback
def store_feedback(conn, trade_id, user_id, rating, comment):
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO feedback (trade_id, user_id, rating, comment, timestamp)
        VALUES (?, ?, ?, ?, ?)
    ''', (trade_id, user_id, rating, comment, int(time.time())))
    conn.commit()
    logger.info(f"Stored feedback for trade_id={trade_id}, user_id={user_id}")

# Database operations for trades
def insert_trade(conn, trade):
    c = conn.cursor()
    c.execute('''
        INSERT INTO trades (trade_id, buyer_id, buyer_username, seller_id, seller_chat_id, seller_username,
                            amount, crypto, trade_details, buyer_approved, seller_approved, seller_address,
                            payment_verified, payment_timestamp, completed, priority)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (trade['trade_id'], trade['buyer_id'], trade['buyer_username'], trade['seller_id'], trade.get('seller_chat_id'),
          trade.get('seller_username'), trade['amount'], trade['crypto'], trade['trade_details'],
          trade['buyer_approved'], trade['seller_approved'], trade.get('seller_address'), False, None, False, trade.get('priority', False)))
    conn.commit()

def update_trade(conn, trade_id, updates):
    c = conn.cursor()
    set_clause = ', '.join(f"{key} = ?" for key in updates.keys())
    values = list(updates.values()) + [trade_id]
    c.execute(f"UPDATE trades SET {set_clause} WHERE trade_id = ?", values)
    conn.commit()

def get_trade(conn, trade_id):
    c = conn.cursor()
    c.execute("SELECT * FROM trades WHERE trade_id = ?", (trade_id,))
    row = c.fetchone()
    if row:
        return {
            'trade_id': row[0], 'buyer_id': row[1], 'buyer_username': row[2], 'seller_id': row[3],
            'seller_chat_id': row[4], 'seller_username': row[5], 'amount': row[6], 'crypto': row[7],
            'trade_details': row[8], 'buyer_approved': bool(row[9]), 'seller_approved': bool(row[10]),
            'seller_address': row[11], 'payment_verified': bool(row[12]), 'payment_timestamp': row[13],
            'completed': bool(row[14]), 'priority': bool(row[15])
        }
    return None

def get_trades_by_seller_id(conn, seller_chat_id):
    c = conn.cursor()
    c.execute("SELECT * FROM trades WHERE seller_id = ? AND seller_approved = 0 AND completed = 0", (seller_chat_id,))
    rows = c.fetchall()
    return [{
        'trade_id': row[0], 'buyer_id': row[1], 'buyer_username': row[2], 'seller_id': row[3],
        'seller_chat_id': row[4], 'seller_username': row[5], 'amount': row[6], 'crypto': row[7],
        'trade_details': row[8], 'buyer_approved': bool(row[9]), 'seller_approved': bool(row[10]),
        'seller_address': row[11], 'payment_verified': bool(row[12]), 'payment_timestamp': row[13],
        'completed': bool(row[14]), 'priority': bool(row[15])
    } for row in rows]

def get_active_trade_by_buyer_id(conn, buyer_id):
    c = conn.cursor()
    c.execute("SELECT * FROM trades WHERE buyer_id = ? AND completed = 0", (buyer_id,))
    row = c.fetchone()
    if row:
        return {
            'trade_id': row[0], 'buyer_id': row[1], 'buyer_username': row[2], 'seller_id': row[3],
            'seller_chat_id': row[4], 'seller_username': row[5], 'amount': row[6], 'crypto': row[7],
            'trade_details': row[8], 'buyer_approved': bool(row[9]), 'seller_approved': bool(row[10]),
            'seller_address': row[11], 'payment_verified': bool(row[12]), 'payment_timestamp': row[13],
            'completed': bool(row[14]), 'priority': bool(row[15])
        }
    return None

# Database operations for private keys
def store_private_key(conn, crypto, private_key):
    encrypted_key = FERNET.encrypt(private_key.encode()).decode()
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO private_keys (crypto, encrypted_key)
        VALUES (?, ?)
    ''', (crypto.strip(), encrypted_key))
    conn.commit()
    logger.info(f"Stored private key for crypto: {crypto}")

def get_private_key(conn, crypto):
    c = conn.cursor()
    crypto_normalized = crypto.strip()
    c.execute("SELECT encrypted_key FROM private_keys WHERE crypto = ?", (crypto_normalized,))
    row = c.fetchone()
    logger.info(f"Queried private key for crypto: {crypto_normalized}, Found: {row is not None}")
    if row:
        return FERNET.decrypt(row[0].encode()).decode()
    return None

# Generate receiving address from private key
def generate_address(crypto, private_key):
    try:
        if crypto == "BTC":
            key = Key(import_key=private_key, is_private=True)
            return key.address()
        elif crypto == "LTC":
            key = Key(import_key=private_key, is_private=True, network='litecoin')
            return key.address()
        elif crypto in ["USDT (ERC20)", "USDT (BEP20)"]:
            w3 = Web3()
            try:
                account = w3.eth.account.from_key(private_key)
                return account.address
            except ValueError:
                if private_key.startswith('0x'):
                    account = w3.eth.account.from_key(private_key[2:])
                    return account.address
                raise ValueError("Invalid private key format for Ethereum/BSC")
        elif crypto == "USDT (TRC20)":
            tron = Tron()
            private_key_obj = PrivateKey(bytes.fromhex(private_key) if not private_key.startswith('0x') else private_key[2:])
            return private_key_obj.public_key.to_base58check_address()
        else:
            return "Unsupported cryptocurrency"
    except Exception as e:
        logger.error(f"Error generating address for {crypto}: {e}")
        return f"Error generating address: {str(e)}"

# Fetch crypto price in USD
def get_crypto_price(crypto):
    try:
        base = {
            "BTC": "bitcoin",
            "LTC": "litecoin",
            "USDT (TRC20)": "tether",
            "USDT (ERC20)": "tether",
            "USDT (BEP20)": "tether"
        }[crypto]
        url = f"https://api.coingecko.com/api/v3/simple/price?ids={base}&vs_currencies=usd"
        response = requests.get(url)
        response.raise_for_status()
        return response.json()[base]["usd"]
    except Exception as e:
        logger.error(f"Error fetching price for {crypto}: {e}")
        return None

# Verify payment on blockchain for exact amount + fee in USD
def verify_payment(crypto, address, expected_total_usd, payment_timestamp):
    try:
        price = get_crypto_price(crypto)
        if not price:
            return False, "Unable to fetch crypto price"
        
        time_threshold = payment_timestamp - 120
        expected_crypto = expected_total_usd / price
        
        if crypto == "BTC":
            url = f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/full?token={BLOCKCYPHER_API_KEY}"
            response = requests.get(url)
            response.raise_for_status()
            transactions = response.json().get("txs", [])
            for tx in transactions:
                tx_time = int(datetime.strptime(tx.get("confirmed", ""), "%Y-%m-%dT%H:%M:%SZ").timestamp()) if tx.get("confirmed") else 0
                if tx_time < time_threshold:
                    continue
                value = sum(v["value"] for v in tx.get("outputs", []) if v.get("addresses", []) == [address]) / 1e8
                if abs(value - expected_crypto) < 0.00000001:  # Exact match within small tolerance
                    return True, f"Received {value:.8f} BTC (equivalent to ${expected_total_usd:.2f})"
            return False, f"Expected exactly {expected_crypto:.8f} BTC (${expected_total_usd:.2f}), no matching transaction found"
        
        elif crypto == "LTC":
            url = f"https://api.blockcypher.com/v1/ltc/main/addrs/{address}/full?token={BLOCKCYPHER_API_KEY}"
            response = requests.get(url)
            response.raise_for_status()
            transactions = response.json().get("txs", [])
            for tx in transactions:
                tx_time = int(datetime.strptime(tx.get("confirmed", ""), "%Y-%m-%dT%H:%M:%SZ").timestamp()) if tx.get("confirmed") else 0
                if tx_time < time_threshold:
                    continue
                value = sum(v["value"] for v in tx.get("outputs", []) if v.get("addresses", []) == [address]) / 1e8
                if abs(value - expected_crypto) < 0.00000001:
                    return True, f"Received {value:.8f} LTC (equivalent to ${expected_total_usd:.2f})"
            return False, f"Expected exactly {expected_crypto:.8f} LTC (${expected_total_usd:.2f}), no matching transaction found"
        
        elif crypto == "USDT (TRC20)":
            tron = Tron()
            contract_address = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
            url = f"https://api.trongrid.io/v1/accounts/{address}/transactions/trc20?contract_address={contract_address}&api_key={TRONGRID_API_KEY}"
            response = requests.get(url)
            response.raise_for_status()
            transactions = response.json().get("data", [])
            for tx in transactions:
                tx_time = int(tx.get("block_timestamp", 0) / 1000)
                if tx_time < time_threshold:
                    continue
                value = int(tx.get("value", 0)) / 1e6
                if abs(value - expected_crypto) < 0.000001 and tx.get("to") == address:
                    return True, f"Received {value:.6f} USDT (TRC20) (equivalent to ${expected_total_usd:.2f})"
            return False, f"Expected exactly {expected_crypto:.6f} USDT (TRC20) (${expected_total_usd:.2f}), no matching transaction found"
        
        elif crypto == "USDT (ERC20)":
            w3 = Web3()
            contract_address = w3.to_checksum_address("0xdac17f958d2ee523a2206206994597c13d831ec7")
            url = f"https://api.etherscan.io/api?module=account&action=tokentx&contractaddress={contract_address}&address={address}&sort=desc&apikey={ETHERSCAN_API_KEY}"
            response = requests.get(url)
            response.raise_for_status()
            transactions = response.json().get("result", [])
            for tx in transactions:
                tx_time = int(tx.get("timeStamp", 0))
                if tx_time < time_threshold:
                    continue
                value = int(tx.get("value", 0)) / 1e6
                if abs(value - expected_crypto) < 0.000001 and tx.get("to").lower() == address.lower():
                    return True, f"Received {value:.6f} USDT (ERC20) (equivalent to ${expected_total_usd:.2f})"
            return False, f"Expected exactly {expected_crypto:.6f} USDT (ERC20) (${expected_total_usd:.2f}), no matching transaction found"
        
        elif crypto == "USDT (BEP20)":
            w3 = Web3()
            contract_address = w3.to_checksum_address("0x55d398326f99059ff775485246999027b3197955")
            url = f"https://api.bscscan.com/api?module=account&action=tokentx&contractaddress={contract_address}&address={address}&sort=desc&apikey={BSCSCAN_API_KEY}"
            response = requests.get(url)
            response.raise_for_status()
            transactions = response.json().get("result", [])
            for tx in transactions:
                tx_time = int(tx.get("timeStamp", 0))
                if tx_time < time_threshold:
                    continue
                value = int(tx.get("value", 0)) / 1e18
                if abs(value - expected_crypto) < 0.000000000000000001 and tx.get("to").lower() == address.lower():
                    return True, f"Received {value:.18f} USDT (BEP20) (equivalent to ${expected_total_usd:.2f})"
            return False, f"Expected exactly {expected_crypto:.18f} USDT (BEP20) (${expected_total_usd:.2f}), no matching transaction found"
        
        return False, "Unsupported cryptocurrency"
    except Exception as e:
        logger.error(f"Error verifying payment for {crypto}: {e}")
        return False, f"Verification failed: {str(e)}"

# Send funds to seller's address
async def send_funds(crypto, private_key, to_address, amount_usd):
    try:
        price = get_crypto_price(crypto)
        if not price:
            logger.error(f"Failed to fetch price for {crypto}")
            return False, "Unable to fetch crypto price"
        if amount_usd <= 0:
            logger.error(f"Invalid trade amount: {amount_usd} USD")
            return False, "Invalid trade amount"
        
        amount_crypto = amount_usd / price
        logger.info(f"Calculated {amount_crypto:.6f} {crypto} from {amount_usd:.2f} USD at price {price:.2f} USD/{crypto}")
        
        if crypto == "BTC":
            key = Key(import_key=private_key, is_private=True)
            from_address = key.address()
            url = f"https://api.blockcypher.com/v1/btc/main/addrs/{from_address}/balance?token={BLOCKCYPHER_API_KEY}"
            response = requests.get(url)
            balance = response.json().get("balance", 0) / 1e8
            if balance < amount_crypto:
                logger.error(f"Insufficient BTC balance: {balance:.8f} available, need {amount_crypto:.8f}")
                return False, f"Insufficient balance: {balance:.8f} BTC available"
            tx = Transaction()
            tx.add_output(to_address, amount_crypto)
            tx.sign(private_key)
            tx_raw = tx.raw_hex()
            url = f"https://api.blockcypher.com/v1/btc/main/txs/push?token={BLOCKCYPHER_API_KEY}"
            response = requests.post(url, json={"tx": tx_raw})
            response.raise_for_status()
            txid = response.json().get("tx", {}).get("hash")
            logger.info(f"BTC transaction sent: TXID {txid}")
            return True, f"Funds sent successfully. TXID: {txid}"
        
        elif crypto == "LTC":
            key = Key(import_key=private_key, is_private=True, network='litecoin')
            from_address = key.address()
            url = f"https://api.blockcypher.com/v1/ltc/main/addrs/{from_address}/balance?token={BLOCKCYPHER_API_KEY}"
            response = requests.get(url)
            balance = response.json().get("balance", 0) / 1e8
            if balance < amount_crypto:
                logger.error(f"Insufficient LTC balance: {balance:.8f} available, need {amount_crypto:.8f}")
                return False, f"Insufficient balance: {balance:.8f} LTC available"
            tx = Transaction(network='litecoin')
            tx.add_output(to_address, amount_crypto)
            tx.sign(private_key)
            tx_raw = tx.raw_hex()
            url = f"https://api.blockcypher.com/v1/ltc/main/txs/push?token={BLOCKCYPHER_API_KEY}"
            response = requests.post(url, json={"tx": tx_raw})
            response.raise_for_status()
            txid = response.json().get("tx", {}).get("hash")
            logger.info(f"LTC transaction sent: TXID {txid}")
            return True, f"Funds sent successfully. TXID: {txid}"
        
        elif crypto == "USDT (TRC20)":
            tron = Tron()
            private_key_obj = PrivateKey(bytes.fromhex(private_key) if not private_key.startswith('0x') else private_key[2:])
            from_address = private_key_obj.public_key.to_base58check_address()
            contract_address = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
            amount = int(amount_crypto * 1e6)
            if amount <= 0:
                logger.error(f"Invalid USDT (TRC20) amount: {amount}")
                return False, f"Invalid transfer amount: {amount_crypto:.6f} USDT"
            contract = tron.get_contract(contract_address)
            txn = (
                contract.functions.transfer(to_address, amount)
                .with_owner(from_address)
                .build()
                .sign(private_key_obj)
            )
            result = tron.trx.broadcast(txn)
            txid = result["id"]
            logger.info(f"USDT (TRC20) transaction sent: TXID {txid}")
            return True, f"Funds sent successfully. TXID: {txid}"
        
        elif crypto == "USDT (ERC20)":
            w3 = Web3(Web3.HTTPProvider('https://mainnet.infura.io/v3/d858b82150b846cf84c9e85e9402b399'))
            account = w3.eth.account.from_key(private_key)
            from_address = account.address
            contract_address = w3.to_checksum_address("0xdac17f958d2ee523a2206206994597c13d831ec7")
            amount = int(amount_crypto * 1e6)
            if amount <= 0:
                logger.error(f"Invalid USDT (ERC20) amount: {amount}")
                return False, f"Invalid transfer amount: {amount_crypto:.6f} USDT"
            if not is_valid_ethereum_address(to_address):
                logger.error(f"Invalid USDT (ERC20) recipient address: {to_address}")
                return False, f"Invalid recipient address: {to_address}"
            contract_abi = [
                {"constant": False, "inputs": [{"name": "_to", "type": "address"}, {"name": "_value", "type": "uint256"}],
                 "name": "transfer", "outputs": [{"name": "", "type": "bool"}], "type": "function"}
            ]
            contract = w3.eth.contract(address=contract_address, abi=contract_abi)
            nonce = w3.eth.get_transaction_count(from_address)
            gas_price = w3.eth.gas_price
            tx = contract.functions.transfer(to_address, amount).build_transaction({
                'from': from_address,
                'nonce': nonce,
                'gas': 100000,
                'gasPrice': gas_price
            })
            signed_tx = w3.eth.account.sign_transaction(tx, private_key)
            tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            logger.info(f"USDT (ERC20) transaction sent: TXID {tx_hash.hex()}")
            return True, f"Funds sent successfully. TXID: {tx_hash.hex()}"
        
        elif crypto == "USDT (BEP20)":
            w3 = Web3(Web3.HTTPProvider('https://bsc-dataseed.binance.org/'))
            account = w3.eth.account.from_key(private_key)
            from_address = account.address
            contract_address = w3.to_checksum_address("0x55d398326f99059ff775485246999027b3197955")
            amount = int(amount_crypto * 1e18)
            if amount <= 0:
                logger.error(f"Invalid USDT (BEP20) amount: {amount}")
                return False, f"Invalid transfer amount: {amount_crypto:.6f} USDT"
            if not is_valid_ethereum_address(to_address):
                logger.error(f"Invalid USDT (BEP20) recipient address: {to_address}")
                return False, f"Invalid recipient address: {to_address}"
            contract_abi = [
                {"constant": False, "inputs": [{"name": "_to", "type": "address"}, {"name": "_value", "type": "uint256"}],
                 "name": "transfer", "outputs": [{"name": "", "type": "bool"}], "type": "function"}
            ]
            contract = w3.eth.contract(address=contract_address, abi=contract_abi)
            nonce = w3.eth.get_transaction_count(from_address)
            gas_price = w3.eth.gas_price
            tx = contract.functions.transfer(to_address, amount).build_transaction({
                'from': from_address,
                'nonce': nonce,
                'gas': 100000,
                'gasPrice': gas_price
            })
            signed_tx = w3.eth.account.sign_transaction(tx, private_key)
            tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            logger.info(f"USDT (BEP20) transaction sent: TXID {tx_hash.hex()}")
            return True, f"Funds sent successfully. TXID: {tx_hash.hex()}"
        
        return False, "Unsupported cryptocurrency"
    except Exception as e:
        logger.error(f"Error sending funds for {crypto}: {e}")
        return False, f"Failed to send funds: {str(e)}"

# New Feature: Inline Crypto Price Converter
async def convert(update, context):
    chat_id = update.effective_chat.id
    conn = context.bot_data['db']
    user = get_user(conn, chat_id)
    level = user['level'] if user else 'Novice'
    args = context.args
    if len(args) != 2:
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"💸 *Usage* | Level: {level}\n"
                f"/convert <amount> <crypto>\n"
                f"Example: /convert 100 BTC\n"
                f"Supported: BTC, LTC, USDT (TRC20), USDT (ERC20), USDT (BEP20)"
            ),
            parse_mode='Markdown'
        )
        return
    try:
        amount = float(args[0])
        crypto = args[1].upper()
        if crypto not in ["BTC", "LTC", "USDT (TRC20)", "USDT (ERC20)", "USDT (BEP20)"]:
            raise ValueError("Unsupported cryptocurrency")
        price = get_crypto_price(crypto)
        if not price:
            await context.bot.send_message(
                chat_id=chat_id,
                text=f"⚠️ *Error* | Level: {level}\nUnable to fetch price for {crypto}. Try again later.",
                parse_mode='Markdown'
            )
            return
        crypto_amount = amount / price
        decimals = 8 if crypto in ["BTC", "LTC"] else 6 if crypto in ["USDT (TRC20)", "USDT (ERC20)"] else 18
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"💸 *Conversion Result* | Level: {level}\n"
                f"${amount:,.2f} USD = {crypto_amount:.{decimals}f} {crypto}\n"
                f"Price: ${price:,.2f} USD/{crypto}\n"
                f"📊 Ready to trade? Use /escrow!"
            ),
            parse_mode='Markdown'
        )
    except ValueError as e:
        await context.bot.send_message(
            chat_id=chat_id,
            text=f"⚠️ *Error* | Level: {level}\nInvalid input. {str(e)}\nUse: /convert <amount> <crypto>",
            parse_mode='Markdown'
        )

# New Feature: Escrow Fee Calculator
async def fee(update, context):
    chat_id = update.effective_chat.id
    conn = context.bot_data['db']
    user = get_user(conn, chat_id)
    level = user['level'] if user else 'Novice'
    args = context.args
    if len(args) != 1:
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"🧮 *Usage* | Level: {level}\n"
                f"/fee <amount>\n"
                f"Example: /fee 100"
            ),
            parse_mode='Markdown'
        )
        return
    try:
        amount = float(args[0])
        if amount <= 0:
            raise ValueError("Amount must be greater than 0")
        fee = amount * 0.02
        total = amount + fee
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"🧮 *Escrow Fee Calculator* | Level: {level}\n"
                f"Trade Amount: ${amount:,.2f}\n"
                f"Escrow Fee (2%): ${fee:,.2f}\n"
                f"Total: ${total:,.2f}\n"
                f"📊 Ready to trade? Use /escrow!"
            ),
            parse_mode='Markdown'
        )
    except ValueError as e:
        await context.bot.send_message(
            chat_id=chat_id,
            text=f"⚠️ *Error* | Level: {level}\nInvalid amount. {str(e)}\nUse: /fee <amount>",
            parse_mode='Markdown'
        )

# New Feature: Generate Trade Receipt
def generate_trade_receipt(trade, txid):
    fee = trade['amount'] * 0.02
    total = trade['amount'] + fee
    price = get_crypto_price(trade['crypto'])
    crypto_amount = total / price if price else "N/A"
    decimals = 8 if trade['crypto'] in ["BTC", "LTC"] else 6 if trade['crypto'] in ["USDT (TRC20)", "USDT (ERC20)"] else 18
    crypto_amount_formatted = f"{crypto_amount:.{decimals}f}" if isinstance(crypto_amount, float) else crypto_amount
    return (
        f"📜 *SafeGuardEscrow Trade Receipt*\n"
        f"Trade ID: `{trade['trade_id']}`\n"
        f"Buyer: {trade['buyer_username']} (ID: {trade['buyer_id']})\n"
        f"Seller: {trade['seller_username']} (ID: {trade['seller_id']})\n"
        f"Amount: ${trade['amount']:.2f}\n"
        f"Escrow Fee (2%): ${fee:.2f}\n"
        f"Total: ${total:.2f} ({crypto_amount_formatted} {trade['crypto']})\n"
        f"Details: {trade['trade_details']}\n"
        f"Recipient Address: `{trade['seller_address']}`\n"
        f"Transaction ID: `{txid}`\n"
        f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"Status: ✅ Completed\n"
        f"🌟 Thank you for trading with SafeGuardEscrow!"
    )

# New Feature: Trade Milestone Tracker
async def check_trade_milestone(context, chat_id, trade_count):
    milestones = {1: "First Trade", 5: "High Five", 10: "Decade Dealer", 20: "Legendary Trader"}
    for count, title in milestones.items():
        if trade_count == count:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"🏆 *Trade Milestone Achieved!*\n"
                    f"Congratulations on your *{title}* milestone ({trade_count} trades)!\n"
                    f"Keep trading to reach the next level! 🎉"
                ),
                parse_mode='Markdown'
            )

# Define command handlers
async def list_private_keys(update, context):
    chat_id = update.effective_chat.id
    if chat_id != ADMIN_ID:
        await context.bot.send_message(chat_id=chat_id, text="🚫 *Unauthorized*: Only the admin can view private keys.")
        return
    conn = context.bot_data['db']
    c = conn.cursor()
    c.execute("SELECT crypto FROM private_keys")
    rows = c.fetchall()
    if not rows:
        await context.bot.send_message(chat_id=chat_id, text="🔍 No private keys found in the database.")
        return
    crypto_list = [row[0] for row in rows]
    await context.bot.send_message(chat_id=chat_id, text=f"🔑 *Stored Private Keys*:\n{', '.join(crypto_list)}", parse_mode='Markdown')

async def price(update, context):
    chat_id = update.effective_chat.id
    conn = context.bot_data['db']
    user = get_user(conn, chat_id)
    level = user['level'] if user else 'Novice'
    cryptos = ["BTC", "LTC", "USDT (TRC20)", "USDT (ERC20)", "USDT (BEP20)"]
    prices = []
    for crypto in cryptos:
        price = get_crypto_price(crypto)
        if price:
            prices.append(f"📈 *{crypto}*: ${price:,.2f} USD")
        else:
            prices.append(f"⚠️ *{crypto}*: Price unavailable")
    message = "\n".join(prices)
    await context.bot.send_message(
        chat_id=chat_id,
        text=(
            f"💰 *Current Crypto Prices* | Level: {level}\n"
            f"{message}\n\n"
            f"💸 Convert USD to crypto with /convert!\n"
            f"📊 Start trading with /escrow!"
        ),
        parse_mode='Markdown'
    )

async def history(update, context):
    chat_id = update.effective_chat.id
    conn = context.bot_data['db']
    user = get_user(conn, chat_id)
    level = user['level'] if user else 'Novice'
    c = conn.cursor()
    c.execute("SELECT trade_id, amount, crypto, completed, buyer_id, seller_chat_id, trade_details, buyer_username, seller_username FROM trades WHERE buyer_id = ? OR seller_chat_id = ?", (chat_id, chat_id))
    trades = c.fetchall()
    if not trades:
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"📜 *No Trade History* | Level: {level}\n"
                f"You haven't participated in any trades yet. Start one with /escrow!"
            ),
            parse_mode='Markdown'
        )
        return
    message = [f"📜 *Trade History* | Level: {level}"]
    for trade in trades:
        status = "Completed" if trade[3] else "Active"
        role = "Buyer" if trade[4] == chat_id else "Seller"
        other_party = trade[8] if role == "Buyer" else trade[7]
        message.append(f"ID: `{trade[0]}` | Role: {role} | Amount: ${trade[1]:.2f} {trade[2]} | Status: {status}")
        if not trade[3]:
            message.append(f"   └─ *Details*: {trade[6]}")
            message.append(f"   └─ *Actions*: Use buttons below")
    keyboard = []
    for trade in trades:
        if not trade[3]:
            keyboard.append([
                InlineKeyboardButton("ℹ️ Details", callback_data=f"view_{trade[0]}"),
                InlineKeyboardButton("🚨 Dispute", callback_data=f"dispute_{trade[0]}"),
                InlineKeyboardButton("⭐ Priority", callback_data=f"priority_{trade[0]}")
            ])
    reply_markup = InlineKeyboardMarkup(keyboard) if keyboard else None
    await context.bot.send_message(
        chat_id=chat_id,
        text="\n".join(message),
        parse_mode='Markdown',
        reply_markup=reply_markup
    )

async def start(update, context):
    user = update.effective_user
    username = user.username if user.username else user.first_name
    chat_id = update.effective_chat.id
    conn = context.bot_data['db']
    
    insert_user(conn, chat_id, username)
    user = get_user(conn, chat_id)
    level = user['level'] if user else 'Novice'
    
    message = (
        f"🌟 *Welcome to SafeGuardEscrow Bot, {username}!* 🌟\n"
        f"Level: *{level}* | Trade securely with confidence!\n\n"
        f"🔒 We hold funds safely until both parties agree.\n"
        f"💸 *Escrow Fee*: 2% of the trade amount (calculate with /fee).\n"
        f"📞 Need help? Use /contact for support within 24 hours.\n"
        f"💰 Check prices with /price or convert with /convert!\n\n"
        f"👉 *Get started by exploring below!*"
    )
    button1 = InlineKeyboardButton("ℹ️ What is Escrow?", callback_data="what")
    button2 = InlineKeyboardButton("📝 Instructions", callback_data="instructions")
    button3 = InlineKeyboardButton("⚖️ Terms", callback_data="terms")
    button4 = InlineKeyboardButton("🚀 Start Escrow", callback_data="start_escrow")
    keyboard = [
        [button1, button2],
        [button3, button4]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    sent_message = await context.bot.send_message(
        chat_id=chat_id,
        text=message,
        parse_mode='Markdown',
        reply_markup=reply_markup
    )
    context.user_data['start_message_id'] = sent_message.message_id
    trades = get_trades_by_seller_id(conn, chat_id)
    context.user_data['seller_chat_id'] = chat_id
    context.user_data['seller_username'] = username
    for trade in trades:
        update_trade(conn, trade['trade_id'], {
            'seller_chat_id': chat_id,
            'seller_username': username
        })
        trade_message = generate_trade_message(
            trade['trade_id'], "Seller", trade['buyer_username'], trade['amount'],
            trade['crypto'], trade['trade_details'], step=3
        )
        button1 = InlineKeyboardButton("✅ Approve", callback_data=f"approve_{trade['trade_id']}")
        button2 = InlineKeyboardButton("❌ Decline", callback_data=f"decline_{trade['trade_id']}")
        keyboard = [[button1, button2]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await context.bot.send_message(
            chat_id=chat_id,
            text=trade_message,
            parse_mode='Markdown',
            reply_markup=reply_markup
        )

async def help_command(update, context):
    chat_id = update.effective_chat.id
    conn = context.bot_data['db']
    user = get_user(conn, chat_id)
    level = user['level'] if user else 'Novice'
    await context.bot.send_message(
        chat_id=chat_id,
        text=(
            f"🆘 Need Help? | Level: {level}\n"
            f"SafeGuardEscrow Bot secures your crypto trades.\n\n"
            f"🔑 Commands:\n"
            f"/start - Begin your journey\n"
            f"/escrow - Start a new trade\n"
            f"/price - Check crypto prices\n"
            f"/convert - Convert USD to crypto\n"
            f"/fee - Calculate escrow fees\n"
            f"/history - View trade history\n"
            f"/priority - Prioritize a trade\n"
            f"/contact - Get support\n"
            f"/cancel - Cancel a trade\n"
            f"/dispute - Raise a dispute\n"
            f"/release_funds - Release funds\n"
            f"/refund - Request a refund\n\n"
            f"🌟 Start trading with /escrow!"
        )
        # parse_mode is omitted, defaulting to None (plain text)
    )

async def escrow(update, context):
    user = update.effective_user
    username = user.username if user.username else user.first_name
    chat_id = update.effective_chat.id
    conn = context.bot_data['db']
    user = get_user(conn, chat_id)
    level = user['level'] if user else 'Novice'
    
    active_trade = get_active_trade_by_buyer_id(conn, chat_id)
    if active_trade:
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"⚠️ *Active Trade Detected* | Level: {level}\n"
                f"You have an ongoing trade (ID: {active_trade['trade_id']}).\n"
                f"Please complete or cancel it using /cancel before starting a new one."
            ),
            parse_mode='Markdown'
        )
        return
    
    message = (
        f"👋 *Hello, {username}!* | Level: {level}\n"
        f"Let's start a secure trade. What's your role?\n\n"
        f"📊 *Progress*: [█ ▒ ▒ ▒ ▒] Step 1/5 - Choose Role\n"
        f"💡 *Tip*: Use /convert to check crypto amounts!"
    )
    button1 = InlineKeyboardButton("🛒 Buyer", callback_data="buyer")
    button2 = InlineKeyboardButton("💼 Seller", callback_data="seller")
    keyboard = [[button1, button2]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await context.bot.send_message(chat_id=chat_id, text=message, parse_mode='Markdown', reply_markup=reply_markup)
async def contact(update, context):
    chat_id = update.effective_chat.id
    conn = context.bot_data['db']
    user = get_user(conn, chat_id)
    level = user['level'] if user else 'Novice'
    message = await context.bot.send_message(
        chat_id=chat_id,
        text=(
            f"📞 Contact Support | Level: {level}\n"
            f"Please reply to this message with your issue, and our team will respond within 24 hours.\n"
            f"ℹ️ Include your trade ID (e.g., TRADEID12345) if applicable."
        )
    )
    context.user_data['state'] = 'awaiting_contact_reply'
    context.user_data['contact_message_id'] = message.message_id

async def cancel(update, context):
    chat_id = update.effective_chat.id
    conn = context.bot_data['db']
    user = get_user(conn, chat_id)
    level = user['level'] if user else 'Novice'
    
    active_trade = get_active_trade_by_buyer_id(conn, chat_id)
    if not active_trade:
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"ℹ️ *No Active Trade* | Level: {level}\n"
                f"You don't have any ongoing trades to cancel. Start a new one with /escrow!"
            ),
            parse_mode='Markdown'
        )
        return
    
    trade_id = active_trade['trade_id']
    message = (
        f"⚠️ *Confirm Cancellation* | Level: {level}\n"
        f"Are you sure you want to cancel Trade {trade_id}?\n"
        f"This action cannot be undone."
    )
    button1 = InlineKeyboardButton("✅ Yes, Cancel", callback_data=f"confirm_cancel_{trade_id}")
    button2 = InlineKeyboardButton("❌ No, Keep Trade", callback_data="keep_trade")
    keyboard = [[button1, button2]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await context.bot.send_message(chat_id=chat_id, text=message, parse_mode='Markdown', reply_markup=reply_markup)

async def dispute(update, context):
    chat_id = update.effective_chat.id
    conn = context.bot_data['db']
    user = get_user(conn, chat_id)
    level = user['level'] if user else 'Novice'
    
    active_trade = get_active_trade_by_buyer_id(conn, chat_id)
    if not active_trade:
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"ℹ️ *No Active Trade* | Level: {level}\n"
                f"You don't have any ongoing trades to dispute. Start a new one with /escrow!"
            ),
            parse_mode='Markdown'
        )
        return
    
    trade_id = active_trade['trade_id']
    context.user_data['state'] = 'awaiting_dispute_details'
    context.user_data['trade_id'] = trade_id
    await context.bot.send_message(
        chat_id=chat_id,
        text=(
            f"🚨 *Raise a Dispute* | Level: {level}\n"
            f"Trade ID: {trade_id}\n"
            f"Please provide detailed information about the issue with this trade.\n"
            f"📝 *Example*: 'Seller did not deliver the promised goods after payment.'\n"
            f"⏰ Our support team will review your case within {'12' if active_trade['priority'] else '24'} hours."
        ),
        parse_mode='Markdown'
    )

async def refund(update, context):
    chat_id = update.effective_chat.id
    conn = context.bot_data['db']
    user = get_user(conn, chat_id)
    level = user['level'] if user else 'Novice'
    
    active_trade = get_active_trade_by_buyer_id(conn, chat_id)
    if not active_trade:
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"ℹ️ *No Active Trade* | Level: {level}\n"
                f"You don't have any ongoing trades to refund. Start a new one with /escrow!"
            ),
            parse_mode='Markdown'
        )
        return
    if not active_trade['payment_verified']:
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"⏳ *Payment Not Verified* | Level: {level}\n"
                f"The payment for Trade {active_trade['trade_id']} is still being verified.\n"
                f"Please wait or contact support with /contact."
            ),
            parse_mode='Markdown'
        )
        return
    if active_trade['completed']:
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"✅ *Trade Completed* | Level: {level}\n"
                f"Trade {active_trade['trade_id']} has already been finalized. Refunds are not possible."
            ),
            parse_mode='Markdown'
        )
        return
    
    trade_id = active_trade['trade_id']
    message = (
        f"💰 *Confirm Refund Request* | Level: {level}\n"
        f"Trade ID: {trade_id}\n"
        f"Amount to Refund: ${active_trade['amount']:.2f} {active_trade['crypto']} (excluding 2% fee)\n"
        f"Are you sure you want to request a refund and cancel this trade?\n"
        f"⚠️ This action cannot be undone."
    )
    button1 = InlineKeyboardButton("✅ Yes, Refund", callback_data=f"confirm_refund_{trade_id}")
    button2 = InlineKeyboardButton("❌ No, Cancel", callback_data="cancel_refund")
    keyboard = [[button1, button2]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await context.bot.send_message(chat_id=chat_id, text=message, parse_mode='Markdown', reply_markup=reply_markup)

async def process_refunded_funds(context):
    job_data = context.job.data
    trade_id = job_data['trade_id']
    refund_address = job_data['refund_address']
    chat_id = job_data['chat_id']
    conn = context.bot_data['db']
    trade = get_trade(conn, trade_id)
    if not trade:
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"⚠️ *Error* | Level: {get_user(conn, chat_id)['level']}\n"
                f"Trade {trade_id} not found. Please contact support with /contact."
            ),
            parse_mode='Markdown'
        )
        return
    private_key = get_private_key(conn, trade['crypto'])
    if not private_key:
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"⚠️ *Error* | Level: {get_user(conn, chat_id)['level']}\n"
                f"No private key found for {trade['crypto']}. Please contact support with /contact."
            ),
            parse_mode='Markdown'
        )
        return
    success, message = await send_funds(trade['crypto'], private_key, refund_address, trade['amount'])
    if success:
        c = conn.cursor()
        c.execute("DELETE FROM trades WHERE trade_id = ?", (trade_id,))
        conn.commit()
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"✅ *Refund Successful* | Level: {get_user(conn, chat_id)['level']}\n"
                f"Trade ID: {trade_id}\n"
                f"Amount: ${trade['amount']:.2f} {trade['crypto']} has been sent to `{refund_address}`.\n"
                f"{message}\n"
                f"📜 The trade has been canceled.\n"
                f"🌟 Start a new trade with /escrow!"
            ),
            parse_mode='Markdown'
        )
        if trade.get('seller_chat_id'):
            await context.bot.send_message(
                chat_id=trade['seller_chat_id'],
                text=(
                    f"❌ *Trade Canceled and Refunded*\n"
                    f"Trade ID: {trade_id}\n"
                    f"The buyer requested a refund, and the trade has been canceled.\n"
                    f"📜 You can wait for a new trade request."
                ),
                parse_mode='Markdown'
            )
    else:
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"⚠️ *Refund Failed* | Level: {get_user(conn, chat_id)['level']}\n"
                f"Trade ID: {trade_id}\n"
                f"Failed to send refund: {message}\n"
                f"📞 Please contact support with /contact."
            ),
            parse_mode='Markdown'
        )
        if trade.get('seller_chat_id'):
            await context.bot.send_message(
                chat_id=trade['seller_chat_id'],
                text=(
                    f"⚠️ *Refund Failed*\n"
                    f"Trade ID: {trade_id}\n"
                    f"Failed to process refund for the buyer: {message}\n"
                    f"📞 The buyer has been advised to contact support."
                ),
                parse_mode='Markdown'
            )

async def priority(update, context):
    chat_id = update.effective_chat.id
    conn = context.bot_data['db']
    user = get_user(conn, chat_id)
    level = user['level'] if user else 'Novice'
    
    active_trade = get_active_trade_by_buyer_id(conn, chat_id)
    if not active_trade:
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"ℹ️ *No Active Trade* | Level: {level}\n"
                f"You don't have any ongoing trades to prioritize. Start a new one with /escrow!"
            ),
            parse_mode='Markdown'
        )
        return
    
    trade_id = active_trade['trade_id']
    if active_trade['priority']:
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"⭐ *Trade Already Prioritized* | Level: {level}\n"
                f"Trade {trade_id} is already marked as priority."
            ),
            parse_mode='Markdown'
        )
        return
    
    update_trade(conn, trade_id, {'priority': True})
    await context.bot.send_message(
        chat_id=chat_id,
        text=(
            f"⭐ *Priority Support Activated* | Level: {level}\n"
            f"Trade {trade_id} is now prioritized.\n"
            f"⏰ Our team will address any issues within 12 hours."
        ),
        parse_mode='Markdown'
    )
    if active_trade.get('seller_chat_id'):
        await context.bot.send_message(
            chat_id=active_trade['seller_chat_id'],
            text=(
                f"⭐ *Priority Notification*\n"
                f"Trade {trade_id} has been marked as priority by the buyer.\n"
                f"⏰ Any issues will be addressed within 12 hours."
            ),
            parse_mode='Markdown'
        )
    await context.bot.send_message(
        chat_id=ADMIN_ID,
        text=(
            f"⭐ *Priority Trade Alert*\n"
            f"Trade ID: {trade_id}\n"
            f"Buyer: {active_trade['buyer_username']} (ID: {active_trade['buyer_id']})\n"
            f"Seller: {active_trade['seller_username']} (ID: {active_trade['seller_id']})\n"
            f"Amount: ${active_trade['amount']:.2f} {active_trade['crypto']}\n"
            f"Details: {active_trade['trade_details']}\n"
            f"⏰ Please monitor for potential disputes within 12 hours."
        ),
        parse_mode='Markdown'
    )

async def release_funds(update, context):
    chat_id = update.effective_chat.id
    conn = context.bot_data['db']
    user = get_user(conn, chat_id)
    level = user['level'] if user else 'Novice'
    
    active_trade = get_active_trade_by_buyer_id(conn, chat_id)
    if not active_trade:
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"ℹ️ *No Active Trade* | Level: {level}\n"
                f"You don't have any ongoing trades. Start a new one with /escrow!"
            ),
            parse_mode='Markdown'
        )
        return
    if not active_trade['payment_verified']:
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"⏳ *Payment Not Verified* | Level: {level}\n"
                f"The payment is still being verified. Please wait or contact support with /contact."
            ),
            parse_mode='Markdown'
        )
        return
    if not active_trade['seller_address']:
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"📬 *No Seller Address* | Level: {level}\n"
                f"The seller hasn't provided a receiving address yet. Please wait or contact support with /contact."
            ),
            parse_mode='Markdown'
        )
        return
    if active_trade['completed']:
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"✅ *Trade Completed* | Level: {level}\n"
                f"This trade has already been finalized."
            ),
            parse_mode='Markdown'
        )
        return
    
    message = (
        f"💸 *Confirm Fund Release* | Level: {level}\n"
        f"Trade ID: {active_trade['trade_id']}\n"
        f"Amount: ${active_trade['amount']:.2f} {active_trade['crypto']} to {active_trade['seller_username']}\n"
        f"Are you sure you want to release the funds? This action cannot be undone.\n\n"
        f"📊 *Progress*: [█████] Step 5/5 - Complete Trade"
    )
    button1 = InlineKeyboardButton("✅ Yes, Release", callback_data=f"confirm_release_{active_trade['trade_id']}")
    button2 = InlineKeyboardButton("❌ No, Cancel", callback_data="cancel_release")
    keyboard = [[button1, button2]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await context.bot.send_message(chat_id=chat_id, text=message, parse_mode='Markdown', reply_markup=reply_markup)

# Generate trade confirmation message
def generate_trade_message(trade_id, role, other_party, amount, crypto, trade_details, step=3):
    fee = amount * 0.02
    total_amount = amount + fee
    steps = ["Choose Role", "Enter Details", "Approve Trade", "Send Payment", "Complete Trade"]
    progress = ["█" if i < step else "▒" for i in range(5)]
    progress_bar = f"[{' '.join(progress)}] Step {step}/5 - {steps[step-1]}"
    return (
        f"📋 *Trade Summary* 📋\n"
        f"Trade ID: `{trade_id}`\n"
        f"Role: *{role}*\n"
        f"{'Seller' if role == 'Buyer' else 'Buyer'}: *{other_party}*\n"
        f"Amount: *${amount:.2f}*\n"
        f"Escrow Fee (2%): *${fee:.2f}*\n"
        f"Total: *${total_amount:.2f} {crypto}*\n"
        f"Details: _{trade_details}_\n\n"
        f"📊 *Progress*: {progress_bar}\n"
        f"👉 Please review and approve or decline the trade."
    )

# Payment verification job
async def check_payment(context):
    job_data = context.job.data
    trade_id = job_data['trade_id']
    notified = job_data.get('notified', False)
    conn = context.bot_data['db']
    trade = get_trade(conn, trade_id)
    if not trade:
        return
    if trade['payment_verified'] or trade['completed']:
        return
    private_key = get_private_key(conn, trade['crypto'])
    if not private_key:
        await context.bot.send_message(
            chat_id=trade['buyer_id'],
            text=(
                f"⚠️ *Error* | Level: {get_user(conn, trade['buyer_id'])['level']}\n"
                f"No private key found for {trade['crypto']}. Please contact support with /contact."
            ),
            parse_mode='Markdown'
        )
        return
    escrow_address = generate_address(trade['crypto'], private_key)
    if "Error" in escrow_address:
        await context.bot.send_message(
            chat_id=trade['buyer_id'],
            text=(
                f"⚠️ *Error* | Level: {get_user(conn, trade['buyer_id'])['level']}\n"
                f"Failed to generate escrow address for {trade['crypto']}. Please contact support with /contact."
            ),
            parse_mode='Markdown'
        )
        return
    payment_timestamp = trade['payment_timestamp'] or int(time.time())
    verified, message = verify_payment(trade['crypto'], escrow_address, trade['amount'] + trade['amount'] * 0.02, payment_timestamp)
    if verified:
        update_trade(conn, trade_id, {'payment_verified': True})
        await context.bot.send_message(
            chat_id=trade['buyer_id'],
            text=(
                f"✅ *Payment Verified!* | Level: {get_user(conn, trade['buyer_id'])['level']}\n"
                f"{message}\n"
                f"📊 *Progress*: [█████] Step 5/5 - Complete Trade\n"
                f"👉 Please confirm delivery and use /release_funds to send the funds to the seller."
            ),
            parse_mode='Markdown'
        )
        await context.bot.send_message(
            chat_id=trade['seller_chat_id'],
            text=(
                f"✅ *Payment Verified!*\n"
                f"{message}\n"
                f"📊 *Progress*: [█████] Step 5/5 - Complete Trade\n"
                f"👉 Please deliver the goods/services to the buyer."
            ),
            parse_mode='Markdown'
        )
    else:
        if not notified:
            await context.bot.send_message(
                chat_id=trade['buyer_id'],
                text=(
                    f"⏳ *Payment Not Yet Verified* | Level: {get_user(conn, trade['buyer_id'])['level']}\n"
                    f"Details: {message}\n"
                    f"🔄 We'll continue checking silently.\n"
                    f"ℹ️ Ensure you sent the exact amount to the correct address. Need help? Use /contact."
                ),
                parse_mode='Markdown'
            )
            job_data['notified'] = True
        context.job_queue.run_once(check_payment, 60, data=job_data)

# Initial payment check after "Payment Made" button
async def check_payment_initial(context):
    trade_id = context.job.data['trade_id']
    conn = context.bot_data['db']
    trade = get_trade(conn, trade_id)
    if not trade:
        return
    if trade['payment_verified'] or trade['completed']:
        return
    private_key = get_private_key(conn, trade['crypto'])
    if not private_key:
        await context.bot.send_message(
            chat_id=trade['buyer_id'],
            text=(
                f"⚠️ *Error* | Level: {get_user(conn, trade['buyer_id'])['level']}\n"
                f"No private key found for {trade['crypto']}. Please contact support with /contact."
            ),
            parse_mode='Markdown'
        )
        return
    escrow_address = generate_address(trade['crypto'], private_key)
    if "Error" in escrow_address:
        await context.bot.send_message(
            chat_id=trade['buyer_id'],
            text=(
                f"⚠️ *Error* | Level: {get_user(conn, trade['buyer_id'])['level']}\n"
                f"Failed to generate escrow address for {trade['crypto']}. Please contact support with /contact."
            ),
            parse_mode='Markdown'
        )
        return
    payment_timestamp = trade['payment_timestamp'] or int(time.time())
    verified, message = verify_payment(trade['crypto'], escrow_address, trade['amount'] + trade['amount'] * 0.02, payment_timestamp)
    if verified:
        update_trade(conn, trade_id, {'payment_verified': True})
        await context.bot.send_message(
            chat_id=trade['buyer_id'],
            text=(
                f"✅ *Payment Verified!* | Level: {get_user(conn, trade['buyer_id'])['level']}\n"
                f"{message}\n"
                f"📊 *Progress*: [█████] Step 5/5 - Complete Trade\n"
                f"👉 Please confirm delivery and use /release_funds to send the funds to the seller."
            ),
            parse_mode='Markdown'
        )
        await context.bot.send_message(
            chat_id=trade['seller_chat_id'],
            text=(
                f"✅ *Payment Verified!*\n"
                f"{message}\n"
                f"📊 *Progress*: [█████] Step 5/5 - Complete Trade\n"
                f"👉 Please deliver the goods/services to the buyer."
            ),
            parse_mode='Markdown'
        )
    else:
        await context.bot.send_message(
            chat_id=trade['buyer_id'],
            text=(
                f"⏳ *Payment Not Yet Verified* | Level: {get_user(conn, trade['buyer_id'])['level']}\n"
                f"Details: {message}\n"
                f"🔄 We'll check again in 1 minute.\n"
                f"ℹ️ Ensure you sent the exact amount to the correct address. Need help? Use /contact."
            ),
            parse_mode='Markdown'
        )
        context.job_queue.run_once(check_payment, 60, data={'trade_id': trade_id, 'notified': False})

# Relevant part from button_handler for "payment_made" callback
async def button_handler(update, context):
    query = update.callback_query
    await query.answer()
    chat_id = query.message.chat.id
    user = query.from_user
    username = user.username if user.username else user.first_name
    conn = context.bot_data['db']
    user_data = get_user(conn, chat_id)
    level = user_data['level'] if user_data else 'Novice'

    if query.data == "payment_made":
        trade_id = context.user_data.get('trade_id')
        if not trade_id:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ *Error* | Level: {level}\n"
                    f"No active trade found. Start a new trade with /escrow."
                ),
                parse_mode='Markdown'
            )
            return
        trade = get_trade(conn, trade_id)
        if not trade:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ *Error* | Level: {level}\n"
                    f"Trade not found. Start a new trade with /escrow."
                ),
                parse_mode='Markdown'
            )
            return
        update_trade(conn, trade_id, {'payment_timestamp': int(time.time())})
        await context.bot.delete_message(chat_id=chat_id, message_id=query.message.message_id)
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"⏳ *Payment Notified* | Level: {level}\n"
                f"We'll verify your payment for Trade {trade_id} soon.\n"
                f"📊 *Progress*: [████ ▒] Step 5/5 - Verifying Payment\n"
                f"ℹ️ This may take a few minutes. You'll be notified once confirmed."
            ),
            parse_mode='Markdown'
        )
        context.job_queue.run_once(check_payment_initial, 10, data={'trade_id': trade_id})

# Relevant part from message_handler for sending payment instructions
async def message_handler(update, context):
    chat_id = update.effective_chat.id
    user = update.effective_user
    username = user.username if user.username else user.first_name
    text = update.message.text.strip()
    conn = context.bot_data['db']
    user_data = get_user(conn, chat_id)
    level = user_data['level'] if user_data else 'Novice'

    if 'state' not in context.user_data:
        return

    state = context.user_data.get('state')

    if state == 'awaiting_seller_address':
        seller_address = text.strip()
        trade_id = context.user_data.get('trade_id')
        if not trade_id:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ *Error* | Level: {level}\n"
                    f"No active trade found. Start a new trade with /escrow."
                ),
                parse_mode='Markdown'
            )
            return
        trade = get_trade(conn, trade_id)
        if not trade:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ *Error* | Level: {level}\n"
                    f"Trade not found. Start a new trade with /escrow."
                ),
                parse_mode='Markdown'
            )
            return
        if trade['crypto'] in ["USDT (ERC20)", "USDT (BEP20)"] and not is_valid_ethereum_address(seller_address):
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ *Error* | Level: {level}\n"
                    f"Invalid {trade['crypto']} address. Please provide a valid address (e.g., 0x123...)."
                ),
                parse_mode='Markdown'
            )
            return
        update_trade(conn, trade_id, {'seller_address': seller_address})
        private_key = get_private_key(conn, trade['crypto'])
        if not private_key:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ *Error* | Level: {level}\n"
                    f"No private key found for {trade['crypto']}. Please contact support with /contact."
                ),
                parse_mode='Markdown'
            )
            return
        escrow_address = generate_address(trade['crypto'], private_key)
        if "Error" in escrow_address:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ *Error* | Level: {level}\n"
                    f"Failed to generate escrow address: {escrow_address}\n"
                    f"Please contact support with /contact."
                ),
                parse_mode='Markdown'
            )
            return
        fee = trade['amount'] * 0.02
        total_amount = trade['amount'] + fee
        price = get_crypto_price(trade['crypto'])
        crypto_amount = total_amount / price if price else None
        decimals = 8 if trade['crypto'] in ["BTC", "LTC"] else 6 if trade['crypto'] in ["USDT (TRC20)", "USDT (ERC20)"] else 18
        crypto_amount_text = f"{crypto_amount:.{decimals}f} {trade['crypto']}" if crypto_amount else f"${total_amount:.2f} USD (price unavailable)"
        message = (
            f"📬 *Seller Address Received* | Level: {level}\n"
            f"Trade ID: {trade_id}\n"
            f"Please send *{crypto_amount_text}* to the following escrow address:\n"
            f"`{escrow_address}`\n"
            f"⚠️ *Important*:\n"
            f"- Send the exact amount to avoid delays.\n"
            f"- Network fees are your responsibility.\n"
            f"- After sending, click 'Payment Made' below.\n"
            f"📊 *Progress*: [████ ▒] Step 4/5 - Send Payment"
        )
        button = InlineKeyboardButton("✅ Payment Made", callback_data="payment_made")
        keyboard = [[button]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await context.bot.send_message(
            chat_id=trade['buyer_id'],
            text=message,
            parse_mode='Markdown',
            reply_markup=reply_markup
        )
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"✅ *Address Submitted* | Level: {level}\n"
                f"Trade ID: {trade_id}\n"
                f"Your {trade['crypto']} address `{seller_address}` has been recorded.\n"
                f"Waiting for the buyer to send the payment.\n"
                f"📊 *Progress*: [████ ▒] Step 4/5 - Awaiting Payment"
            ),
            parse_mode='Markdown'
        )
        context.user_data['state'] = None

# Define callback query handler for inline buttons
async def button_handler(update, context):
    query = update.callback_query
    await query.answer()
    chat_id = query.message.chat.id
    user = query.from_user
    username = user.username if user.username else user.first_name
    conn = context.bot_data['db']
    user_data = get_user(conn, chat_id)
    level = user_data['level'] if user_data else 'Novice'

    if query.data == "buyer":
        try:
            await context.bot.delete_message(chat_id=chat_id, message_id=query.message.message_id)
        except Exception as e:
            logger.error(f"Failed to delete role selection message: {e}")
        message = (
            f"🛒 *You're the Buyer!* | Level: {level}\n"
            f"Please send the Seller's Telegram ID (numeric, e.g., 123456789).\n"
            f"ℹ️ *Tip*: Ask the seller to share their ID or start the bot with /start.\n"
            f"📊 *Progress*: [██ ▒ ▒ ▒] Step 2/5 - Enter Seller ID"
        )
        await context.bot.send_message(chat_id=chat_id, text=message, parse_mode='Markdown')
        context.user_data['state'] = 'awaiting_seller_id'
        context.user_data['buyer_id'] = chat_id
        context.user_data['buyer_username'] = username
    elif query.data == "seller":
        try:
            await context.bot.delete_message(chat_id=chat_id, message_id=query.message.message_id)
        except Exception as e:
            logger.error(f"Failed to delete role selection message: {e}")
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"💼 *You're the Seller!* | Level: {level}\n"
                f"Your Telegram ID is: `{chat_id}`\n"
                f"📩 Share this ID with the buyer to start a trade.\n"
                f"⏳ You'll be notified when a buyer initiates a trade with you."
            ),
            parse_mode='Markdown'
        )
        context.user_data['state'] = 'seller_selected'
        context.user_data['seller_chat_id'] = chat_id
        context.user_data['seller_username'] = username
    elif query.data in ["BTC", "USDT_TRC20", "USDT_ERC20", "USDT_BEP20", "LTC"]:
        crypto = {
            "BTC": "BTC",
            "USDT_TRC20": "USDT (TRC20)",
            "USDT_ERC20": "USDT (ERC20)",
            "USDT_BEP20": "USDT (BEP20)",
            "LTC": "LTC"
        }[query.data]
        try:
            await context.bot.delete_message(chat_id=chat_id, message_id=query.message.message_id)
        except Exception as e:
            logger.error(f"Failed to delete cryptocurrency selection message: {e}")
        context.user_data['crypto'] = crypto
        message = (
            f"💰 *Cryptocurrency Selected*: {crypto} | Level: {level}\n"
            f"Escrow Fee: 2% (use /fee to calculate)\n"
            f"Please enter the trade amount in USD (e.g., 100.50).\n"
            f"ℹ️ *Tip*: Use /convert to check crypto equivalent.\n"
            f"📊 *Progress*: [███ ▒ ▒] Step 3/5 - Enter Amount"
        )
        await context.bot.send_message(chat_id=chat_id, text=message, parse_mode='Markdown')
        context.user_data['state'] = 'awaiting_amount'
    elif query.data.startswith("approve_"):
        trade_id = query.data.split("_")[1]
        trade = get_trade(conn, trade_id)
        if not trade:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ *Error* | Level: {level}\n"
                    f"Trade not found. Please start a new trade with /escrow."
                ),
                parse_mode='Markdown'
            )
            return
        if trade['completed']:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"✅ *Trade Completed* | Level: {level}\n"
                    f"This trade has already been finalized."
                ),
                parse_mode='Markdown'
            )
            return
        message = (
            f"✅ *Confirm Approval* | Level: {level}\n"
            f"Trade ID: {trade_id}\n"
            f"Are you sure you want to approve this trade?\n\n"
            f"📊 *Progress*: [███ ▒ ▒] Step 3/5 - Approve Trade"
        )
        button1 = InlineKeyboardButton("✅ Yes, Approve", callback_data=f"confirm_approve_{trade_id}")
        button2 = InlineKeyboardButton("❌ No, Cancel", callback_data="cancel_approve")
        keyboard = [[button1, button2]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await context.bot.delete_message(chat_id=chat_id, message_id=query.message.message_id)
        await context.bot.send_message(chat_id=chat_id, text=message, parse_mode='Markdown', reply_markup=reply_markup)
    elif query.data.startswith("confirm_approve_"):
        trade_id = query.data.split("_")[2]
        trade = get_trade(conn, trade_id)
        if not trade:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ *Error* | Level: {level}\n"
                    f"Trade not found. Please start a new trade with /escrow."
                ),
                parse_mode='Markdown'
            )
            return
        if chat_id == trade['buyer_id']:
            update_trade(conn, trade_id, {'buyer_approved': True})
            await context.bot.delete_message(chat_id=chat_id, message_id=query.message.message_id)
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"✅ *Trade Approved* | Level: {level}\n"
                    f"Trade ID: {trade_id}\n"
                    f"Waiting for the seller to approve.\n"
                    f"📊 *Progress*: [███ ▒ ▒] Step 3/5 - Awaiting Seller Approval"
                ),
                parse_mode='Markdown'
            )
            if trade.get('seller_chat_id') and not trade['seller_approved']:
                message = generate_trade_message(
                    trade_id, "Seller", trade['buyer_username'], trade['amount'],
                    trade['crypto'], trade['trade_details'], step=3
                )
                button1 = InlineKeyboardButton("✅ Approve", callback_data=f"approve_{trade_id}")
                button2 = InlineKeyboardButton("❌ Decline", callback_data=f"decline_{trade_id}")
                keyboard = [[button1, button2]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await context.bot.send_message(
                    chat_id=trade['seller_chat_id'],
                    text=message,
                    parse_mode='Markdown',
                    reply_markup=reply_markup
                )
        elif chat_id == trade.get('seller_chat_id'):
            update_trade(conn, trade_id, {'seller_approved': True})
            await context.bot.delete_message(chat_id=chat_id, message_id=query.message.message_id)
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"✅ *Trade Approved* | Level: {level}\n"
                    f"Trade ID: {trade_id}\n"
                    f"Please provide your {trade['crypto']} wallet address to receive funds.\n"
                    f"ℹ️ *Example*: {generate_address(trade['crypto'], get_private_key(conn, trade['crypto']))}\n"
                    f"⚠️ Ensure the address is correct!\n"
                    f"📊 *Progress*: [████ ▒] Step 4/5 - Provide Address"
                ),
                parse_mode='Markdown'
            )
            if trade['buyer_approved']:
                await context.bot.send_message(
                    chat_id=trade['buyer_id'],
                    text=(
                        f"✅ *Trade Approved* | Level: {get_user(conn, trade['buyer_id'])['level']}\n"
                        f"Trade ID: {trade_id}\n"
                        f"The seller has approved the trade and will provide their wallet address soon.\n"
                        f"📊 *Progress*: [████ ▒] Step 4/5 - Awaiting Seller Address"
                    ),
                    parse_mode='Markdown'
                )
                context.user_data['state'] = 'awaiting_seller_address'
                context.user_data['trade_id'] = trade_id
    elif query.data.startswith("decline_"):
        trade_id = query.data.split("_")[1]
        trade = get_trade(conn, trade_id)
        if not trade:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ *Error* | Level: {level}\n"
                    f"Trade not found. Please start a new trade with /escrow."
                ),
                parse_mode='Markdown'
            )
            return
        if trade['completed']:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"✅ *Trade Completed* | Level: {level}\n"
                    f"This trade has already been finalized."
                ),
                parse_mode='Markdown'
            )
            return
        c = conn.cursor()
        c.execute("DELETE FROM trades WHERE trade_id = ?", (trade_id,))
        conn.commit()
        await context.bot.delete_message(chat_id=chat_id, message_id=query.message.message_id)
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"❌ *Trade Declined* | Level: {level}\n"
                f"Trade ID: {trade_id}\n"
                f"You have declined the trade. It has been canceled.\n"
                f"📊 Start a new trade with /escrow."
            ),
            parse_mode='Markdown'
        )
        other_party_id = trade['buyer_id'] if chat_id == trade.get('seller_chat_id') else trade.get('seller_chat_id')
        if other_party_id:
            await context.bot.send_message(
                chat_id=other_party_id,
                text=(
                    f"❌ *Trade Declined*\n"
                    f"Trade ID: {trade_id}\n"
                    f"The {'seller' if chat_id == trade['buyer_id'] else 'buyer'} has declined the trade.\n"
                    f"📊 Start a new trade with /escrow."
                ),
                parse_mode='Markdown'
            )
    elif query.data.startswith("confirm_cancel_"):
        trade_id = query.data.split("_")[2]
        trade = get_trade(conn, trade_id)
        if not trade:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ *Error* | Level: {level}\n"
                    f"Trade not found. Please start a new trade with /escrow."
                ),
                parse_mode='Markdown'
            )
            return
        c = conn.cursor()
        c.execute("DELETE FROM trades WHERE trade_id = ?", (trade_id,))
        conn.commit()
        await context.bot.delete_message(chat_id=chat_id, message_id=query.message.message_id)
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"❌ *Trade Canceled* | Level: {level}\n"
                f"Trade ID: {trade_id}\n"
                f"The trade has been canceled successfully.\n"
                f"📊 Start a new trade with /escrow."
            ),
            parse_mode='Markdown'
        )
        if trade.get('seller_chat_id'):
            await context.bot.send_message(
                chat_id=trade['seller_chat_id'],
                text=(
                    f"❌ *Trade Canceled*\n"
                    f"Trade ID: {trade_id}\n"
                    f"The buyer has canceled the trade.\n"
                    f"📜 You can wait for a new trade request."
                ),
                parse_mode='Markdown'
            )
    elif query.data == "keep_trade":
        await context.bot.delete_message(chat_id=chat_id, message_id=query.message.message_id)
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"✅ *Trade Kept Active* | Level: {level}\n"
                f"The trade remains active. Use /history to view details or /cancel to try again."
            ),
            parse_mode='Markdown'
        )
    elif query.data.startswith("confirm_release_"):
        trade_id = query.data.split("_")[2]
        trade = get_trade(conn, trade_id)
        if not trade:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ *Error* | Level: {level}\n"
                    f"Trade not found. Please start a new trade with /escrow."
                ),
                parse_mode='Markdown'
            )
            return
        if not trade['payment_verified']:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⏳ *Payment Not Verified* | Level: {level}\n"
                    f"The payment is still being verified. Please wait or contact support with /contact."
                ),
                parse_mode='Markdown'
            )
            return
        if not trade['seller_address']:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"📬 *No Seller Address* | Level: {level}\n"
                    f"The seller hasn't provided a receiving address yet. Please wait or contact support with /contact."
                ),
                parse_mode='Markdown'
            )
            return
        if trade['completed']:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"✅ *Trade Completed* | Level: {level}\n"
                    f"This trade has already been finalized."
                ),
                parse_mode='Markdown'
            )
            return
        private_key = get_private_key(conn, trade['crypto'])
        if not private_key:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ *Error* | Level: {level}\n"
                    f"No private key found for {trade['crypto']}. Please contact support with /contact."
                ),
                parse_mode='Markdown'
            )
            return
        success, message = await send_funds(trade['crypto'], private_key, trade['seller_address'], trade['amount'])
        if success:
            update_trade(conn, trade_id, {'completed': True})
            increment_trade_count(conn, trade['buyer_id'])
            increment_trade_count(conn, trade['seller_chat_id'])
            await check_trade_milestone(context, trade['buyer_id'], get_user(conn, trade['buyer_id'])['trade_count'])
            await check_trade_milestone(context, trade['seller_chat_id'], get_user(conn, trade['seller_chat_id'])['trade_count'])
            receipt = generate_trade_receipt(trade, message.split("TXID: ")[1] if "TXID: " in message else "N/A")
            await context.bot.delete_message(chat_id=chat_id, message_id=query.message.message_id)
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"💸 *Funds Released!* | Level: {level}\n"
                    f"Trade ID: {trade_id}\n"
                    f"{message}\n"
                    f"📜 Below is your trade receipt:\n\n{receipt}"
                ),
                parse_mode='Markdown'
            )
            await context.bot.send_message(
                chat_id=trade['seller_chat_id'],
                text=(
                    f"💰 *Funds Received!* | Level: {get_user(conn, trade['seller_chat_id'])['level']}\n"
                    f"Trade ID: {trade_id}\n"
                    f"{message}\n"
                    f"📜 Below is your trade receipt:\n\n{receipt}"
                ),
                parse_mode='Markdown'
            )
            feedback_message = (
                f"⭐ *Rate This Trade* | Level: {level}\n"
                f"Trade ID: {trade_id}\n"
                f"Please rate your experience (1-5 stars):"
            )
            buttons = [
                [InlineKeyboardButton(f"{i} ⭐", callback_data=f"rate_{trade_id}_{i}") for i in range(1, 6)]
            ]
            reply_markup = InlineKeyboardMarkup(buttons)
            await context.bot.send_message(chat_id=chat_id, text=feedback_message, parse_mode='Markdown', reply_markup=reply_markup)
            await context.bot.send_message(chat_id=trade['seller_chat_id'], text=feedback_message, parse_mode='Markdown', reply_markup=reply_markup)
        else:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ *Error* | Level: {level}\n"
                    f"Trade ID: {trade_id}\n"
                    f"Failed to release funds: {message}\n"
                    f"📞 Please contact support with /contact."
                ),
                parse_mode='Markdown'
            )
    elif query.data == "cancel_release":
        await context.bot.delete_message(chat_id=chat_id, message_id=query.message.message_id)
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"✅ *Release Canceled* | Level: {level}\n"
                f"The funds remain in escrow. Use /release_funds to try again or /contact for support."
            ),
            parse_mode='Markdown'
        )
    elif query.data.startswith("confirm_refund_"):
        trade_id = query.data.split("_")[2]
        trade = get_trade(conn, trade_id)
        if not trade:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ *Error* | Level: {level}\n"
                    f"Trade not found. Please contact support with /contact."
                ),
                parse_mode='Markdown'
            )
            return
        if not trade['payment_verified']:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⏳ *Payment Not Verified* | Level: {level}\n"
                    f"The payment is still being verified. Please wait or contact support with /contact."
                ),
                parse_mode='Markdown'
            )
            return
        if trade['completed']:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"✅ *Trade Completed* | Level: {level}\n"
                    f"This trade has already been finalized. Refunds are not possible."
                ),
                parse_mode='Markdown'
            )
            return
        await context.bot.delete_message(chat_id=chat_id, message_id=query.message.message_id)
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"💰 *Provide Refund Address* | Level: {level}\n"
                f"Trade ID: {trade_id}\n"
                f"Please enter your {trade['crypto']} wallet address to receive the refund (excluding 2% fee).\n"
                f"ℹ️ *Example*: {generate_address(trade['crypto'], get_private_key(conn, trade['crypto']))}\n"
                f"⚠️ Ensure the address is correct!"
            ),
            parse_mode='Markdown'
        )
        context.user_data['state'] = 'awaiting_refund_address'
        context.user_data['trade_id'] = trade_id
    elif query.data == "cancel_refund":
        await context.bot.delete_message(chat_id=chat_id, message_id=query.message.message_id)
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"✅ *Refund Canceled* | Level: {level}\n"
                f"The trade remains active. Use /refund to try again or /history to view details."
            ),
            parse_mode='Markdown'
        )
    elif query.data.startswith("rate_"):
        _, trade_id, rating = query.data.split("_")
        rating = int(rating)
        trade = get_trade(conn, trade_id)
        if not trade:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ *Error* | Level: {level}\n"
                    f"Trade not found. Please contact support with /contact."
                ),
                parse_mode='Markdown'
            )
            return
        context.user_data['trade_id'] = trade_id
        context.user_data['rating'] = rating
        context.user_data['state'] = 'awaiting_feedback_comment'
        await context.bot.delete_message(chat_id=chat_id, message_id=query.message.message_id)
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"⭐ *Rating: {rating} Star{'s' if rating != 1 else ''}* | Level: {level}\n"
                f"Trade ID: {trade_id}\n"
                f"Please provide a brief comment about your experience (or type 'none' to skip)."
            ),
            parse_mode='Markdown'
        )
    elif query.data.startswith("dispute_"):
        trade_id = query.data.split("_")[1]
        trade = get_trade(conn, trade_id)
        if not trade:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ *Error* | Level: {level}\n"
                    f"Trade not found. Please start a new trade with /escrow."
                ),
                parse_mode='Markdown'
            )
            return
        context.user_data['state'] = 'awaiting_dispute_details'
        context.user_data['trade_id'] = trade_id
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"🚨 *Raise a Dispute* | Level: {level}\n"
                f"Trade ID: {trade_id}\n"
                f"Please provide detailed information about the issue with this trade.\n"
                f"📝 *Example*: 'Seller did not deliver the promised goods after payment.'\n"
                f"⏰ Our support team will review your case within {'12' if trade['priority'] else '24'} hours."
            ),
            parse_mode='Markdown'
        )
    elif query.data.startswith("priority_"):
        trade_id = query.data.split("_")[1]
        trade = get_trade(conn, trade_id)
        if not trade:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ *Error* | Level: {level}\n"
                    f"Trade not found. Please start a new trade with /escrow."
                ),
                parse_mode='Markdown'
            )
            return
        if trade['priority']:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⭐ *Trade Already Prioritized* | Level: {level}\n"
                    f"Trade {trade_id} is already marked as priority."
                ),
                parse_mode='Markdown'
            )
            return
        update_trade(conn, trade_id, {'priority': True})
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"⭐ *Priority Support Activated* | Level: {level}\n"
                f"Trade {trade_id} is now prioritized.\n"
                f"⏰ Our team will address any issues within 12 hours."
            ),
            parse_mode='Markdown'
        )
        if trade.get('seller_chat_id'):
            await context.bot.send_message(
                chat_id=trade['seller_chat_id'],
                text=(
                    f"⭐ *Priority Notification*\n"
                    f"Trade {trade_id} has been marked as priority by the {'buyer' if chat_id == trade['buyer_id'] else 'seller'}.\n"
                    f"⏰ Any issues will be addressed within 12 hours."
                ),
                parse_mode='Markdown'
            )
        await context.bot.send_message(
            chat_id=ADMIN_ID,
            text=(
                f"⭐ *Priority Trade Alert*\n"
                f"Trade ID: {trade_id}\n"
                f"Buyer: {trade['buyer_username']} (ID: {trade['buyer_id']})\n"
                f"Seller: {trade['seller_username']} (ID: {trade['seller_id']})\n"
                f"Amount: ${trade['amount']:.2f} {trade['crypto']}\n"
                f"Details: {trade['trade_details']}\n"
                f"⏰ Please monitor for potential disputes within 12 hours."
            ),
            parse_mode='Markdown'
        )
    elif query.data == "what":
        await context.bot.edit_message_text(
            chat_id=chat_id,
            message_id=query.message.message_id,
            text=(
                f"ℹ️ *What is Escrow?* | Level: {level}\n"
                f"Escrow is a secure way to trade. SafeGuardEscrow holds funds until both parties (buyer and seller) agree the trade terms are met.\n"
                f"🔒 Funds are only released when both approve.\n"
                f"💸 A small 2% fee ensures security (use /fee to calculate).\n"
                f"🚀 Ready to trade? Use /escrow!"
            ),
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🔙 Back", callback_data="back_to_start")
            ]])
        )
    elif query.data == "instructions":
        await context.bot.edit_message_text(
            chat_id=chat_id,
            message_id=query.message.message_id,
            text=(
                f"📜 Instructions | Level: {level}\n"
                f"SafeGuardEscrow Bot helps you trade crypto securely.\n\n"
                f"🛠 How to Trade:\n"
                f"1. Start with /escrow and enter the seller's Telegram ID.\n"
                f"2. Choose a cryptocurrency (e.g., BTC, USDT, LTC).\n"
                f"3. Set the trade amount in USD.\n"
                f"4. Provide trade details and approve the trade.\n"
                f"5. Send payment to the escrow address.\n"
                f"6. Release funds with /release_funds or file a dispute with /dispute.\n\n"
                f"ℹ️ Tips:\n"
                f"- Check fees with /fee.\n"
                f"- View trade history with /history.\n"
                f"- Contact support with /contact.\n\n"
                f"🌟 Ready? Use /escrow to begin!"
            ),
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🔙 Back", callback_data="back_to_start")
            ]])
        )
    elif query.data == "start_escrow":
        await context.bot.delete_message(chat_id=chat_id, message_id=query.message.message_id)
        await escrow(update, context)
    elif query.data == "back_to_start":
        await context.bot.delete_message(chat_id=chat_id, message_id=query.message.message_id)
        await start(update, context)
    elif query.data == "terms":
        message = (
                f"⚖️ *Terms of Service* | Level: {level}\n"
                f"By using SafeGuardEscrow, you agree to:\n"
                f"1. Provide accurate trade information.\n"
                f"2. Pay a 2% escrow fee on all trades.\n"
                f"3. Comply with Telegram's and our platform's rules.\n"
                f"4. Resolve disputes through our arbitration process.\n"
                f"5. Not use the service for illegal activities.\n"
                f"📜 *Note*: We are not liable for losses due to user error or external factors.\n"
                f"💬 Questions? Use /contact for support.\n"
                f"🌟 Start a trade with /escrow!"
        )
        back_button = InlineKeyboardButton("⬅️ Back", callback_data="back_to_start")
        keyboard = [[back_button]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await context.bot.delete_message(chat_id=chat_id, message_id=query.message.message_id)
        await context.bot.send_message(
            chat_id=chat_id,
            text=message,
            parse_mode='Markdown', 
            reply_markup=reply_markup
        )
    elif query.data == "payment_made":
        trade_id = context.user_data.get('trade_id')
        if not trade_id:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ *Error* | Level: {level}\n"
                    f"No active trade found. Please start a new trade with /escrow."
                ),
                parse_mode='Markdown'
            )
            return
        trade = get_trade(conn, trade_id)
        if not trade:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ *Error* | Level: {level}\n"
                    f"Trade not found. Please start a new trade with /escrow."
                ),
                parse_mode='Markdown'
            )
            return
        update_trade(conn, trade_id, {'payment_timestamp': int(time.time())})
        await context.bot.delete_message(chat_id=chat_id, message_id=query.message.message_id)
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"⏳ *Payment Notified* | Level: {level}\n"
                f"Trade ID: {trade_id}\n"
                f"We'll verify your payment for Trade {trade_id} soon.\n"
                f"📊 *Progress*: [████ ▒] Step 4/5 - Verifying Payment\n"
                f"ℹ️ This may take a few minutes. You'll be notified once confirmed."
            ),
            parse_mode='Markdown'
        )
        await context.bot.send_message(
            chat_id=trade['seller_chat_id'],
            text=(
                f"⏳ *Payment Notified*\n"
                f"Trade ID: {trade_id}\n"
                f"The buyer has notified us of their payment\n"
                f"📊 *Progress*: [████ ▒] Step 4/5 - Verifying Payment\n"
                f"🔄 You'll be notified once confirmed."
            ),
            parse_mode='Markdown'
        )
        context.job_queue.run_once(check_payment_initial, 10, data={'trade_id': trade_id})
    elif query.data.startswith("view_"):
        trade_id = query.data.split("_")[1]
        trade = get_trade(conn, trade_id)
        if not trade:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ *Error* | Level: {level}\n"
                    f"Trade not found. Please start a new trade with /escrow."
                ),
                parse_mode='Markdown'
            )
            return
        role = "Buyer" if chat_id == trade['buyer_id'] else "Seller"
        other_party = trade['seller_username'] if role == "Buyer" else trade['buyer_username']
        fee = trade['amount'] * 0.02
        total = trade['amount'] + fee
        status = "Completed" if trade['completed'] else "Active"
        message = (
            f"📋 *Trade Details* | Level: {level}\n"
            f"Trade ID: `{trade_id}`\n"
            f"Role: *{role}*\n"
            f"{'Seller' if role == 'Buyer' else 'Buyer'}: *{other_party}*\n"
            f"Amount: *${trade['amount']:.2f} {trade['crypto']}*\n"
            f"Escrow Fee (2%): *${fee:.2f}*\n"
            f"Total: *${total:.2f}*\n"
            f"Details: _{trade['trade_details']}_\n"
            f"Status: *{status}*\n"
            f"Priority: *{'Yes' if trade['priority'] else 'No'}*"
        )
        await context.bot.send_message(chat_id=chat_id, text=message, parse_mode='Markdown')

# Define message handler for text input
async def handle_message(update, context):
    chat_id = update.effective_chat.id
    text = update.message.text.strip()
    user = update.effective_user
    username = user.username if user.username else user.first_name
    conn = context.bot_data['db']
    user_data = get_user(conn, chat_id)
    level = user_data['level'] if user_data else 'Novice'
    state = context.user_data.get('state')

    # Handle reply to contact message
    if state == 'awaiting_contact_reply' and update.message.reply_to_message:
        if update.message.reply_to_message.message_id == context.user_data.get('contact_message_id'):
            await context.bot.send_message(
                chat_id=ADMIN_ID,
                text=(
                    f"📞 New Support Request\n"
                    f"From: {username} (ID: {chat_id})\n"
                    f"Level: {level}\n"
                    f"Message: {text}\n"
                    f"🕒 Sent: {update.message.date.strftime('%Y-%m-%d %H:%M:%S UTC')}"
                )
            )
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"✅ Support Request Sent | Level: {level}\n"
                    f"Your message has been sent to our team. We'll respond within 24 hours.\n"
                    f"📞 Use /contact again for further issues."
                )
            )
            context.user_data['state'] = None
            context.user_data['contact_message_id'] = None
            return

    # Existing states
    if state == 'awaiting_seller_id':
        try:
            seller_id = int(text)
            seller_chat_id = seller_id
            seller = get_user(conn, seller_chat_id)
            if not seller:
                await context.bot.send_message(
                    chat_id=chat_id,
                    text=(
                        f"⚠️ Error | Level: {level}\n"
                        f"Seller ID {seller_id} not found. Please ask the seller to start the bot with /start."
                    )
                )
                return
            context.user_data['seller_id'] = seller_id
            context.user_data['seller_chat_id'] = seller_chat_id
            context.user_data['seller_username'] = seller['username']
            button1 = InlineKeyboardButton("BTC", callback_data="BTC")
            button2 = InlineKeyboardButton("LTC", callback_data="LTC")
            button3 = InlineKeyboardButton("USDT (TRC20)", callback_data="USDT_TRC20")
            button4 = InlineKeyboardButton("USDT (ERC20)", callback_data="USDT_ERC20")
            button5 = InlineKeyboardButton("USDT (BEP20)", callback_data="USDT_BEP20")
            keyboard = [
                [button1, button2],
                [button3, button4],
                [button5]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"✅ Seller Selected: {seller['username']} | Level: {level}\n"
                    f"Please select the cryptography for the trade.\n"
                    f"📊 Progress: [██ ▒ ▒ ▒] Step 2/5 - Select Crypto"
                ),
                reply_markup=reply_markup
            )
            context.user_data['state'] = 'awaiting_crypto'
        except ValueError:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ Error | Level: {level}\n"
                    f"Please enter a valid numeric Telegram ID for the seller."
                )
            )
    elif state == 'awaiting_amount':
        try:
            amount = float(text)
            if amount <= 0:
                raise ValueError("Amount must be greater than 0")
            context.user_data['amount'] = amount
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"💰 Amount Set: ${amount:.2f} | Level: {level}\n"
                    f"Please provide the trade details (e.g., 'Selling 1 BTC for $30,000').\n"
                    f"📊 Progress: [███ ▒ ▒] Step 3/5 - Enter Details"
                )
            )
            context.user_data['state'] = 'awaiting_details'
        except ValueError:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ Error | Level: {level}\n"
                    f"Please enter a valid amount in USD (e.g., 100.50)."
                )
            )
    elif state == 'awaiting_details':
        trade_id = generate_trade_id(conn)
        trade = {
            'trade_id': trade_id,
            'buyer_id': context.user_data['buyer_id'],
            'buyer_username': context.user_data['buyer_username'],
            'seller_id': context.user_data['seller_id'],
            'seller_chat_id': context.user_data['seller_chat_id'],
            'seller_username': context.user_data['seller_username'],
            'amount': context.user_data['amount'],
            'crypto': context.user_data['crypto'],
            'trade_details': text,
            'buyer_approved': False,
            'seller_approved': False,
            'priority': False
        }
        insert_trade(conn, trade)
        message = generate_trade_message(
            trade_id, "Buyer", trade['seller_username'], trade['amount'], trade['crypto'], trade['trade_details'], step=3
        )
        button1 = InlineKeyboardButton("✅ Approve", callback_data=f"approve_{trade_id}")
        button2 = InlineKeyboardButton("❌ Decline", callback_data=f"decline_{trade_id}")
        keyboard = [[button1, button2]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await context.bot.send_message(
            chat_id=chat_id,
            text=message,
            reply_markup=reply_markup
        )
        context.user_data['state'] = None
        context.user_data['trade_id'] = trade_id
    elif state == 'awaiting_seller_address':
        trade_id = context.user_data.get('trade_id')
        trade = get_trade(conn, trade_id)
        if not trade:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ Error | Level: {level}\n"
                    f"Trade not found. Please start a new trade with /escrow."
                )
            )
            return
        if chat_id != trade.get('seller_chat_id'):
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ Error | Level: {level}\n"
                    f"Only the seller can provide the wallet address."
                )
            )
            return
        if trade['crypto'] in ["USDT (ERC20)", "USDT (BEP20)"] and not is_valid_ethereum_address(text):
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ Error | Level: {level}\n"
                    f"Invalid {trade['crypto']} address. Please provide a valid address."
                )
            )
            return
        update_trade(conn, trade_id, {'seller_address': text})
        private_key = get_private_key(conn, trade['crypto'])
        if not private_key:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ Error | Level: {level}\n"
                    f"No private key found for {trade['crypto']}. Please contact support with /contact."
                )
            )
            return
        escrow_address = generate_address(trade['crypto'], private_key)
        if "Error" in escrow_address:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ Error | Level: {level}\n"
                    f"Failed to generate escrow address: {escrow_address}\n"
                    f"📞 Please contact support with /contact."
                )
            )
            return
        fee = trade['amount'] * 0.02
        total_amount = trade['amount'] + fee
        price = get_crypto_price(trade['crypto'])
        if not price:
            await context.bot.send_message(
                chat_id=trade['buyer_id'],
                text=(
                    f"⚠️ Price Fetch Failed | Level: {get_user(conn, trade['buyer_id'])['level']}\n"
                    f"Trade ID: {trade_id}\n"
                    f"Unable to fetch {trade['crypto']} price. Please send exactly ${total_amount:.2f} to the escrow address:\n\n"
                    f"📬 {escrow_address}\n\n"
                    f"Trade Amount: ${trade['amount']:.2f}\n"
                    f"Escrow Fee (2%): ${fee:.2f}\n"
                    f"Total to Send: ${total_amount:.2f}\n"
                    f"⚠️ Important: Use a price converter (e.g., /convert) to calculate the {trade['crypto']} amount.\n"
                    f"📊 Progress: [████ ▒] Step 4/5 - Send Payment\n"
                    f"👉 Click 'Payment Made' once sent."
                ),
                reply_markup=InlineKeyboardMarkup([[
                    InlineKeyboardButton("✅ Payment Made", callback_data="payment_made")
                ]])
            )
            return
        crypto_amount = total_amount / price
        decimals = 8 if trade['crypto'] in ["BTC", "LTC"] else 6 if trade['crypto'] in ["USDT (TRC20)", "USDT (ERC20)"] else 18
        crypto_amount_formatted = f"{crypto_amount:.{decimals}f}"
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"✅ Address Saved | Level: {level}\n"
                f"Trade ID: {trade_id}\n"
                f"Your {trade['crypto']} address has been recorded.\n"
                f"📊 Progress: [████ ▒] Step 4/5 - Awaiting Payment"
            )
        )
        await context.bot.send_message(
            chat_id=trade['buyer_id'],
            text=(
                f"💸 Send Payment | Level: {get_user(conn, trade['buyer_id'])['level']}\n"
                f"Trade ID: {trade_id}\n"
                f"You must send the total amount (trade amount + 2% escrow fee) to the escrow address below:\n\n"
                f"📬 {escrow_address}\n\n"
                f"Trade Amount: ${trade['amount']:.2f}\n"
                f"Escrow Fee (2%): ${fee:.2f}\n"
                f"Total to Send: ${total_amount:.2f} ({crypto_amount_formatted} {trade['crypto']})\n"
                f"⚠️ Important: Send exactly ${total_amount:.2f} (or {crypto_amount_formatted} {trade['crypto']}) to avoid delays.\n"
                f"📊 Progress: [████ ▒] Step 4/5 - Send Payment\n"
                f"👉 Click 'Payment Made' once sent."
            ),
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("✅ Payment Made", callback_data="payment_made")
            ]])
        )
        context.user_data['state'] = None
    elif state == 'awaiting_dispute_details':
        trade_id = context.user_data.get('trade_id')
        trade = get_trade(conn, trade_id)
        if not trade:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ Error | Level: {level}\n"
                    f"Trade not found. Please start a new trade with /escrow."
                )
            )
            return
        dispute_message = (
            f"🚨 New Dispute Filed\n"
            f"Trade ID: {trade_id}\n"
            f"Filed by: {username} (ID: {chat_id})\n"
            f"Role: {'Buyer' if chat_id == trade['buyer_id'] else 'Seller'}\n"
            f"Amount: ${trade['amount']:.2f} {trade['crypto']}\n"
            f"Issue: {text}\n"
            f"Priority: {'Yes' if trade['priority'] else 'No'}\n"
            f"⏰ Please review within {'12' if trade['priority'] else '24'} hours."
        )
        await context.bot.send_message(
            chat_id=ADMIN_ID,
            text=dispute_message
        )
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"✅ Dispute Filed | Level: {level}\n"
                f"Trade ID: {trade_id}\n"
                f"Your dispute has been submitted successfully.\n"
                f"📞 Our support team will reach out within {'12' if trade['priority'] else '24'} hours.\n"
                f"ℹ️ You can check the status with /history."
            )
        )
        other_party_id = trade['seller_chat_id'] if chat_id == trade['buyer_id'] else trade['buyer_id']
        if other_party_id:
            await context.bot.send_message(
                chat_id=other_party_id,
                text=(
                    f"🚨 Dispute Filed\n"
                    f"Trade ID: {trade_id}\n"
                    f"A dispute has been raised by the {'buyer' if chat_id == trade['seller_chat_id'] else 'seller'}.\n"
                    f"📞 Our support team will review within {'12' if trade['priority'] else '24'} hours."
                )
            )
        context.user_data['state'] = None
        context.user_data['trade_id'] = None
    elif state == 'awaiting_refund_address':
        trade_id = context.user_data.get('trade_id')
        trade = get_trade(conn, trade_id)
        if not trade:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ Error | Level: {level}\n"
                    f"Trade not found. Please contact support with /contact."
                )
            )
            return
        if trade['crypto'] in ["USDT (ERC20)", "USDT (BEP20)"] and not is_valid_ethereum_address(text):
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ Error | Level: {level}\n"
                    f"Invalid {trade['crypto']} address. Please provide a valid address."
                )
            )
            return
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"⏳ Processing Refund | Level: {level}\n"
                f"Trade ID: {trade_id}\n"
                f"Refund Address: {text}\n"
                f"Please wait approximately 5 minutes for the refund to process.\n"
                f"💰 You'll receive ${trade['amount']:.2f} {trade['crypto']} (excluding 2% fee)."
            )
        )
        context.job_queue.run_once(
            process_refunded_funds,
            300,  # 5 minutes
            data={'trade_id': trade_id, 'refund_address': text, 'chat_id': chat_id}
        )
        context.user_data['state'] = None
        context.user_data['trade_id'] = None
    elif state == 'awaiting_feedback_comment':
        trade_id = context.user_data.get('trade_id')
        rating = context.user_data.get('rating')
        if not trade_id or not rating:
            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    f"⚠️ Error | Level: {level}\n"
                    f"Feedback session expired. Please start a new trade with /escrow."
                )
            )
            return
        comment = text if text.lower() != 'none' else ''
        store_feedback(conn, trade_id, chat_id, rating, comment)
        await context.bot.send_message(
            chat_id=chat_id,
            text=(
                f"✅ Feedback Submitted | Level: {level}\n"
                f"Trade ID: {trade_id}\n"
                f"Rating: {rating} ⭐\n"
                f"Comment: {comment or 'None'}\n"
                f"🌟 Thank you for your feedback! Start a new trade with /escrow."
            )
        )
        context.user_data['state'] = None
        context.user_data['trade_id'] = None
        context.user_data['rating'] = None

# Error handler
async def error_handler(update, context):
    logger.error(f"Update {update} caused error {context.error}")
    if update and update.effective_chat:
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=(
                f"⚠️ *Oops, something went wrong!* | Level: {get_user(context.bot_data['db'], update.effective_chat.id)['level'] if update.effective_chat else 'Novice'}\n"
                f"Please try again or contact support with /contact."
            ),
            parse_mode='Markdown'
        )

# Main function to run the bot
def main():
    application = Application.builder().token(TELEGRAM_TOKEN).build()
    application.bot_data['db'] = init_db()
    
    # Command handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("escrow", escrow))
    application.add_handler(CommandHandler("contact", contact))
    application.add_handler(CommandHandler("cancel", cancel))
    application.add_handler(CommandHandler("dispute", dispute))
    application.add_handler(CommandHandler("refund", refund))
    application.add_handler(CommandHandler("priority", priority))
    application.add_handler(CommandHandler("release_funds", release_funds))
    application.add_handler(CommandHandler("price", price))
    application.add_handler(CommandHandler("convert", convert))
    application.add_handler(CommandHandler("fee", fee))
    application.add_handler(CommandHandler("history", history))
    application.add_handler(CommandHandler("list_private_keys", list_private_keys))
    
    # Callback query handler
    application.add_handler(CallbackQueryHandler(button_handler))
    
    # Message handler for text input
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    # Error handler
    application.add_error_handler(error_handler)
    
    # Start the bot
    logger.info("Starting SafeGuardEscrow Bot...")
    application.run_polling(allowed_updates=["message", "callback_query"])

if __name__ == '__main__':
    main()