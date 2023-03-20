# import numpy as np
from flask import Flask, session, abort, request, jsonify, render_template, redirect, url_for, flash, redirect

import os
# import wikipedia
import datetime
import hashlib
import json
from urllib.parse import urlparse
# from uuid import uuid4
from flask_cors import CORS

import requests

import asyncio
# from twilio.base.exceptions import TwilioRestException
# from authy.api import AuthyApiClient
from flask_bootstrap import Bootstrap
import openai

import os
# from os.path import join, dirname
# from dotenv import load_dotenv

# dotenv_path = '.env'
# load_dotenv(dotenv_path)

# mint_acct= os.environ.get("mint_acct")
# priv_key = PrivateKey(bytes.fromhex(os.environ.get("priv_key"))
import pandas as pd
import numpy as np
import datetime as dt
# import cbpro
# import matplotlib.pyplot as plt 
import time
# from web3.middleware import geth_poa_middleware
# from web3.gas_strategies.time_based import medium_gas_price_strategy
# # from eth_account.messages import encode_defunct

# from web3 import Web3
import json
# import librosa


# from web3 import Web3
# from web3 import middleware
# from web3.middleware import geth_poa_middleware
# from web3.auto import w3
# infura_url = "https://mainnet.infura.io/v3/5c9cb0b35a2742659dec6fc7680c16c4"
# web3 = Web3(Web3.HTTPProvider(infura_url))
# web3.middleware_onion.inject(geth_poa_middleware, layer=0)


# from coinbase.wallet.client import Client
import json
import pandas as pd 
# Before implementation, set environmental variables with the names API_KEY and API_SECRET
# from web3.auto import w3
from uuid import *
# client = Tron()
import braintree

from werkzeug.security import generate_password_hash, check_password_hash
from faunadb import query as q
from faunadb.client import FaunaClient
from faunadb.objects import Ref
from faunadb.errors import BadRequest, NotFound

config = braintree.Configuration.configure(environment=braintree.Environment.Sandbox,
        merchant_id="ENTER MERCHANT ID",
        public_key="ENTER PUBLIC KEY",
        private_key="ENTER PRIVATE KEY"
)

gateway = braintree.BraintreeGateway(config)
client = FaunaClient(secret="ENTER FAUNADB SECRET KEY",domain="db.us.fauna.com")

# from dotenv import load_dotenv
# load_dotenv('.env')
# apiKey = os.getenv("apiKey")
# apiSecret = os.getenv("apiSecret")
# passphrase = os.getenv("passphrase")

# auth_client = cbpro.AuthenticatedClient(apiKey,apiSecret,passphrase)
# auth_client_df = pd.DataFrame(auth_client.get_accounts()) 


# context = request.get.form('context')
class LaFrancBlockchain:

    def __init__(self):
        self.chain = []
        self.transactions = []
        self.create_block(proof=1, previous_hash='0000',context=str('Mine The First Block'),response=str("Block Has Not Been Mined"))
        self.nodes = set()

    def create_block(self, proof, previous_hash,context,response):
        # client = Tron()
        # my_url = 'http://lafranccoinbase.herokuapp.com/sakujoooCloud/'
        # opening up connection, downloading the page
        # html_page = requests.get('http://lafranccoinbase.herokuapp.com/sakujoooCloud/')
        # soup = soup(html_page.content, 'html.parser')
        # warning = soup.find('div', class_="lister-item mode-detail")
        # images = warning.findAll('img')
        # image = images
        # image = str('http://lafranccoinbase.herokuapp.com/sakujoooCloud/{}'.format(image[0:]))
        # command = takeCommand()
        # contract = client.get_contract('TXd7Bx2CyQ8c5C1BTberw6Fww8Mk4jnV1c')
        # mint_acct = os.getenv("mint_acct")
        # priv_key = PrivateKey(bytes.fromhex(os.getenv("priv_key")))
        # receiver=request.form.get("receiver Tron address")
        # context = request.form.get('context')
        # precision = contract.functions.decimals()
        block = {'index': len(self.chain) + 1,
                 'timestamp': str(datetime.datetime.now()),
                 'proof': proof,
                 'previous_hash': previous_hash,
                 'context': context,
                 'response': response,
                 'transactions': self.transactions
                 #  'Miner_Minting_Address':mint_acct,
                 #    'receiver':receiver ,
                 #    'image':image,
                #  'query': context,

                 #    'totalSupply':contract.functions.balanceOf('TBeDPd2zP3piD8zBXfRfXFwhBAHYcUVPgy')
                 }
        self.transactions = []
        self.chain.append(block)
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        while check_proof is False:
            hash_operation = hashlib.sha256(
                str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(
                str(proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] != '0000':
                return False
            previous_block = block
            block_index += 1
        return True

    # sender,receiver,amount # sender = sender receiver = receiver amount = amount
    def add_transaction(self,sender,receiver,amount):
        # mint_acct =os.getenv("mint_acct")
        # priv_key = os.getenv(PrivateKey(bytes.fromhex("priv_key")))
        # # web3.eth.mint_acct = mint_acct
        # receiver= request.form.get("receiver Tron address") #'TUKibtKtD9U5ceEiYhmeqD83k52viJANEX'

        previous_block = blockchain.get_previous_block()
        previous_proof = previous_block['proof']
        proof = blockchain.proof_of_work(previous_proof)
        previous_hash = blockchain.hash(previous_block)
        self.transactions.append({
            'sender': sender,
            'receiver':receiver,
            'amount':amount,
            # 'minter':mint_acct
        })
        previous_block = self.get_previous_block()
        return previous_block['index'] + 1

    def add_node(self, address):
        # address = 'http:127.0.0.1:8677/'
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)
        # node = parsed_url.
# Give the Chain a Reason to exist

    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)
        for node in network:
            response = requests.get(f'http://{node}/get_chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                if length > max_length and self.is_chain_valid(chain):
                    max_length = length
                    longest_chain = chain
        if longest_chain:
            self.chain = longest_chain
            return True
        return False



    # json = request.get_json() 
    # nodes = json.get('nodes')
    # for node in nodes:
    #     blockchain.add_node(node)
    # # response = {'message':'THE FOLLOWING NODES ARE CONNECTED',
    # # 'total_nodes': list(blockchain.nodes)} 
    # total_nodes = list(blockchain.nodes)
    # connected = 'THE FOLLOWING NODES ARE CONNECTED {}'.format(total_nodes)




app = Flask(__name__)
bootstrap = Bootstrap(app)
# Fclient = FaunaClient(secret="fnAEflNSoFAAQ0DqKRR3lLxOKA53IcVSdw2WL8un",domain="db.us.fauna.com")

cors = CORS(app, resources={r"/*": {"origins": ["http://yappolafranc.herokuapp.com/YappoLaFranc_gpt","http://yappolafranc.herokuapp.com/image_bot"]}})
# cors = CORS(infura_url, resources={r"/*": {"origins": "https://ropsten.infura.io/v3/89f69d97c5c44c35959cc4d15c0f0531"}})

app.config['BOOTSTRAP_BTN_STYLE'] = 'primary'  # default to 'secondary'
# app.config['BOOTSTRAP_BOOTSWATCH_THEME'] = 'lumen'
app.secret_key = 'ENTER APP KEY'

# engine = pyttsx3.init('sapi5')
# voices = engine.getProperty('voices')
# engine.setProperty('voice', voices[1].id)

# def speak(audio):
#     engine.say(audio)
#     engine.runAndWait()

TIMEOUT_SECONDS = 2

@app.route("/insult")
def insult():
    return render_template('insult.html')

@app.route('/image_bot')
def image_bot():
    return render_template('image_bot.html')


@app.route('/response')
def response():
    return render_template('response.html')

@app.route('/connected')
def connected():
    return render_template('connected.html')

@app.route('/about')
def about():
    return render_template('about.html')

def worker(ws, loop):
    asyncio.set_event_loop(loop)
    loop.run_until_complete(ws.start())


# @app.route('/wishMe')
# def wishMe():
#     hour = int(datetime.datetime.now().hour)
#     if hour>= 0 and hour<12:
#         speak("Good Morning !")

#     elif hour>= 12 and hour<18:
#         speak("Good Afternoon!")

#     else:
#         speak("Good Evening!")

#     assname =("Yappola Search")
#     speak("I am your Virtual  Assistant")
#     speak(assname)
#     return redirect('context.html')
# def usrname():
#     speak("What should i call you")
#     uname = takecontext()
#     speak("Welcome ")
#     speak(uname)
#     columns = shutil.get_terminal_size().columns

#     print("#####################".center(columns))
#     print("Welcome ", uname.center(columns))
#     print("#####################".center(columns))

#     speak("How can i Help you, ")

# def takecontext():

#     r = sr.Recognizer()

#     with sr.Microphone() as source:

#         speak("Listening...")
#         r.pause_threshold = 10
#         audio = r.listen(source)

#     try:
#         print("Recognizing...")
#         query = r.recognize_google(audio, language ='en-in')
#         speak(f"User said: {query}\n")

#     except Exception as e:
#         print(e)
#         speak("Unable to Recognize your voice.")
#         return "None"

#     return query


# @app.route('/context')
# def context():
#     return render_template('index.html')

@app.route('/')
def home():
    # if session.get('user_id'):
    #     flash('You are logged in!', 'warning')
    #     return redirect(url_for('dashboard'))

    # subscript = gateway.subscription.create({
    #     # "payment_method_token": create.customer.credit_cards[0].token,
    #     "plan_id": "YappoLaFranc_gpt_ID"
    # })
    

    # print(subscript)

# pass client_token to your front-end
    # client_token = gateway.client_token.generate({
    #     "customer_id": subscript.customer.id
    # })

    if session.get('user_id'):
        flash('You are logged in!', 'warning')
        return redirect(url_for('YappoLaFranc_gpt'))


    message = 'Welcome To The Official ChatGPT-LaFranc Decentralized AI Network !'
    
    fullChain = 'full blockchain {}, {}'.format(len(blockchain.chain),blockchain.chain)


    is_chain_replaced = blockchain.replace_chain()

    if is_chain_replaced:
        # response = {'message': 'NODES HAD DIFFERENT CHAINS , REPLACED BY LONGEST CHAIN',
        # 'new_chain': blockchain.chain }
        chain_replaced = 'NODES HAD DIFFERENT CHAINS , REPLACED BY LONGEST CHAIN'
        # data['status'] = 200 
        # data['data'] = message
    else:
        # response = {'message': 'NODE IS CONNECT TO LARGEST CHAIN',
        # 'actual_chain':blockchain.chain}
        chain_replaced = 'NODE IS CONNECT TO LARGEST CHAIN'
        # data['status'] = 200 
        # data['data'] = message 

    is_valid = blockchain.is_chain_valid(blockchain.chain)
    # message = {} 
    # data = {}
    if is_valid:
        # response = {'message': 'All good. The Blockchain is valid.'}
        valid = 'All good,Blockchain Is Valid' 
        # data['status'] = 200 
        # data['data'] = message
        # json = request.get_json() 
        # nodes = json.post('nodes')
        # for node in nodes:
        #     blockchain.add_node(node)
        # # response = {'message':'THE FOLLOWING NODES ARE CONNECTED',
        # # 'total_nodes': list(blockchain.nodes)} 
        # total_nodes = list(blockchain.nodes)
        # connected = 'THE FOLLOWING NODES ARE CONNECTED {}'.format(total_nodes)

    else:
        # response = {'message': 'Houston, we have a problemo. The Blockchain is not valid.'}
        valid = 'Houston, we have a problemo. The Blockchain is not valid' 
        # data['status'] = 200 
        # data['data'] = message

    # json = request.get_json() 
    # nodes = json.get('nodes')
    # for node in nodes:
    #     blockchain.add_node(node)
    # # response = {'message':'THE FOLLOWING NODES ARE CONNECTED',
    # # 'total_nodes': list(blockchain.nodes)} 
    # total_nodes = list(blockchain.nodes)
    # connected = 'THE FOLLOWING NODES ARE CONNECTED {}'.format(total_nodes)


    return render_template('index.html', message=message,fullChain=fullChain, valid = valid, chain_replaced=chain_replaced)


@app.route('/create',methods=['POST'])
def create():
    import re
    if session.get('user_id'):
            flash('You are logged in!', 'warning')
            return redirect(url_for('YappoLaFranc_gpt'))

    first_name = request.form.get("Enter First Name")
    last_name = request.form.get("Enter Last Name")
        
    result = braintree.Customer.create({
            "first_name": first_name,
            "last_name": last_name,
            "email": request.form.get("Enter Email"),
            "payment_method_nonce": 'fake-visa-checkout-visa-nonce',
            "credit_card": {
                "cardholder_name":first_name+' '+last_name,
                "number": request.form.get("Enter Credit/Debit Card Number"),
                "options": {
            "verify_card": True
            }
        }
        })
    id =result.customer.id
    print(result.customer.email)

        # token = gateway.client_token.generate( "customer_id": a_customer_id)
        # # braintree.CreditCardGateway.create()
    subscript = braintree.Subscription.create({
            "payment_method_token": result.customer.payment_methods[0].token,
            "plan_id": "YappoLaFranc_gpt_ID"
        })
    print(subscript)

    status = subscript.subscription.status
    print(status)
    method=result.customer.payment_methods
    print(method)
    subscript_ID = subscript.subscription.id


    if status !='Active':
        inactive='Account inactive'
        return render_template('index.html',inactive=inactive)
    if request.method =='POST':

        email = request.form['Enter Email']
        password = request.form['Create Password']
        name = request.form['Create Username']
        email_regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
        if not re.search(email_regex, email) or not 6 < len(password) < 20:
            flash('Invalid email or password!, password needs to be between 6 and 20 characters', 'warning')
            return render_template('index.html')
        if password != request.form['Confirm Password']:
            flash('password fields not equal', 'warning')
            return render_template('index.html')
        password = generate_password_hash(password)
        user = {'name': name, 'email': email, 'password': password,'Subscription ID':subscript_ID,'Status':subscript.subscription.status}
        print(user)
        try:
            # store user data to db
            new_user = client.query(q.create(
                q.collection('user'),
                {'data': user}
            ))
        except BadRequest:
            flash('Email already exists')
        else:
            session['user_id'] = new_user['ref'].id()
            flash('Account created successfully', 'success')
            return redirect(url_for('YappoLaFranc_gpt'))

    # return render_template('YappoLaFranc_gpt.html',create=result,id=id,subscript=subscript,status=status,method=method)

@app.route('/signin/', methods=['POST', 'GET'])
def signin():
    if session.get('user_id'):
            flash('You are logged in!', 'warning')
            return redirect(url_for('YappoLaFranc_gpt'))
    
    if request.method =='POST':
        # get the user details
        email = request.form['email']
        password = request.form['password']
        # verify if the user details exist
        try:
            user = client.query(
                q.get(q.match(q.index('user_by_email'), email))
                )

            print(user)
            # print(search_results)
            print(session)

            subscription = braintree.Subscription.find(user['data']['Subscription ID'])
            print(subscription)


            status = subscription.status_history[0].status
            print(status)

        except NotFound:
            flash('Invalid email or password', category='warning')
        else:
            if check_password_hash(user['data']['password'], password) and status =='Active':
                session['user_id'] = user['ref'].id()
                print(session['user_id'])

                flash('Signed in successfully', 'success')
                return redirect(url_for('YappoLaFranc_gpt'))
            else:
                flash('Invalid email or password', 'warning')
    return render_template('signin.html')


@app.route("/signout/")
def signout():
	if not session.get('user_id'):
		flash('You need to be logged in to do this!', 'warning')
	else:
		session.pop('user_id', None)
		flash('Signed out successfully', 'success')
	return redirect(url_for('home'))


@app.route('/YappoLaFranc_gpt')
def YappoLaFranc_gpt():

    if not session.get('user_id'):
        flash('You need to be logged in to view this page!', 'warning')
        return redirect(url_for('index'))

    return render_template('YappoLaFranc_gpt.html',token=token)


@app.route('/chain')
def chain():
    message = 'Welcome To The Official ChatGPT-LaFranc Decentralized AI Network !'
    
    fullChain = 'full blockchain {}, {}'.format(len(blockchain.chain),blockchain.chain)


    is_chain_replaced = blockchain.replace_chain()

    if is_chain_replaced:
        # response = {'message': 'NODES HAD DIFFERENT CHAINS , REPLACED BY LONGEST CHAIN',
        # 'new_chain': blockchain.chain }
        chain_replaced = 'NODES HAD DIFFERENT CHAINS , REPLACED BY LONGEST CHAIN'
        # data['status'] = 200 
        # data['data'] = message
    else:
        # response = {'message': 'NODE IS CONNECT TO LARGEST CHAIN',
        # 'actual_chain':blockchain.chain}
        chain_replaced = 'NODE IS CONNECT TO LARGEST CHAIN'
        # data['status'] = 200 
        # data['data'] = message 

    is_valid = blockchain.is_chain_valid(blockchain.chain)
    # message = {} 
    # data = {}
    if is_valid:
        # response = {'message': 'All good. The Blockchain is valid.'}
        valid = 'All good,Blockchain Is Valid' 
        # data['status'] = 200 
        # data['data'] = message
        # json = request.get_json() 
        # nodes = json.post('nodes')
        # for node in nodes:
        #     blockchain.add_node(node)
        # # response = {'message':'THE FOLLOWING NODES ARE CONNECTED',
        # # 'total_nodes': list(blockchain.nodes)} 
        # total_nodes = list(blockchain.nodes)
        # connected = 'THE FOLLOWING NODES ARE CONNECTED {}'.format(total_nodes)

    else:
        # response = {'message': 'Houston, we have a problemo. The Blockchain is not valid.'}
        valid = 'Houston, we have a problemo. The Blockchain is not valid' 
        # data['status'] = 200 
        # data['data'] = message

    # json = request.get_json() 
    # nodes = json.get('nodes')
    # for node in nodes:
    #     blockchain.add_node(node)
    # # response = {'message':'THE FOLLOWING NODES ARE CONNECTED',
    # # 'total_nodes': list(blockchain.nodes)} 
    # total_nodes = list(blockchain.nodes)
    # connected = 'THE FOLLOWING NODES ARE CONNECTED {}'.format(total_nodes)


    return render_template('chain.html', message=message,fullChain=fullChain, valid = valid, chain_replaced=chain_replaced)




@app.route('/enter_address')
def enter_address():
    return render_template('enter_address.html')

@app.route('/address', methods=['POST'])
def address():

    address = request.form['Enter Ethereum Address']

    user = {'EthereumAddress': address}
    print(user)
    # print(user)
    try:
            # store user data to db
        new_user = client.query(q.create(
            q.collection('EthereumAddress'),
            {'data': user}
        ))
    except BadRequest:
        flash('Email already exists')
    else:
        session['user_id'] = new_user['ref'].id()
        flash('Account created successfully', 'success')
        return redirect(url_for('YappoLaFranc_gpt'))



    return render_template('enter_address.html',address=address)



    # id = result

# "credit_card": {
#             "cardholder_name": "John Doe",
#             "cvv": "123",
#             "expiration_date": "12/2012",
#             "number": "4111111111111111",
#             "token": "my_token",
#             "billing_address": {
#                 "first_name": "John",
#                 "last_name": "Doe",
#                 "company": "Braintree",
#                 "street_address": "111 First Street",
#                 "extended_address": "Unit 1",
#                 "locality": "Chicago",
#                 "postal_code": "60606",
#                 "region": "IL",
#                 "country_name": "United States of America"
#             },
#             "options": {
#                 "verify_card": True,
#                 "verification_amount": "2.00"
#             }
#         },
#         "custom_fields": {
#             "my_key": "some value"
#         }
#     })



    
# def latestBlock():
#     web3.eth.getBlock('latest')
#     web3.eth.getBlock('latest')
#     web3.eth.getBlock('latest')
#     web3.eth.getBlock('latest')
#     web3.eth.getBlock('latest')
#     web3.eth.getBlock('latest')
#     web3.eth.getBlock('latest')
#     web3.eth.getBlock('latest')
#     web3.eth.getBlock('latest')
#     web3.eth.getBlock('latest')
#     web3.eth.getBlock('latest')
#     a = web3.eth.getBlock('latest')
#     import time 
#     time.sleep(3)
#     return a



import stripe
    
# @app.route('/tron_trade')
# def tron_trade():
#     message = 'Welcome To The Official ChatGPT-LaFranc Decentralized AI Network !'

#     return render_template('tron_trade.html',message=message)




blockchain = LaFrancBlockchain()

node_address = str(uuid4()).replace('-', '') #New
root_node = 'e36f0158f0aed45b3bc755dc52ed4560d' #New
pub_key ='pk_live_2pO0yUvt9xKyjAo9rca8Vkc600FWtgJuqZ'

@app.route("/response_bot", methods=["POST"])
def response_bot():
    import time

    if not session.get('user_id'):
        flash('You need to be logged in to view this page!', 'warning')
        return redirect(url_for('index'))

    openai.api_key = "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"
    context = request.form.get("Enter your question, Then Click the Button Below")
    # res = client.query(context)
    # answers = next(res.results).text
    # answers = str(answers)
    response = openai.Completion.create(
        model="text-davinci-003",
        prompt="Create an explanation: {}".format(context),
        temperature=0.7,
        max_tokens=1000,
        top_p=1,
        frequency_penalty=0,
        presence_penalty=0
    )
    # SpeakText(response.choices[0].text)
    time.sleep(1)

    # client = Tron()
    # client1 = Tron(network='nile')
    # amount =  1_000_000

    # receiver= request.form.get("Enter Tron Address:") 
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof']
    proof = blockchain.proof_of_work(previous_proof)
    previous_hash = blockchain.hash(previous_block)
    # self.block['context'] = context
    

    # txn1 = (client.trx.transfer(mint_acct,receiver,1_000)
    #     .memo("did it work")
    #     .build()
    #     .sign(priv_key)
    #     )
    # tx_hash1 = txn1.txid
    # txn1.broadcast()


    # contract = client.get_contract("TXd7Bx2CyQ8c5C1BTberw6Fww8Mk4jnV1c") 
    # txn = (
    #     contract.functions.transfer(receiver, 1_000_000)
    #     .with_owner(mint_acct) 
    #     .build()
    #     .sign(priv_key)
    #     )
    # tx_hash = txn.txid    
    # # tx_hash = hash(tx_hash)+hash(tx_hash)**2
    # txn.broadcast()
    trans = blockchain.add_transaction(sender = root_node, receiver = node_address, amount = 1.15)
    
    block = blockchain.create_block(proof, previous_hash,context,response.choices[0].text) 
    
    message= 'Congratulations, you just mined GPT Block {} at {} !, Proof of work {}, previous hash {}\n, block {}, transactions: {}'.format(block['index'],block['timestamp'],block['proof'],block['previous_hash'],block,block['transactions']) #\n transactions{}, \n LaFranc-TRX HASH {}, ,RECEIVING MINTER {},tx_hash,block['transactions'],receiver

    # import re
    # my_new_text = re.sub('[^ a-zA-Z0-9]', '',response.choices[0].text)
    # from PIL import Image, ImageFont, ImageDraw
    # my_image = Image.open("static/LoGO.jpg")
    # # title_font = ImageFont.truetype('playfair-font.ttf', 200)
    # title_text = response.choices[0].text
    # image_editable = ImageDraw.Draw(my_image)
    # image_editable.text((15,15), title_text, (10, 34, 109),direction='ltr;')
    # my_image.save("static/result.jpg")


    is_chain_replaced = blockchain.replace_chain()

    if is_chain_replaced:
        # response = {'message': 'NODES HAD DIFFERENT CHAINS , REPLACED BY LONGEST CHAIN',
        # 'new_chain': blockchain.chain }
        chain_replaced = 'NODES HAD DIFFERENT CHAINS , REPLACED BY LONGEST CHAIN'
        # data['status'] = 200 
        # data['data'] = message
    else:
        # response = {'message': 'NODE IS CONNECT TO LARGEST CHAIN',
        # 'actual_chain':blockchain.chain}
        chain_replaced = 'NODE IS CONNECT TO LARGEST CHAIN'
        # data['status'] = 200 
        # data['data'] = message 
    # command = context 
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    # message = {} 
    # data = {}
    if is_valid:
        # response = {'message': 'All good. The Blockchain is valid.'}
        valid = 'All good,Blockchain Is Valid' 
        # data['status'] = 200 
        # data['data'] = message
    else:
        # response = {'message': 'Houston, we have a problemo. The Blockchain is not valid.'}
        valid = 'Houston, we have a problemo. The Blockchain is not valid' 
        # data['status'] = 200 
        # data['data'] = message
    # while True:
    #     # command=command
    #     # if command == "who are you":
    #     #     answers = ("I am yappola \_(^^)_/")
    #     # if command == "who created you" or "Who Created You?":
    #     #     answers = ("Yappola \_(^^)_/")
    #     #     return render_template('study_bot.html', answers=answers)
    #     try:
    #         app_id = "5PL6G8-KRH7PUAAH5"
    #         client = wolframalpha.Client(app_id)
    #         res = client.query(command)
    #         answers = next(res.results).text
    #         answers = str(answers)
    #         print(answers)
    #         # voice = speak("The answer is "+answers)
    #     except:
    #         try:
    #             command = command.split(' ')
    #             command = command.join(command[2:])  # input[2:]
    #             answers = wikipedia.summary(command)
    #             # voice = speak("Searching for context "+context)
    #         except:
    #             answers = 'No more relevant information'
    #             # voice = speak(answers)
    #     break
    print(session)

    return render_template("YappoLaFranc_gpt.html", result=response.choices[0].text ,message=message,valid=valid,chain_replaced=chain_replaced,trans=trans) #answers=answers

@app.route("/image_bot", methods=["POST"])
def image():
    import time 

    if not session.get('user_id'):
        flash('You need to be logged in to view this page!', 'warning')
        return redirect(url_for('index'))

    openai.api_key = "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"
    prompt = request.form.get('Enter Media To Produce')
    response = openai.Image.create(
        prompt=prompt,
        n=1,
        size="512x512"
    )
    image_url = response['data'][0]['url']
    time.sleep(1)

    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof']
    proof = blockchain.proof_of_work(previous_proof)
    previous_hash = blockchain.hash(previous_block)
    trans = blockchain.add_transaction(sender = root_node, receiver = node_address, amount = 1.15)
    block = blockchain.create_block(proof, previous_hash,prompt,image_url) 
    message= 'Congratulations, you just mined GPT Block {} at {} !, Proof of work {}, previous hash {}\n, block {}, transactions: {}'.format(block['index'],block['timestamp'],block['proof'],block['previous_hash'],block,block['transactions']) #\n transactions{}, \n LaFranc-TRX HASH {}, ,RECEIVING MINTER {},tx_hash,block['transactions'],receiver
    
    
    is_chain_replaced = blockchain.replace_chain()

    if is_chain_replaced:
        chain_replaced = 'NODES HAD DIFFERENT CHAINS , REPLACED BY LONGEST CHAIN'

    else:
        chain_replaced = 'NODE IS CONNECT TO LARGEST CHAIN'

    is_valid = blockchain.is_chain_valid(blockchain.chain)

    if is_valid:
        valid = 'All good,Blockchain Is Valid' 
    else:
        valid = 'Houston, we have a problemo. The Blockchain is not valid' 

    return render_template("YappoLaFranc_gpt.html", image=image_url,message=message,valid=valid,chain_replaced=chain_replaced,trans=trans)





@app.route("/insult_bot", methods=["POST"])
def insult_bot():
    openai.api_key = "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"
    context = request.form.get("Enter your question, Then Click the Button Below")
    # res = client.query(context)
    # answers = next(res.results).text
    # answers = str(answers)
    response = openai.Completion.create(
        model="text-davinci-003",
        prompt="Create an insult for: {}".format(context),
        temperature=0.7,
        max_tokens=1000,
        top_p=1,
        frequency_penalty=0,
        presence_penalty=0
    )
    # SpeakText(response.choices[0].text)

    # client = Tron()
    # client1 = Tron(network='nile')
    # amount =  1_000_000

    # receiver= request.form.get("Enter Tron Address:") 
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof']
    proof = blockchain.proof_of_work(previous_proof)
    previous_hash = blockchain.hash(previous_block)
    # self.block['context'] = context
    

    # txn1 = (client.trx.transfer(mint_acct,receiver,1_000)
    #     .memo("did it work")
    #     .build()
    #     .sign(priv_key)
    #     )
    # tx_hash1 = txn1.txid
    # txn1.broadcast()


    # contract = client.get_contract("TXd7Bx2CyQ8c5C1BTberw6Fww8Mk4jnV1c") 
    # txn = (
    #     contract.functions.transfer(receiver, 1_000_000)
    #     .with_owner(mint_acct) 
    #     .build()
    #     .sign(priv_key)
    #     )
    # tx_hash = txn.txid    
    # # tx_hash = hash(tx_hash)+hash(tx_hash)**2
    # txn.broadcast()
    trans = blockchain.add_transaction(sender = root_node, receiver = node_address, amount = 1.15)
    
    block = blockchain.create_block(proof, previous_hash,context,response.choices[0].text) 
    # block.
    
    # response = {'message': 'Congratulations, you just mined a GPT block !',
    #             'index': block['index'],
    #             'timestamp': block['timestamp'],
    #             'proof': block['proof'],
    #             'previous_hash': block['previous_hash'],
    #             # 'LFR-TRX_HASH': tx_hash,
    #             # 'transactions': block['transactions'],
    #             # 'receiver':receiver,
    #             'context': block['context']}

    message= 'Congratulations, you just mined GPT Block {} at {} !, Proof of work {}, previous hash {}\n, block {}, transactions: {}'.format(block['index'],block['timestamp'],block['proof'],block['previous_hash'],block,block['transactions']) #\n transactions{}, \n LaFranc-TRX HASH {}, ,RECEIVING MINTER {},tx_hash,block['transactions'],receiver

    # import re
    # my_new_text = re.sub('[^ a-zA-Z0-9]', '', text)
    # from PIL import Image, ImageFont, ImageDraw
    # my_image = Image.open("static/LoGO.jpg")
    # # title_font = ImageFont.truetype('playfair-font.ttf', 200)
    # title_text = response.choices[0].text
    # image_editable = ImageDraw.Draw(my_image)
    # image_editable.text((15,15), title_text, (10, 34, 109),direction='ltr;')
    # my_image.save("static/result.jpg")


    is_chain_replaced = blockchain.replace_chain()

    if is_chain_replaced:
        # response = {'message': 'NODES HAD DIFFERENT CHAINS , REPLACED BY LONGEST CHAIN',
        # 'new_chain': blockchain.chain }
        chain_replaced = 'NODES HAD DIFFERENT CHAINS , REPLACED BY LONGEST CHAIN'
        # data['status'] = 200 
        # data['data'] = message
    else:
        # response = {'message': 'NODE IS CONNECT TO LARGEST CHAIN',
        # 'actual_chain':blockchain.chain}
        chain_replaced = 'NODE IS CONNECT TO LARGEST CHAIN'
        # data['status'] = 200 
        # data['data'] = message 
    # command = context 
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    # message = {} 
    # data = {}
    if is_valid:
        # response = {'message': 'All good. The Blockchain is valid.'}
        valid = 'All good,Blockchain Is Valid' 
        # data['status'] = 200 
        # data['data'] = message
    else:
        # response = {'message': 'Houston, we have a problemo. The Blockchain is not valid.'}
        valid = 'Houston, we have a problemo. The Blockchain is not valid' 
        # data['status'] = 200 
        # data['data'] = message
    # while True:
    #     # command=command
    #     # if command == "who are you":
    #     #     answers = ("I am yappola \_(^^)_/")
    #     # if command == "who created you" or "Who Created You?":
    #     #     answers = ("Yappola \_(^^)_/")
    #     #     return render_template('study_bot.html', answers=answers)
    #     try:
    #         app_id = "5PL6G8-KRH7PUAAH5"
    #         client = wolframalpha.Client(app_id)
    #         res = client.query(command)
    #         answers = next(res.results).text
    #         answers = str(answers)
    #         print(answers)
    #         # voice = speak("The answer is "+answers)
    #     except:
    #         try:
    #             command = command.split(' ')
    #             command = command.join(command[2:])  # input[2:]
    #             answers = wikipedia.summary(command)
    #             # voice = speak("Searching for context "+context)
    #         except:
    #             answers = 'No more relevant information'
    #             # voice = speak(answers)
    #     break

    return render_template("insult.html", insult=response.choices[0].text ,message=message,valid=valid,chain_replaced=chain_replaced,trans=trans) #answers=answers





stripe.api_key = "sk_test_51MfxZgEBVnZ8rhY5V7rL4Fo1qqjwUIO2TTOKrj0BUxjzboKWYrc0LUkXD6swp9m17GdjxtxJ0vScMtP4BDyM0pgM00VTSyWXmg"
customers = stripe.Customer.list()
customers_data = customers['data']
print(customers_data)
email = 'peacewithit1@gmail.com'

for i in range(len(customers)):
    to = customers.data[i]['email']
    print(customers.data[i]['id'])
    if email == to:
        print('true')
    if email != to:
        print('false')


# import sendgrid
# import os
# from sendgrid.helpers.mail import Mail, Email, To, Content
# import smtplib
# import ssl
# from email.message import EmailMessage
# import os
# from sendgrid import SendGridAPIClient
# from sendgrid.helpers.mail import Mail


# email = 'peacewithit1@gmail.com'

# for i in range(len(customers)):
#     to = customers.data[i]['email']
#     print(customers.data[i]['id'])
#     if email == to:
#         print('true')
#     if email != to:
#         print('false')
    


@app.route("/enter_code",methods=["POST"])
def enter_code():
    return render_template('/enter_code.html')

@app.route("/enter",methods=["POST"])
def enter():
    passphrase = "Speak It Into Existence"
    code = request.form.get('Enter Code: ')
    # email = request.form.get('Enter Email')
    
    if code == passphrase:
        return render_template("/response.html")
    if code != passphrase:
        return redirect('https://yappolafranc.com/')



# Checking if the Blockchain is valid
@app.route('/is_valid', methods = ['GET'])
def is_valid():
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    message = {} 
    data = {}
    if is_valid:
        # response = {'message': 'All good. The Blockchain is valid.'}
        message = 'All good,Blockchain Is Valid' 
        # data['status'] = 200 
        # data['data'] = message
    else:
        response = {'message': 'Houston, we have a problemo. The Blockchain is not valid.'}
        message['message'] = 'Houston, we have a problemo. The Blockchain is not valid' 
        data['status'] = 200 
        data['data'] = message   
    return jsonify(data)

### Adding LaFrancChain Transactions
@app.route('/add_transaction', methods = ['POST'])
def add_transaction():
    message = {} 
    data = {}
    json = request.get_json()
    transactions_keys= ['sender','receiver','amount']
    if not all (key in json for key in transactions_keys):
        message['message'] = 'HOME ELMENTS OF THE TRASACTION ARE MISSING' 
        data['status'] =  400
        data['data'] = message   
        return jsonify(data) #'HOME ELMENTS OF THE TRASACTION ARE MISSING' 
    index = blockchain.add_transaction(json['sender'],json['receiver'],json['amount']) 
    response = {'message': f'This Transaction IS NOW ON BLOCK {index}'}
    message['message'] = 'This Transaction IS NOW ON BLOCK {}'.format(index)
    data['status'] = 201 
    data['data'] = message   
    return jsonify(response),201

### Decentralizing LaFrancCoin 

###Connecting Nodes 
@app.route('/connect_node',methods=["POST"]) 
def connect_node():
    received_json = request.get_json() 
    nodes = received_json.get('nodes')
    if nodes is None:
        message = ' No Node Found'
        return render_template('connected.html',nodes=nodes,message = message)
    for node in nodes:
        blockchain.add_node(node)
        message = 'All the nodes are now connected. The YappoLaFranc Blockchain now contains the following nodes:'
        total_nodes= list(blockchain.nodes)

    # data['status'] = 201 
    # data['data'] = message   
    return render_template('connected.html',nodes=nodes,connected = message,total_nodes=total_nodes)


### Connect longest chain if necessary
@app.route('/replace_chain', methods = ['GET'])
def replace_chain():
    is_chain_replaced = blockchain.replace_chain()
    message = {} 
    data = {}
    if is_chain_replaced:
        response = {'message': 'NODES HAD DIFFERENT CHAINS , REPLACED BY LONGEST CHAIN',
        'new_chain': blockchain.chain }
        message['message'] = 'NODES HAD DIFFERENT CHAINS , REPLACED BY LONGEST CHAIN {}'.format(blockchain.chain)
        data['status'] = 200 
        data['data'] = message
    else:
        response = {'message': 'NODE IS CONNECT TO LARGEST CHAIN',
        'actual_chain':blockchain.chain}
        message['message'] = 'NODE IS CONNECT TO LARGEST CHAIN {}'.format(blockchain.chain)
        data['status'] = 200 
        data['data'] = message   
    return jsonify(data)

# from bs4 import BeautifulSoup



import requests

import urllib.request

import shutil





usr_agent = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
    'Accept-Encoding': 'none',
    'Accept-Language': 'en-US,en;q=0.8',
    'Connection': 'keep-alive',
}




import stripe
@app.route('/pay', methods=['POST'])
def pay():
    customer = stripe.Customer.create(
        email=request.form['stripeEmail'], source=request.form['stripeToken'])
    charge = stripe.Subscription.create(
  customer=customer.id,
  items=[
    {"price": "10"},
  ],
)
    

@app.route('/thanks')
def thanks():
    return render_template('thanks.html')


if __name__ == "__main__":
    # debug=True,host="0.0.0.0",port=50000
    app.run(debug=True, host="0.0.0.0", port=5000)
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    # clear = lambda: os.system('cls')
    # clear()
    # wishMe()
    # usrname()



# def strip(x, frame_length, hop_length):
#     # Compute RMSE.
#     rmse = librosa.feature.rms(x, frame_length=frame_length, hop_length=hop_length, center=True)
#     # Identify the first frame index where RMSE exceeds a threshold.
#     thresh = 0.01
#     frame_index = 0
#     while rmse[0][frame_index] < thresh:
#         frame_index += 1
        
#     # Convert units of frames to samples.
#     start_sample_index = librosa.frames_to_samples(frame_index, hop_length=hop_length)
    
#     # Return the trimmed signal.
#     return x[start_sample_index:]


# @app.route('/trade')
# def trade():
#     from sklearn.linear_model import LinearRegression
#     from sklearn.model_selection import train_test_split,TimeSeriesSplit
#     import pandas as pd
#     from sklearn.preprocessing import MinMaxScaler
#     from sklearn.ensemble import AdaBoostRegressor
#     import numpy as np
#     import datetime as dt
#     # import cbpro
#     import matplotlib.pyplot as plt 
#     import time
#     # from web3.middleware import geth_poa_middleware
#     # from web3.gas_strategies.time_based import medium_gas_price_strategy
#     # from eth_account.messages import encode_defunct

#     from web3 import Web3, constants
#     from web3 import middleware
#     # from flask import Flask, flash, request, redirect, url_for, render_template
#     # from werkzeug.utils import secure_filename
#     import json
#     import librosa

#     def current_price(currency):
#         currency = 'eth-usd'
#         Period = 60 #[60, 300, 900, 3600, 21600, 86400]
#         historicData = auth_client.get_product_historic_rates(currency, granularity=Period)
#         #     print(historicData)
#                 # Make an array of the historic price data from the matrix
#         price = np.squeeze(np.asarray(np.matrix(historicData)[:,4]))
#                 # Wait for 1 second, to avoid API limit
#         time.sleep(1)
#                 # Get latest data and show to the user for reference
#         newData = auth_client.get_product_ticker(product_id=currency)
#         currentPrice=newData['price']
#         print('currency: {}'.format(currency))
#         print('current_price {} \n\n'.format(currentPrice))
#         return currentPrice

#     def history(currency):
#         currency = currency
#         Period = 60 #[60, 300, 900, 3600, 21600, 86400]      
#         historicData = auth_client.get_product_historic_rates(currency, granularity=Period)
#         historicData = pd.DataFrame(historicData,columns=['time','open','high','low','close','volume'])
#         price = historicData['high']
#                 # Wait for 1 second, to avoid API limit
#         time.sleep(1)
#         return historicData

#     def profit_target(token,current_holdings,target_percentage): 
#         token = token
#         print('\n\n {} target'.format(token))
#         current_holdings = current_holdings
#         target_percentage = current_holdings * float(target_percentage)
#         total_target = current_holdings+target_percentage
#         print('{} profit target {}, == {}'.format(token,target_percentage,total_target))
#         return target_percentage 

#     def loss(token,current_holdings,loss):
#         token = token
#         print('\n\n {} loss'.format(token))
#         current_holdings = current_holdings
#         target_percentage = current_holdings * float(loss)
#         total_loss = current_holdings-target_percentage
#         print('{} stop loss {}, == {}'.format(token,target_percentage,total_loss)) 
#         return target_percentage 

#     tr = 'Tron AI Sidechain testing'

#     currency = 'eth-usd' #request.form.get('Enter currency pair (dnt-usd)')
#     current_price = current_price(currency) 

#     print('amount to trade is betweet 0.015<=>1 ETH')
#     auth_client_currency = np.random.uniform(0.01,1.0)
#     init_bal = 'available {} for trading: {}\n\n'.format(currency,auth_client_currency)
#     amount = auth_client_currency

#     current_balance = float(current_price) * float(auth_client_currency)
#     print('current balances: {}\n\n'.format(current_balance))

#     print('-->PROFIT TARGETS:')
#     tar = profit_target(currency,current_balance, .3) 
#     tar2 = profit_target(currency,current_balance, .15) 
#     print('\n\n -->MAX LOSS:')
#     loss = loss(currency,current_balance, .1)


#     import pandas as pd 
#     import matplotlib.pyplot as plt
#     # import IPython.display as ipd
#     import pandas as pd
#     import librosa
#     import keras
#     import librosa.display
#     import time
#     # %pylab inline
#     # import glob
#     # import plotly
#     # import plotly.graph_objects as go
#     # import plotly.express as px
#     import warnings
#     import numpy as np
#     import plotly.express as px
#     # from sklearn.decomposition import PCA, FastICA
#     # import plotly.graph_objects as go
#     # warnings.filterwarnings('ignore')

#     # if not os.path.exists("images"):
#     #     os.mkdir("images")
        
#     '''call chosen currency via coinbase API'''
#     currency = 'eth-usd'
#     iteration=1
#     print('Analyzing and predicting {} \n\n'.format(currency))
#     while True:
#         '''Call Chosen Currency History'''
#         data = history(currency)
#         data.to_csv('currency_high.csv',index=False)
#         a0 = pd.read_csv('currency_high.csv')

#         '''Isolate Features From Respective Currency Data'''
#         # a0 = a0.drop(['Unnamed: 0'], axis=0 )
#         b0 = a0['open']
#         c0 = a0['high']
#         d0 = a0['low']
#         e0 = a0['close']
#         f0 = a0['volume']
#         i0 = a0['time']

#         order_book = auth_client.get_product_order_book('ETH-USD')
#         print('Order Book \n\n',order_book)
        
#         '''Averaging Isolated Price Data'''
#         avg=np.average(b0)   
#         avg1=np.average(c0) 
#         avg2=np.average(d0)
#         avg3=np.average(e0)
#         print('avg OPEN : {}, avg High : {}, avg LOW : {}, avg CLOSE : {}\n\n'.format(avg,avg1,avg2,avg3))


        
#         '''currency volume'''
#         background = f0
#         '''Time'''
#         x = i0
#         '''Open'''
#         y = b0
#         '''Creating isolated datasets'''
#         x_df = pd.DataFrame(x)  
#         y_df = pd.DataFrame(y) 
#         background_df = pd.DataFrame(background) 
#         x = x_df 
#         y = y_df 

#         '''Extract and rejoin volume,time,open data'''
#         background = background_df
#         extract = x.join(background) 
#         extract = extract.join(y)
#         extract 
       
#         data = extract.to_csv('data/extraction_data.csv') 
#         data = pd.read_csv('data/extraction_data.csv')
#         data = data.drop(['Unnamed: 0'],axis=1) 
#         data 

#         X= i0 #time
#         y = data['open'] 
#         background = data['volume']

#         '''Restructure data so algorithim can read data and udate sample rates for linear regression '''
#         data = np.squeeze(np.asarray(np.matrix(data)[:,1])) 
#         # sam_rate = np.squeeze(np.asarray(np.matrix(data)[:,1])) 
#         # D = np.abs(librosa.stft(data))**2
#         # S = librosa.feature.melspectrogram(data,sr=sam_rate,S=D,n_mels=512)
#         # log_S1 = librosa.power_to_db(S,ref=np.max)

#         # librosa.get_duration(data, sam_rate)
#         # h_l = 500
#         # f_l = 0
#         h_l = 256 
#         f_l = 512

#         #Create Linear regression models for Time Series Cross Validation
#         reg = LinearRegression(n_jobs=-1, normalize=True ) 
#         reg1 = LinearRegression(n_jobs=-1, normalize=True ) 
#         reg2 = LinearRegression(n_jobs=-1, normalize=True ) 
#         reg3 = LinearRegression(n_jobs=-1, normalize=True ) 
#         reg4 = LinearRegression(n_jobs=-1, normalize=True ) 

#         first_iteration = a0
#         time = first_iteration['time']

        
#         '''Open Prediction Model'''
#         y_open= first_iteration['open'] 
#         X_open = first_iteration.drop(['open'],axis=1) 
#         mini = MinMaxScaler() 
#         X_open = mini.fit_transform(X_open) 
#         Xo_train,Xo_test,yo_train,yo_test = train_test_split(X_open,y_open,test_size=.45,shuffle=False) 
#         reg.fit(Xo_train,yo_train)
#         tscv = TimeSeriesSplit(n_splits=5)
# #         print(tscv)  
#         TimeSeriesSplit(max_train_size=None, n_splits=4)
#         for train_index, test_index in tscv.split(X_open):
#             print("TRAIN:", train_index, "TEST:", test_index)
#             Xo_train, Xo_test = X_open[train_index], X_open[test_index]
#             yo_train, yo_test = y_open[train_index], y_open[test_index]
#     #     from sklearn.externals import joblib
#     #     joblib.dump(reg, 'models/tsco_1.pkl')
#         bata =  data
# #         bata.shape
#         date = i0 
#         future_x_open = X_open 
#         X_open = X_open[-1:] 
#         bata = bata
#         date = i0 
#         date = date.tail()
#         #bata = bata.tail() 
#         date = i0
#         y_open = reg.predict(future_x_open) 
#         print('accuracy {}'.format(reg.score(Xo_test,yo_test)))
#         y_open_df = pd.DataFrame(y_open) 
#         y_open_df.to_csv('open_pred.csv')

#         '''High Prediction Model'''
#         y_high= first_iteration['high']
#         X_high = first_iteration.drop(['high'],axis=1) 
#         mini = MinMaxScaler() 
#         X_high = mini.fit_transform(X_high) 
#         Xh_train,Xh_test,yh_train,yh_test = train_test_split(X_high,y_high,test_size=.45,shuffle=False) 
#         reg1.fit(Xh_train,yh_train)
#         tscv = TimeSeriesSplit(n_splits=5)
# #         print(tscv)  
#         TimeSeriesSplit(max_train_size=None, n_splits=4)
#         for train_index, test_index in tscv.split(X_high):
#             print("TRAIN:", train_index, "TEST:", test_index)
#             Xh_train, Xh_test = X_high[train_index], X_high[test_index]
#             yh_train, yh_test = y_high[train_index], y_high[test_index]
#     #     from sklearn.externals import joblib
#     #     joblib.dump(reg, 'models/tscv_1.pkl')
#         bata =  data
# #         bata.shape
#         date = i0 
#         future_x_high = X_high 
#         X_high = X_high[-1:] 
#         bata = bata
#         date = i0 
#         date = date.tail()
#         #bata = bata.tail() 
#         date = i0
#         y_high = reg1.predict(future_x_high) 
#         print('accuracy {}'.format(reg1.score(Xh_test,yh_test)))
#         y_high_df = pd.DataFrame(y_high) 
#         y_high_df.to_csv('high_pred.csv')

#         '''Low Prediction Model'''
#         y_low= first_iteration['low']
#         X_low = first_iteration.drop(['low'],axis=1) 
#         mini = MinMaxScaler() 
#         X_low = mini.fit_transform(X_low) 
#         Xl_train,Xl_test,yl_train,yl_test = train_test_split(X_low,y_low,test_size=.45,shuffle=False) 
#         reg2.fit(Xl_train,yl_train)
#         tscv = TimeSeriesSplit(n_splits=5)
# #         print(tscv)  
#         TimeSeriesSplit(max_train_size=None, n_splits=4)
#         for train_index, test_index in tscv.split(X_low):
#             print("TRAIN:", train_index, "TEST:", test_index)
#             Xl_train, Xl_test = X_low[train_index], X_low[test_index]
#             yl_train, yl_test = y_low[train_index], y_low[test_index]
#     #     from sklearn.externals import joblib
#     #     joblib.dump(reg, 'models/tscv_1.pkl')
#         bata =  data
# #         bata.shape
#         date = i0 
#         future_x_low = X_low 
#         X_low = X_low[-1:] 
#         bata = bata
#         date = i0 
#         date = date.tail()
#         #bata = bata.tail() 
#         date = i0
#         y_low = reg2.predict(future_x_low) 
#         print('accuracy {}'.format(reg2.score(Xl_test,yl_test)))
#         y_low_df = pd.DataFrame(y_low) 
#         y_low_df.to_csv('low_pred.csv')

#         '''Close Prediction Model'''
#         y_close= first_iteration['close']
#         X_close = first_iteration.drop(['close'],axis=1) 
#         mini = MinMaxScaler() 
#         X_close = mini.fit_transform(X_close) 
#         Xc_train,Xc_test,yc_train,yc_test = train_test_split(X_close,y_close,test_size=.45,shuffle=False) 
#         reg3.fit(Xc_train,yc_train)
#         tscv = TimeSeriesSplit(n_splits=5)
# #         print(tscv)  
#         TimeSeriesSplit(max_train_size=None, n_splits=4)
#         for train_index, test_index in tscv.split(X_close):
#             print("TRAIN:", train_index, "TEST:", test_index)
#             Xc_train, Xc_test = X_close[train_index], X_close[test_index]
#             yc_train, yc_test = y_close[train_index], y_close[test_index]
#     #     from sklearn.externals import joblib
#     #     joblib.dump(reg, 'models/tscc_1.pkl')
#         bata =  data
# #         bata.shape
#         date = i0 
#         future_x_close = X_close 
#         X_close = X_close[-1:] 
#         bata = bata
#         date = i0 
#         date = date.tail()
#         #bata = bata.tail() 
#         date = i0
#         y_close = reg3.predict(future_x_close) 
#         print('accuracy {}'.format(reg3.score(Xc_test,yc_test)))
#         y_close_df = pd.DataFrame(y_close) 
#         y_close_df.to_csv('close_pred.csv')
        
#         '''Volume Prediction Model'''
#         y_volume= first_iteration['volume']
#         X_volume = first_iteration.drop(['volume'],axis=1) 
#         Xv_train,Xv_test,yv_train,yv_test = train_test_split(X_volume,y_volume,test_size=.45,shuffle=False) 
#         mini = MinMaxScaler() 
#         X_volume = mini.fit_transform(X_volume) 
#         reg4.fit(Xv_train,yv_train)
#         tscv = TimeSeriesSplit(n_splits=5)
# #         print(tscv)  
# #         TimeSeriesSplit(max_train_size=None, n_splits=4)
#         for train_index, test_index in tscv.split(X_volume):
#             print("TRAIN:", train_index, "TEST:", test_index)
#             Xv_train, Xv_test = X_volume[train_index], X_volume[test_index]
#             yv_train, yv_test = y_volume[train_index], y_volume[test_index]
#     #     from sklearn.externals import joblib
#     #     joblib.dump(reg, 'models/tscv_1.pkl')
#         bata =  data
# #         bata.shape
#         date = i0 
#         future_x_volume = X_volume 
#         X_volume = X_volume[-1:] 
#         bata = bata
#         date = i0 
#         date = date.tail()
#         #bata = bata.tail() 
#         date = i0
#         y_volume = reg4.predict(future_x_volume) 


#         '''Calculate Predicted Energy For Data Features: Open High Low Close Volume 
#         to extract, process, and analyze data from multiple sources'''
#         energy = np.array([
#                 sum(abs(data[i:i+f_l]**2))
#                 for i in range(0, len(data), h_l)
#             ]) 
        

#         energy_r0 = np.array([
#                 sum(abs(reg.predict(Xo_test[i:i+f_l])**2))
#                 for i in range(0, len(reg.predict(Xo_test)), h_l)
#             ])  

#         energy_r1 = np.array([
#                 sum(abs(reg1.predict(Xh_test[i:i+f_l])**2))
#                 for i in range(0, len(reg1.predict(Xh_test)), h_l)
#             ])  
        
#         energy_r2 = np.array([
#                 sum(abs(reg2.predict(Xl_test[i:i+f_l])**2))
#                 for i in range(0, len(reg2.predict(Xl_test)), h_l) 
#             ])  

 
#         energy_r3 = np.array([
#                 sum(abs(reg3.predict(Xv_test[i:i+f_l])**2))
#                 for i in range(0, len(reg3.predict(Xc_test)), h_l)
#             ])
    
#         energy_r4 = np.array([
#                 sum(abs(reg4.predict(Xv_test[i:i+f_l])**2))
#                 for i in range(0, len(reg4.predict(Xv_test)), h_l)
#             ])
        

#         rmse_o = librosa.feature.rms(reg.predict(Xo_test), frame_length=f_l, hop_length=h_l, center=True)
#         rmse_h = librosa.feature.rms(reg1.predict(Xh_test), frame_length=f_l, hop_length=h_l, center=True)
#         rmse_l = librosa.feature.rms(reg2.predict(Xl_test), frame_length=f_l, hop_length=h_l, center=True)
#         rmse_c = librosa.feature.rms(reg3.predict(Xc_test), frame_length=f_l, hop_length=h_l, center=True)
#         rmse_v = librosa.feature.rms(reg4.predict(Xv_test), frame_length=f_l, hop_length=h_l, center=True)
        

#         frames = range(len(energy))
#         # t = librosa.frames_to_time(frames, sr=sam_rate, hop_length=h_l) 

#         print('predicted open')
#         yo = strip(reg.predict(Xo_test), f_l, h_l) #0,500
#         # plt.plot(y)
#         # plt.show()
        
#         print('predicted high')
#         yh = strip(reg1.predict(Xh_test), f_l, h_l) #0,500
#         # plt.plot(yh)
#         # plt.show()
        
#         print('predicted low')
#         yl = strip(reg2.predict(Xl_test), f_l, h_l) #0,500
#         # plt.plot(yl)
#         # plt.show()

#         print('predicted close')
#         yc = strip(reg3.predict(Xc_test), f_l, h_l) #0,500
#         # plt.plot(yc)
#         # plt.show()

#         print('predicted Volume')
#         yv = strip(reg4.predict(Xv_test), f_l, h_l) #0,500
#         # plt.plot(yv)
#         # plt.show()

#         print('Predicted Open Energy: {}'.format(energy_r0))
#         print('Predicted High Energy: {}'.format(energy_r1))
#         print('Predicted Low Energy: {}'.format(energy_r2))
#         print('Predicted Close Energy: {}'.format(energy_r3))
#         print('Predicted Volume Energy: {}'.format(energy_r4))
        
#         print('Predicted Open Root mean squared error: {}'.format(rmse_o))
#         print('Predicted High Root mean squared error: {}'.format(rmse_h))
#         print('Predicted Low Root mean squared error: {}'.format(rmse_l))
#         print('Predicted Close Root mean squared error: {}'.format(rmse_c))
#         print('Predicted Volume Root mean squared error: {}'.format(rmse_v))

#         open_volume = reg.predict(X_open[-1:])*background[-1:]
#         high_volume = reg1.predict(X_high[-1:])*background[-1:]
#         low_volume = reg2.predict(X_low[-1:])*background[-1:]
#         close_volume = reg3.predict(X_close[-1:])*background[-1:]
        
#         print('predicted Open market cap: {}'.format((reg.predict(X_open[-1:])*background[-1:])))
#         print('predicted High market cap: {}'.format((reg1.predict(X_high[-1:])*background[-1:])))
#         print('predicted Low market cap: {}'.format((reg2.predict(X_low[-1:])*background[-1:])))
#         print('predicted Close market cap: {}'.format((reg3.predict(X_close[-1:])*background[-1:])))
        
#         print('predicted Open {} Price: {} \n'.format(currency,yo[-1:]))
#         print('predicted High {} Price: {} \n'.format(currency,yh[-1:]))
#         print('predicted Low {} Price: {} \n'.format(currency,yl[-1:]))
#         print('predicted Close {} Price: {} \n'.format(currency,yc[-1:]))
#         print('predicted {} volume: {} \n'.format(currency,yv[-1:]))

#         current_bal = current_balance
#         pred_open_bal = float(yo[-1:])*float(auth_client_currency)
#         pred_high_bal = float(yh[-1:])*float(auth_client_currency)
#         pred_low_bal = float(yl[-1:])*float(auth_client_currency)
#         pred_close_bal = float(yc[-1:])*float(auth_client_currency)

#         print('predicted Open {} portfolio balance {} \n'.format(currency,float(yo[-1:])*float(auth_client_currency)))
#         print('predicted High {} portfolio balance {} \n'.format(currency,float(yh[-1:])*float(auth_client_currency)))
#         print('predicted Low {} portfolio balance {} \n'.format(currency,float(yl[-1:])*float(auth_client_currency)))
#         print('predicted Close {} portfolio balance {} \n'.format(currency,float(yc[-1:])*float(auth_client_currency)))
        
#         print(yo[-1:])
#         print(yo_test[-1:])
#         print(y_close[-1:])
#         tar_30 = current_balance+tar
#         tar_10 = current_balance+tar2
#         loss_10 =  current_balance-loss                      
        
#         if float(yo[-1:]) and float(yo_test[-1:]) < float(y_close[-1:])*.1:
#             a = 'Predicted open is 10% less than actual previous close: buying {}'.format(currency)
#             print('predicted price', yo[-1:])
#             print('actual price', yo_test[-1:])
#             print('current trading balance',current_balance-1.5)
# #             buy = client.buy('f3b62870-ddd0-5dea-9d80-5190d8558461', amount=amount, currency=currency)
# #             fills1 = pd.DataFrame(client.get_buy('f3b62870-ddd0-5dea-9d80-5190d8558461', buy.id))   
#             latestBlock() 
#             latestBlock()
#             latestBlock()
#             latestBlock()
#             latestBlock() 
#             import time
#             time.sleep(30)

#         if float(yo[-1:]) and float(yo_test[-1:]) < float(y_close[-1:])*.3:
#             a = 'Predicted open is 30% greater than actual previous close: Selling {}'.format(currency)
#             print('predicted price', yo[-1:])
#             print('actual price', yo_test[-1:])
#             print('current trading balance',current_balance-1.5)
# #             buy = client.buy('f3b62870-ddd0-5dea-9d80-5190d8558461', amount=amount, currency=currency)
# #             fills1 = pd.DataFrame(client.get_buy('f3b62870-ddd0-5dea-9d80-5190d8558461', buy.id))   
#             latestBlock() 
#             latestBlock()
#             latestBlock()
#             latestBlock()
#             latestBlock()
#             import time
#             time.sleep(30)
        
#         if float(yo[-1:])==float(yo_test[-1:]):
#             a = 'Predicted open is equal to current price Holding {}'.format(currency)
#             print('predicted price', yo[-1:])
#             print('actual price', yo_test[-1:])
#             print('current trading balance',current_balance)
# #             buy = client.buy('f3b62870-ddd0-5dea-9d80-5190d8558461', amount=amount, currency=currency)
# #             fills1 = pd.DataFrame(client.get_buy('f3b62870-ddd0-5dea-9d80-5190d8558461', buy.id))   
#             latestBlock()
#             latestBlock()
#             latestBlock()
#             latestBlock() 
#             import time
#             time.sleep(30)

#         if current_balance == tar:
#             a = '30% profit target hit, selling'
# #             sell = client.sell('f3b62870-ddd0-5dea-9d80-5190d8558461', amount=amount, currency=currency)
# #             fills1 = pd.DataFrame(client.get_buy('f3b62870-ddd0-5dea-9d80-5190d8558461', buy.id))   
#             latestBlock()
#             latestBlock()
#             latestBlock()
#             latestBlock() 
#             import time
#             time.sleep(30)
            
#         if current_balance == tar2:
#             a = '15% profit target hit, selling'
# #             sell = client.sell('f3b62870-ddd0-5dea-9d80-5190d8558461', amount=amount*.15, currency=currency)
# #             fills1 = pd.DataFrame(client.get_buy('f3b62870-ddd0-5dea-9d80-5190d8558461', buy.id))   
#             latestBlock()
#             latestBlock()
#             latestBlock()
#             latestBlock()
#             import time
#             time.sleep(30)
        
#         if current_balance == loss:
#             a = '10% Stop loss hit, selling'
# #             sell = client.sell('f3b62870-ddd0-5dea-9d80-5190d8558461', amount=amount, currency=currency)
# #             fills1 = pd.DataFrame(client.get_buy('f3b62870-ddd0-5dea-9d80-5190d8558461', buy.id))   
#             latestBlock()
#             latestBlock()
#             latestBlock()
#             latestBlock()
#             import time
#             time.sleep(30)

#         else:
#             a = 'Parameters Not Met: Holding'
#             a1 = 'current trading balance {}'.format(current_balance)
#             latestBlock()
#             latestBlock()
#             latestBlock()
#             latestBlock() 
#             import time
#             time.sleep(30)
        

#         previous_block = blockchain.get_previous_block()
#         previous_proof = previous_block['proof']
#         proof = blockchain.proof_of_work(previous_proof)
#         previous_hash = blockchain.hash(previous_block)
#         block = blockchain.create_block(proof, previous_hash,a,yh[-1:]) 

#         message= 'Congratulations, you just mined GPT Block {} at {} !, Proof of work {}, previous hash {}\n, block {}'.format(block['index'],block['timestamp'],block['proof'],block['previous_hash'],block) #\n transactions{}, \n LaFranc-TRX HASH {}, ,RECEIVING MINTER {},tx_hash,block['transactions'],receiver



#         is_chain_replaced = blockchain.replace_chain()

#         if is_chain_replaced:
#             # response = {'message': 'NODES HAD DIFFERENT CHAINS , REPLACED BY LONGEST CHAIN',
#             # 'new_chain': blockchain.chain }
#             chain_replaced = 'NODES HAD DIFFERENT CHAINS , REPLACED BY LONGEST CHAIN'
#             # data['status'] = 200 
#             # data['data'] = message
#         else:
#             # response = {'message': 'NODE IS CONNECT TO LARGEST CHAIN',
#             # 'actual_chain':blockchain.chain}
#             chain_replaced = 'NODE IS CONNECT TO LARGEST CHAIN'
#             # data['status'] = 200 
#             # data['data'] = message 
#         # command = context 
#         is_valid = blockchain.is_chain_valid(blockchain.chain)
#         # message = {} 
#         # data = {}
#         if is_valid:
#             # response = {'message': 'All good. The Blockchain is valid.'}
#             valid = 'All good,Blockchain Is Valid' 
#             # data['status'] = 200 
#             # data['data'] = message
#         else:
#             # response = {'message': 'Houston, we have a problemo. The Blockchain is not valid.'}
#             valid = 'Houston, we have a problemo. The Blockchain is not valid' 
#             # data['status'] = 200 
#             # data['data'] = message
#         # while True:
#         #     # command=command
#         #     # if command == "who are you":
#         #     #     answers = ("I am yappola \_(^^)_/")
#         #     # if command == "who created you" or "Who Created You?":
#         #     #     answers = ("Yappola \_(^^)_/")
#         #     #     return render_template('study_bot.html', answers=answers)
#         #     try:
#         #         app_id = "5PL6G8-KRH7PUAAH5"
#         #         client = wolframalpha.Client(app_id)
#         #         res = client.query(command)
#         #         answers = next(res.results).text
#         #         answers = str(answers)
#         #         print(answers)
#         #         # voice = speak("The answer is "+answers)
#         #     except:
#         #         try:
#         #             command = command.split(' ')
#         #             command = command.join(command[2:])  # input[2:]
#         #             answers = wikipedia.summary(command)
#         #             # voice = speak("Searching for context "+context)
#         #         except:
#         #             answers = 'No more relevant information'
#         #             # voice = speak(answers)
#         #     break

#         latestBlock()
#         latestBlock()
#         latestBlock()
#         latestBlock() 
#         import time
#         time.sleep(30)
#         iteration += 1 
#         return render_template('tron_trade.html',
#         message=message,tar=tar,tar2=tar2,loss=loss,open_volume=open_volume,pred_high_bal=pred_high_bal,yo=yo[-1:],yh=yh[-1:],yl=yl[-1:],yc=yc[-1:],valid=valid,chain_replaced=chain_replaced
#         # tr=tr,init_bal=init_bal,current_balance=current_balance,tar=tar,tar2=tar2,loss=loss,avg=avg,avg1=avg1,avg2=avg2,avg3=avg3,
#         # rmse_o=rmse_o,rmse_h=rmse_h,rmse_l=rmse_l,rmse_c=rmse_c,rmse_v=rmse_v, energy_r0=energy_r0, energy_r1=energy_r1, energy_r2=energy_r2,energy_r3=energy_r3,energy_r4=energy_r4, 
#         # open_volume=open_volume,high_volume=high_volume,low_volume=low_volume,close_volume=close_volume,
#         # curent_bal=current_bal,pred_open_bal=pred_open_bal,pred_high_bal=pred_high_bal,pred_low_bal=pred_low_bal,pred_close_bal=pred_close_bal,
#         # tar_30=tar_30,tar_10=tar_10,loss_10=loss_10,
#         # a=a,b=b,c=c,d=d,e=e,f=f,g=g,g1=g1
#         )






# @app.route('/submit', methods=['POST'])
# def submit():
#     from twilio.rest import Client
#     import json
#     account_sid = "AC8476723ac3889e29bad41322c9ee279b"
#     # Your Auth Token from twilio.com/console
#     auth_token = "215621b88c2b6a01b50cad3345c5324d"
#     #Service SID https://console.twilio.com/us1/service/verify/VAdfc8aa08a7322f26533dee5c582952ab/settings
#     service_sid = "VAdfc8aa08a7322f26533dee5c582952ab"

#     client = Client(account_sid, auth_token)
#     if request.method == "POST":
#         phone_number = request.form.post("phone_number")
#         with open('file.json', 'w') as f:
#             json.dump(phone_number, f)

#     return render_template('submit.html')


#  @app.route("/verify", methods=["GET", "POST"])
# def verify():
#     import json
#     from twilio.rest import Client
#     account_sid = "AC8476723ac3889e29bad41322c9ee279b"
#     # Your Auth Token from twilio.com/console
#     auth_token = "215621b88c2b6a01b50cad3345c5324d"
#     #Service SID https://console.twilio.com/us1/service/verify/VAdfc8aa08a7322f26533dee5c582952ab/settings
#     service_sid = "VAdfc8aa08a7322f26533dee5c582952ab"

#     client = Client(account_sid, auth_token)
#     if request.method == "POST":
#         code = request.form.get("code")
#         phone_number = request.form.get("phone_number")
#         verification_check = client.verify.v2.services(service_sid).verification_checks.create(to=phone_number, code=code)

#         if verification_check.status == 'approved':
#             try:
#                 message = client.messages\
#                     .create(
#                     to=phone_number,
#                     from_="+16692328645",
#                     body= "You Have Been Verified")
#                 time.sleep(TIMEOUT_SECONDS)
#                 validation_request = client.validation_requests \
#                                         .create(
#                                                 phone_number=phone_number
#                                             )

#                 # print(message())
#             except TwilioRestException as err:
#             # Implement your fallback code here
#                 print(err)
#             time.sleep(TIMEOUT_SECONDS)
#         numbers = [phone_number]

#         for number in numbers:
#             with open('file.csv', 'w') as f:
#                 print('saving number to csv')
#                 while True:
#                     json.dump(number, f)
#                     break
#                 continue
#         return  render_template("verify.html",status=verification_check.status)
#             # return redirect(url_for("verify",status = "You Are Verified"))


#     return render_template("verify.html")

# @app.route('/message', methods=['POST'])
# def message():


#     recip = '+17575818284'
#     # number = request.form.get('Twilio Number Lookup')
#     message = request.form.get('Enter Message')
#         # Your Account SID from twilio.com/console
#     from twilio.rest import Client
#     account_sid = "AC8476723ac3889e29bad41322c9ee279b"
#     # Your Auth Token from twilio.com/console
#     auth_token = "215621b88c2b6a01b50cad3345c5324d"

#     client = Client(account_sid, auth_token)
#     # number = request.form.get(client.lookups.phone_numbers(number).fetch())
#     # print(number.national_format)  # => (510) 867-5309

#     numbers = ["+17575722612","+17575818284"]

#     for number in numbers:

#         try:
#             message = client.messages\
#                 .create(
#                 to=number,
#                 from_="+16692328645",
#                 body= message)
#             time.sleep(TIMEOUT_SECONDS)
#             # print(message())
#         except TwilioRestException as err:
#         # Implement your fallback code here
#             print(err)
    # print(message.sid)
#         # print("The original message is : " + str(message))
#         res = ''.join(format(ord(i), 'b') for i in message)
#         # print("The message after binary conversion : " + str(res))
#         # print('this message will cost {}')
#         send = client.send_message(recip, message)
#         send
    # file = input('do you have a file you would like to send')
    # if file == 'yes':
    #         file = input('select file')
    #         res = ''.join(format(ord(i), 'b') for i in file)
    #         print("The message after binary conversion : " + str(res))
    #         print('this message will cost {}')
    #         client.send_file(recip, file)
    # print('total amount of eth spent will be {}'.format(amount))
    # transact = input('are you okay with this')
    # if transact == 'yes':
    #     print('continuing transaction , please input ethereum address')
    # print('message sent')

    # @client.on(events.NewMessage(pattern='(?i).*Hello'))
    # async def handler(event):
    #     await event.reply('Hey!')

    #     client.run_until_disconnected()
    #     client.disconnect()
    # if service == '750Mb':
    #     amount == mb750[-1:] - cap[-1:]
    #     new_shares = X7_test[-1:]-shares
    #     (input('are you okay with having {} amount of ethereum withdrawn?'.format(
    #         y7_train[-1:]*.0075-shares)))

    #     if 'yes':
    #         print('okay, processing payment and continuing transaction ')
    #         # from telegram as described above
    #         # your phone number
    #         print(
    #             'This is one Line branched to any telegram user via the LaFranc" protocol.')
    #         phone = '+17576320743'
    #         from telethon.sync import TelegramClient, events
    #         # print(client.get_me().stringify())
    #         with TelegramClient('name', api_id, api_hash) as client:
    #             print(client.get_me().stringify())
    #             recip = input(
    #                 'please enter recipients number including Country Code.')
    #             message = input('send ur message')
    #             print("The original message is : " + str(message))
    #             res = ''.join(format(ord(i), 'b') for i in message)
    #             print("The message after binary conversion : " + str(res))
    #             print('this message will cost {}')
    #             client.send_message(recip, message)
    #             file = input('do you have a file you would like to send')
    #             if file == 'yes':
    #                 file = input('select file')
    #                 res = ''.join(format(ord(i), 'b') for i in file)
    #                 print("The message after binary conversion : " + str(res))
    #                 print('this message will cost {}')
    #                 client.send_file(recip, file)
    #             print('total amount of eth spent will be {}'.format(amount))
    #             transact = input('are you okay with this')
    #             if transact == 'yes':
    #                 print('continuing transaction , please input ethereum address')
    #             print('message sent')

    #             @client.on(events.NewMessage(pattern='(?i).*Hello'))
    #             async def handler(event):
    #                 await event.reply('Hey!')

    #                 client.run_until_disconnected()
    #                 client.disconnect()
    # if service == '500Mb':
    #     amount == mb500[-1:] - cap[-1:]
    #     input('are you okay with spending {} amount of ethereum ?'.format(
    #         y5_train[-1:]*.0075-shares))
    #     new_shares = X5_test[-1:]-shares
    #     if 'yes':
    #         print('okay, processing payment and continuing transaction ')
    #         # from telegram as described above
    #         # your phone number
    #         print(
    #             'This is one Line branched to any telegram user via the LaFranc" protocol.')
    #         phone = '+17576320743'
    #         from telethon.sync import TelegramClient, events
    #         # print(client.get_me().stringify())
    #         with TelegramClient('name', api_id, api_hash) as client:
    #             print(client.get_me().stringify())
    #             recip = input(
    #                 'please enter recipients number including Country Code.')
    #             message = input('send ur message')
    #             print("The original message is : " + str(message))
    #             res = ''.join(format(ord(i), 'b') for i in message)
    #             print("The message after binary conversion : " + str(res))
    #             print('this message will cost {}')
    #             client.send_message(recip, message)
    #             file = input('do you have a file you would like to send')
    #             if file == 'yes':
    #                 file = input('select file')
    #                 res = ''.join(format(ord(i), 'b') for i in file)
    #                 print("The message after binary conversion : " + str(res))
    #                 print('this message will cost {}')
    #                 client.send_file(recip, file)
    #             print('total amount of eth spent will be {}'.format(amount))
    #             transact = input('are you okay with this')
    #             if transact == 'yes':
    #                 print('continuing transaction , please input ethereum address')
    #             print('message sent')

    #             @client.on(events.NewMessage(pattern='(?i).*Hello'))
    #             async def handler(event):
    #                 await event.reply('Hey!')

    #                 client.run_until_disconnected()
    #                 client.disconnect()
    # if service == '250Mb':
    #     amount == mb250[-1:] - cap[-1:]
    #     new_shares = X2_test[-1:]-shares
    #     (input('are you okay with having {} amount of ethereum withdrawn?'.format(
    #         y2_train[-1:]*.0075-shares)))
    #     new_shares = X2_test[-1:]-shares
    #     if 'yes':
    #         print('okay, processing payment and continuing transaction ')
    #         # from telegram as described above
    #         # your phone number
    #         print(
    #             'This is one Line branched to any telegram user via the LaFranc" protocol.')
    #         phone = '+17576320743'
    #         from telethon.sync import TelegramClient, events
    #         # print(client.get_me().stringify())
    #         with TelegramClient('name', api_id, api_hash) as client:
    #             print(client.get_me().stringify())
    #             recip = input(
    #                 'please enter recipients number including Country Code.')
    #             message = input('send ur message')
    #             print("The original message is : " + str(message))
    #             res = ''.join(format(ord(i), 'b') for i in message)
    #             print("The message after binary conversion : " + str(res))
    #             print('this message will cost {}')
    #             client.send_message(recip, message)
    #             file = input('do you have a file you would like to send')
    #             if file == 'yes':
    #                 file = input('select file')
    #                 res = ''.join(format(ord(i), 'b') for i in file)
    #                 print("The message after binary conversion : " + str(res))
    #                 print('this message will cost {}')
    #                 client.send_file(recip, file)
    #             print('total amount of eth spent will be {}'.format(amount))
    #             transact = input('are you okay with this')
    #             if transact == 'yes':
    #                 print('continuing transaction , please input ethereum address')
    #             print('message sent')

    #             @client.on(events.NewMessage(pattern='(?i).*Hello'))
    #             async def handler(event):
    #                 await event.reply('Hey!')

    #                 client.run_until_disconnected()
    #                 client.disconnect()

    # return render_template('index.html', prediction_text='Message sent to telegram group {}'.format(message.sid))


