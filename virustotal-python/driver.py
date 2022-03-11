from asyncio.windows_events import NULL
from types import NoneType
from attr import attr
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timezone
import pymongo
import pprint
import requests
import json
import re

client = pymongo.MongoClient("mongodb+srv://admin:123@cluster0.xprpc.mongodb.net/hashdb?retryWrites=true&w=majority")
db = client.Cluster0

app = Flask(__name__)
CORS(app)

md5re = re.compile('^[a-fA-F0-9]{32}$')
sha1re = re.compile('^[a-fA-F0-9]{40}$')
sha256re = re.compile('^[a-fA-F0-9]{64}$')
url = "https://www.virustotal.com/api/v3/files/"
headers = {
    "Accept": "application/json",
    "x-apikey": "c6c1781bab81e19b1488b212a615a64bd9cb6318376a592d41fe79c8b703c18a",
}

@app.route('/')
def home():
    return 'home'

@app.route("/hashinfo/<string:hash>")
def getHash(hash):
    
    if(md5re.match(hash)):
        print('recieved md5 hash...')
        if(len(list(db['hashes'].find({'md5':hash}))) > 0):
            hashinfo = db['hashes'].find_one({'md5':hash})
            return 'hello'
    elif(sha1re.match(hash)):
        print('recieved sha1 hash...')
        if(len(list(db['hashes'].find({'sha1':hash}))) > 0):
            hashinfo = db['hashes'].find_one({'sha1':hash})
            return 'hello'
    else:
        print('recieved sha256 hash...')
        if(len(list(db['hashes'].find({'sha256':hash}))) > 0):
            hashinfo = db['hashes'].find_one({'sha256':hash})
            return 'hello'

    
    print('fetching hash from Virus Total...')
    response = requests.request("GET", url+hash, headers=headers)
    responsejson = json.loads(response.text)
    attributes = responsejson['data']['attributes']
    dt = datetime.fromtimestamp( attributes['creation_date'], tz=timezone.utc )
    db['hashes'].insert_one({
        'creation_date': dt,
        'md5': attributes['md5'],
        'sha1': attributes['sha1'],
        'sha256': attributes['sha256'],
        'size': attributes['size'],
        'type_description' : attributes['type_description'],
        'signature_info' : attributes['signature_info'],
        'names' : attributes['names'],
        'signers' : attributes['signature_info']['signers'],
        'counter_signers': attributes['signature_info']['counter signers'],
        'copyright' : attributes['signature_info']['copyright'],
        'last_submission_date' : attributes['last_submission_date'],
        'last_analysis_stats' : attributes['last_analysis_stats']
    })
    return jsonify({
        'creation_date': dt,
        'md5': attributes['md5'],
        'sha1': attributes['sha1'],
        'sha256': attributes['sha256'],
        'size': attributes['size'],
        'type_description' : attributes['type_description'],
        'signature_info' : attributes['signature_info'],
        'names' : attributes['names'],
        'signers' : attributes['signature_info']['signers'],
        'counter_signers': attributes['signature_info']['counter signers'],
        'copyright' : attributes['signature_info']['copyright'],
        'last_submission_date' : attributes['last_submission_date'],
        'last_analysis_stats' : attributes['last_analysis_stats']
    })


