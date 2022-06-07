from flask import Flask, flash, request, redirect, url_for, render_template
from flask_apscheduler import APScheduler
from flask_socketio import SocketIO, send, emit
import webview
import sys
import threading
from mnemonic import Mnemonic
import os
import hashlib
import ed25519
from json2html import json2html
import json
import bmbpy
import requests
import glob
from datetime import datetime
from engineio.async_drivers import gevent

UPLOAD_FOLDER = 'wallets'
ALLOWED_EXTENSIONS = {'dat'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = os.urandom(16)

scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

socketio = SocketIO(app)

mnemo = Mnemonic("english")

privkey = None
pubkey = None
address = None
mnemonic = None
txjson_b = None
balance_cache = None
latest_txs_cache = None

NODES = ["178.254.42.138", "173.230.139.86"]


# Landing


@app.route('/')
def login():
    wallets_display = []

    wallets = glob.glob("wallets/*.dat")
    wallets_legacy = glob.glob("wallets/*.json")

    for wallet in wallets:
        b = wallet.replace("wallets\\", "")
        wallets_display.append("<a href='/loadwallet/{}'>{}</a>".format(b, b))

    for wallet in wallets_legacy:
        b = wallet.replace("wallets\\", "")
        wallets_display.append("<a href='/loadwallet/{}'>{}</a>".format(b, b))

    return render_template("login.html", wallets=json2html.convert(wallets_display, escape=False))


# Load wallet


@app.route("/loadwallet/<wallet>")
def load_wallet(wallet):
    global privkey, pubkey, address, mnemonic

    try:
        if ".dat" in wallet:
            with open("wallets/" + wallet) as f:
                d = json.load(f)
                mnemonic = d["mnemonic"]
                address = d["address"]
                return redirect(url_for('unlock_wallet'))
        else:
            pass
            # with open("wallets/" + wallet) as f:
            #     d = json.load(f)
            #     print(d["privateKey"][64:])
            #     privkey = ed25519.SigningKey(binascii.unhexlify(d["privateKey"][64:]))
            #     open("my-secret-key.txt", "wb").write(privkey.to_ascii(encoding="hex"))
            #     pubkey = privkey.get_verifying_key()
            #     address = bmbpy.generate_address_from_pubkey(pubkey.to_bytes())
            #
            #     print(pubkey.to_ascii(encoding="hex"))
            #     print(address)
            #
            #     return redirect(url_for('wallet'))
    except Exception as e:
        print("{} : {}".format(type(e), e))
        flash(str("{} : {}".format(type(e), e)))
        return redirect(url_for('login'))

# Add wallet page


@app.route("/addwallet")
def add_wallet():
    return render_template("addwallet.html")


# New wallet


@app.route("/createwallet")
def create_wallet():
    return render_template("createwallet.html")


@app.route("/newwallet", methods=['POST'])
def new_wallet():
    global privkey, pubkey, address
    if request.form:
        data = request.form["passwd"]
        if not data:
            data = ""

        words = mnemo.generate(strength=256)
        wseed = mnemo.to_seed(words, passphrase=data)
        seed = hashlib.sha256(wseed).digest()

        privkey = ed25519.SigningKey(seed)
        pubkey = privkey.get_verifying_key()
        address = bmbpy.generate_address_from_pubkey(pubkey.to_bytes())

        # wlist = words.split(" ")
        # windexed = []
        # wdict = {}
        # c = 0
        # for i, word in enumerate(wlist):
        #     wdict[i + 1] = word
        #     c += 1
        #     if c % 4 == 0:
        #         windexed.append(wdict)
        #         wdict = {}

        # phrase = json2html.convert(windexed, escape=False)

        # generate new name

        wallets = glob.glob("wallets/*.dat")
        n = 0
        for wallet in wallets:
            wallet = wallet.replace("wallets\wallet", "")
            wallet = wallet.replace(".dat", "")
            try:
                if int(wallet) > n:
                    n = int(wallet)
            except Exception as e:
                continue

        n += 1

        # save wallet.dat

        d = None
        with open("wallets/wallet{}.dat".format(n), "w") as f:
            d = {"mnemonic": words, "address": address}
            f.write(json.dumps(d))

        with open("wallets/wallet{}.dat".format(n), "r") as f:
            rdata = json.load(f)
            if d != rdata:
                flash("wallet.dat verification failed, please try again")
                return redirect(url_for('create_wallet'))

        return render_template("newwallet.html", phrase=words)


# Import wallet


@app.route("/importwallet", methods=['GET', 'POST'])
def import_wallet():
    if request.method == 'POST':
        try:
            if 'file' not in request.files:
                flash('No file part')
                return redirect(request.url)
            file = request.files['file']
            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)
            if file and allowed_file(file.filename):

                # generate new name

                wallets = glob.glob("wallets/*.dat")
                n = 0
                for wallet in wallets:
                    wallet = wallet.replace("wallets\wallet", "")
                    wallet = wallet.replace(".dat", "")
                    try:
                        if int(wallet) > n:
                            n = int(wallet)
                    except Exception as e:
                        continue

                n += 1
                filename = "wallet{}.dat".format(n)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                return redirect(url_for('login'))
            else:
                return redirect(request.url)
        except Exception as e:
            print("{} : {}".format(type(e), e))
            flash("{} : {}".format(type(e), e))
    else:
        return render_template("importwallet.html")

# Import from mnemonic

@app.route("/importmnemonic", methods=['GET', 'POST'])
def import_mnemonic():
    global privkey, pubkey, address
    if request.method == 'POST':
        if request.form:
            m = request.form["mnemonic"]
            passwd = request.form["passwd"]
            if not passwd:
                passwd = ""
            if m:
                try:

                    wseed = mnemo.to_seed(m, passphrase=passwd)
                    seed = hashlib.sha256(wseed).digest()

                    privkey = ed25519.SigningKey(seed)
                    pubkey = privkey.get_verifying_key()
                    address = bmbpy.generate_address_from_pubkey(pubkey.to_bytes())


                    # generate new name

                    wallets = glob.glob("wallets/*.dat")
                    n = 0
                    for wallet in wallets:
                        wallet = wallet.replace("wallets\wallet", "")
                        wallet = wallet.replace(".dat", "")
                        try:
                            if int(wallet) > n:
                                n = int(wallet)
                        except Exception as e:
                            continue

                    n += 1

                    # save wallet.dat

                    d = None
                    with open("wallets/wallet{}.dat".format(n), "w") as f:
                        d = {"mnemonic": m, "address": address}
                        f.write(json.dumps(d))

                    with open("wallets/wallet{}.dat".format(n), "r") as f:
                        rdata = json.load(f)
                        if d != rdata:
                            flash("wallet.dat verification failed, please try again")
                            return redirect(url_for('create_wallet'))

                    return redirect(url_for('login'))
                except Exception as e:
                    print("{} : {}".format(type(e), e))
                    flash("{} : {}".format(type(e), e))
    else:
        return render_template("importmnemonic.html")


# Unlock wallet


@app.route("/unlockwallet", methods=['GET', 'POST'])
def unlock_wallet():
    global privkey, pubkey, address, mnemonic, balance_cache, latest_txs_cache
    if request.method == 'POST':
        if request.form:
            passwd = request.form["passwd"]
            if not passwd:
                passwd = ""
            words = mnemonic
            wseed = mnemo.to_seed(words, passphrase=passwd)
            seed = hashlib.sha256(wseed).digest()

            privkey = ed25519.SigningKey(seed)
            pubkey = privkey.get_verifying_key()
            if address != bmbpy.generate_address_from_pubkey(pubkey.to_bytes()):
                flash("invalid password")
                return redirect(url_for('unlock_wallet'))

            balance_cache = get_balance(address, 1)
            latest_txs_cache = get_latest_txs(address, 1)

            return redirect(url_for('wallet'))
    else:
        return render_template("unlockwallet.html")


# Wallet landing


@app.route("/wallet")
def wallet():
    global privkey, pubkey, address

    latest_txs = format_latest_txs()

    overview = {"address: ": "<a href='https://explorer.0xf10.com/account/{}' target='_blank'>{}</a>".format(address, address),
                "balance: ": balance_cache if balance_cache else 0}

    if privkey:
        return render_template("wallet.html", wallet_overview=json2html.convert(overview, escape=False),
                               txs=json2html.convert(latest_txs, escape=False))


# Send transaction


@app.route("/sendtx", methods=['GET', 'POST'])
def send_tx():
    global txjson_b
    if request.method == 'POST':
        if request.form:
            amount = request.form["amount"]
            fee = int(request.form["fee"])
            recipient = request.form["recipient"]

            txjson = bmbpy.generate_tx_json(address, recipient, round(float(amount) * 10000), round(fee), privkey)

            flash("<p>amount: {} BMB <br> fee: {} leaf <br> to: {}</p>".format(amount, fee, recipient))

            txjson_b = txjson

            return redirect("/confirmtx")

    else:
        return render_template("sendtx.html")


@app.route("/confirmtx")
def confirm_tx():

    return render_template("confirmtx.html", confirm='<a href="/submittx"><p>confirm</p></a>')


@app.route("/submittx")
def submit_tx():
    global txjson_b
    try:
        h = bmbpy.generate_tx_hash_from_json(txjson_b)
        r = bmbpy.submit_tx_json(txjson_b, NODES)

        txjson_b = None

        if r:
            flash('success! <a href="https://explorer.0xf10.com/tx/{}" target="_blank">link</a>'.format(h))
        else:
            flash("error!")

        return redirect(url_for("wallet"))

    except Exception as e:
        txjson_b = None
        print("{} : {}".format(type(e), e))
        flash(str("{} : {}".format(type(e), e)))
        return redirect(url_for("wallet"))


#
# Helper
#

def get_balance(address, t):
    try:
        r = requests.get("https://explorer.0xf10.com/api/accounts/balance?address={}".format(address), timeout=t)
        return r.text
    except Exception as e:
        print("{} : {}".format(type(e), e))
        return 0


def get_latest_txs(address, t):
    try:
        r = requests.get("https://explorer.0xf10.com/api/accounts/transactions?address={}".format(address), timeout=t)
        if r.text.startswith('{"error'):
            return None
        return r.json()
    except Exception as e:
        print("{} : {}".format(type(e), e))
        return None


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def format_latest_txs():
    latest_txs = []

    if not latest_txs_cache:
        latest_txs = ""
    else:
        for i, tx in enumerate(latest_txs_cache):

            latest_txs.append({})

            latest_txs[i]["height"] = tx["height"]
            latest_txs[i]["timestamp"] = tx["timestamp"]
            latest_txs[i]["amount"] = tx["amount"]
            latest_txs[i]["fee"] = tx["fee"]

            if tx["recipient"] == address:
                latest_txs[i]["to/from"] = tx["sender"]
            elif tx["sender"] == address:
                latest_txs[i]["to/from"] = tx["recipient"]

            date_time = datetime.fromtimestamp(tx["timestamp"])
            latest_txs[i]["timestamp"] = date_time.strftime("%m/%d/%Y, %H:%M:%S")

    return latest_txs


# sync


@scheduler.task('interval', id='sync', seconds=10, misfire_grace_time=60)
def sync():
    with scheduler.app.app_context():
        global balance_cache, latest_txs_cache

        if address:
            balance_cache = get_balance(address, 5)
            latest_txs_cache = get_latest_txs(address, 5)

        print("synced")


# socketio


@socketio.on('connect')
def first_connect():
    print("connected")

    overview = {"address: ": '<a href="https://explorer.0xf10.com/account/{}" target="_blank">{}</a>'.format(address, address), "balance: ": balance_cache if balance_cache else 0}

    html = json2html.convert(overview, escape=False)

    emit("overview", {"data": html}, namespace="/")


@socketio.on('update_wallet')
def handle_message():
    latest_txs = format_latest_txs()

    overview = {"address: ": '<a href="https://explorer.0xf10.com/account/{}" target="_blank">{}</a>'.format(address, address), "balance: ": balance_cache if balance_cache else 0}

    html = json2html.convert(overview, escape=False)
    emit("overview", {"data": html}, namespace="/")

    html = json2html.convert(latest_txs, escape=False)
    emit("txs", {"data": html}, namespace="/")


def start_server():
    # app.run(host='127.0.0.1', port=52323)
    socketio.run(app, host='127.0.0.1', port=52323)


if __name__ == '__main__':

    if not os.path.exists("wallets"):
        os.makedirs("wallets")

    t = threading.Thread(target=start_server)
    t.daemon = True
    t.start()

    webview.create_window("Bamboo Wallet", "http://localhost:52323/", width=820, height=500, text_select=True, resizable=False)
    webview.start()
    sys.exit()
