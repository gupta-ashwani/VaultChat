"""
web_client.py — Phase 4 Local Web Client (Flask Bridge with Persistence)
"""
import sys
import sqlite3
import os
import threading
import time
from flask import Flask, render_template, request, jsonify
from zeep import Client as SoapClient
import crypto_utils
from lxml import etree

app = Flask(__name__)

# Config
port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
SOAP_WSDL = "http://127.0.0.1:8000/?wsdl"
KEYS_DIR = f"client_keys_{port}"
DB_FILE = f"client_data_{port}.db"

def get_soap_client():
    return SoapClient(SOAP_WSDL)

# ─── Local Database Methods ───
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS Config (key TEXT PRIMARY KEY, value TEXT)')
    c.execute('CREATE TABLE IF NOT EXISTS Contacts (username TEXT PRIMARY KEY, friend_code TEXT NOT NULL, public_key TEXT NOT NULL)')
    c.execute('CREATE TABLE IF NOT EXISTS Messages (id INTEGER PRIMARY KEY AUTOINCREMENT, contact TEXT NOT NULL, text TEXT NOT NULL, is_sent BOOLEAN NOT NULL, signature_valid BOOLEAN NOT NULL, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, raw_xml TEXT)')
    conn.commit()
    conn.close()

def get_config(key):
    conn = get_db()
    row = conn.cursor().execute('SELECT value FROM Config WHERE key = ?', (key,)).fetchone()
    conn.close()
    return row['value'] if row else None

def set_config(key, value):
    conn = get_db()
    conn.cursor().execute('INSERT OR REPLACE INTO Config (key, value) VALUES (?, ?)', (key, value))
    conn.commit()
    conn.close()

# ─── Flask Routes ───
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/me", methods=["GET"])
def get_me():
    username = get_config("username")
    friend_code = get_config("friend_code")
    if username and friend_code:
        return jsonify({"username": username, "friend_code": friend_code})
    return jsonify({"username": None, "friend_code": None})

@app.route("/api/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    if not username:
        return jsonify({"error": "Username required"}), 400

    try:
        priv_pem, pub_pem = crypto_utils.generate_and_save_keys(username, keys_dir=KEYS_DIR)
        
        soap = get_soap_client()
        res = soap.service.RegisterUser(username=username, public_key=pub_pem)
        friend_code = res.friend_code

        set_config("username", username)
        set_config("friend_code", friend_code)
        set_config("private_key", priv_pem)
        set_config("public_key", pub_pem)

        return jsonify({
            "username": username,
            "friend_code": friend_code
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/contacts", methods=["GET", "POST"])
def contacts():
    if request.method == "GET":
        conn = get_db()
        rows = conn.cursor().execute('SELECT username, friend_code FROM Contacts').fetchall()
        conn.close()
        return jsonify({"contacts": [dict(r) for r in rows]})
    
    if request.method == "POST":
        friend_code = request.json.get("friend_code")
        if not friend_code:
            return jsonify({"error": "Friend code required"}), 400
            
        try:
            soap = get_soap_client()
            res = soap.service.GetContactByCode(friend_code=friend_code)
            if not res or res.username == "Not found":
                return jsonify({"error": "Friend code not found"}), 404
                
            conn = get_db()
            conn.cursor().execute('INSERT OR REPLACE INTO Contacts (username, friend_code, public_key) VALUES (?, ?, ?)',
                                  (res.username, friend_code, res.public_key))
            conn.commit()
            conn.close()
            return jsonify({"username": res.username, "friend_code": friend_code})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

@app.route("/api/history", methods=["GET"])
def history():
    contact = request.args.get("contact")
    conn = get_db()
    rows = conn.cursor().execute('SELECT text, is_sent, signature_valid, timestamp, raw_xml FROM Messages WHERE contact = ? ORDER BY timestamp ASC', (contact,)).fetchall()
    conn.close()
    return jsonify({"messages": [dict(r) for r in rows]})

@app.route("/api/send", methods=["POST"])
def send_message():
    current_username = get_config("username")
    private_key_pem = get_config("private_key")
    if not current_username or not private_key_pem:
        return jsonify({"error": "Not registered"}), 403

    data = request.json
    receiver = data.get("receiver")
    plaintext = data.get("message")
    
    if not receiver or not plaintext:
        return jsonify({"error": "Receiver and message required"}), 400

    try:
        conn = get_db()
        row = conn.cursor().execute('SELECT public_key FROM Contacts WHERE username = ?', (receiver,)).fetchone()
        conn.close()
        if not row:
             return jsonify({"error": "Contact not found locally"}), 404
             
        receiver_pub = crypto_utils.pem_to_public_key(row["public_key"])
        private_key = crypto_utils.pem_to_private_key(private_key_pem)
        
        secure_xml = crypto_utils.build_secure_message(
            plaintext_msg=plaintext,
            sender_username=current_username,
            sender_private_key=private_key,
            receiver_public_key=receiver_pub
        )
        
        soap = get_soap_client()
        res = soap.service.SendMessage(
            sender=current_username,
            receiver=receiver,
            xml_payload=secure_xml
        )
        
        conn = get_db()
        conn.cursor().execute('INSERT INTO Messages (contact, text, is_sent, signature_valid, raw_xml) VALUES (?, ?, ?, ?, ?)',
                              (receiver, plaintext, True, True, secure_xml))
        conn.commit()
        conn.close()
        
        return jsonify({"message": "Sent securely"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─── Background Poller ───
def poll_messages():
    while True:
        time.sleep(3)
        current_username = get_config("username")
        private_key_pem = get_config("private_key")
        if not current_username or not private_key_pem:
            continue
            
        try:
            soap = get_soap_client()
            soap_msgs_str = soap.service.GetMessages(username=current_username)
            if soap_msgs_str:
                root = etree.fromstring(soap_msgs_str.encode('utf-8'))
                conn = get_db()
                private_key = crypto_utils.pem_to_private_key(private_key_pem)
                
                for msg_el in root.findall('message'):
                    sender = msg_el.find('sender').text
                    raw_xml = msg_el.find('payload').text
                    timestamp = msg_el.find('timestamp').text
                    
                    # Ensure sender is in contacts to get their public key
                    row = conn.cursor().execute('SELECT public_key FROM Contacts WHERE username = ?', (sender,)).fetchone()
                    if row:
                        sender_pub = crypto_utils.pem_to_public_key(row["public_key"])
                        try:
                            parsed = crypto_utils.parse_secure_message(
                                xml_str=raw_xml,
                                receiver_private_key=private_key,
                                sender_public_key=sender_pub
                            )
                            conn.cursor().execute('INSERT INTO Messages (contact, text, is_sent, signature_valid, timestamp, raw_xml) VALUES (?, ?, ?, ?, ?, ?)',
                                                  (sender, parsed["plaintext"], False, parsed["signature_valid"], timestamp, raw_xml))
                        except Exception as e:
                            conn.cursor().execute('INSERT INTO Messages (contact, text, is_sent, signature_valid, timestamp, raw_xml) VALUES (?, ?, ?, ?, ?, ?)',
                                                  (sender, f"[DECRYPTION FAILED] {str(e)}", False, False, timestamp, raw_xml))
                    else:
                        # Received message from unknown contact
                        conn.cursor().execute('INSERT INTO Messages (contact, text, is_sent, signature_valid, timestamp, raw_xml) VALUES (?, ?, ?, ?, ?, ?)',
                                              (sender, "[ERROR] Received message from unknown contact. Add them first to fetch their public key.", False, False, timestamp, raw_xml))
                conn.commit()
                conn.close()
        except Exception as e:
            pass

if __name__ == "__main__":
    init_db()
    t = threading.Thread(target=poll_messages, daemon=True)
    t.start()
    
    print("=" * 60)
    print(f"  Starting Local Web Client on http://127.0.0.1:{port}")
    print("=" * 60)
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
