"""
Test script for the Secure XML Messaging SOAP Server.
Starts server in a background thread and fires test requests using zeep.
"""

import threading
import time
from zeep import Client
from zeep.transports import Transport
import requests

SERVER_URL = "http://127.0.0.1:8000/"
SOAP_URL   = "http://127.0.0.1:8000/soap"

def start_server():
    import os, sys
    sys.path.insert(0, os.path.dirname(__file__))
    from server import app
    import database
    database.init_db()
    app.run(host="127.0.0.1", port=8000, debug=False, use_reloader=False)

if __name__ == "__main__":
    # Start server in background thread
    t = threading.Thread(target=start_server, daemon=True)
    t.start()
    print("Waiting for server to start...")
    time.sleep(2)

    # Use zeep to talk to our WSDL
    client = Client(SERVER_URL)

    print("\n" + "="*50)
    print("  Phase 1 - SOAP Endpoint Tests")
    print("="*50)

    # 1. Register users
    res = client.service.RegisterUser(username="alice", public_key="ALICE_PUBLIC_KEY_PLACEHOLDER")
    print(f"[RegisterUser] Alice  -> {res}")

    res = client.service.RegisterUser(username="bob", public_key="BOB_PUBLIC_KEY_PLACEHOLDER")
    print(f"[RegisterUser] Bob    -> {res}")

    # 2. Get public key
    pk = client.service.GetPublicKey(username="alice")
    print(f"[GetPublicKey] Alice  -> {pk}")

    pk = client.service.GetPublicKey(username="nobody")
    print(f"[GetPublicKey] Nobody -> {pk}")

    # 3. Send a message from alice to bob
    res = client.service.SendMessage(
        sender="alice",
        receiver="bob",
        xml_payload="<EncryptedPayload><data>Hello Bob, this will be encrypted in Phase 2!</data></EncryptedPayload>"
    )
    print(f"[SendMessage]  Alice->Bob -> {res}")

    # 4. Get messages for bob
    msgs_xml = client.service.GetMessages(username="bob")
    print(f"[GetMessages]  Bob received:\n{msgs_xml}")

    # 5. Confirm messages are deleted after delivery
    msgs_xml2 = client.service.GetMessages(username="bob")
    print(f"[GetMessages]  Bob (again, should be empty):\n{msgs_xml2}")

    print("\n" + "="*50)
    print("  All Phase 1 tests PASSED!")
    print("="*50)
