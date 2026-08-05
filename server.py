"""
Secure XML Messaging - SOAP 1.1 Server
Built with Flask + lxml (hand-crafted SOAP XML)
Endpoints: RegisterUser, GetPublicKey, SendMessage, GetMessages
"""

from flask import Flask, request, Response
from lxml import etree
import database

app = Flask(__name__)

# ─── XML / SOAP Namespaces ────────────────────────────────────────────────────
NS_SOAP = "http://schemas.xmlsoap.org/soap/envelope/"
NS_SVC  = "http://secure.messaging.service/"

NSMAP = {
    'soapenv': NS_SOAP,
    'svc':     NS_SVC,
}

# ─── WSDL (served at GET /) ───────────────────────────────────────────────────
WSDL = """<?xml version="1.0" encoding="UTF-8"?>
<definitions name="SecureMessagingService"
  targetNamespace="http://secure.messaging.service/"
  xmlns="http://schemas.xmlsoap.org/wsdl/"
  xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
  xmlns:tns="http://secure.messaging.service/"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema">

  <!-- Types -->
  <types>
    <xsd:schema targetNamespace="http://secure.messaging.service/">
      <xsd:element name="RegisterUserRequest">
        <xsd:complexType>
          <xsd:sequence>
            <xsd:element name="username"   type="xsd:string"/>
            <xsd:element name="public_key" type="xsd:string"/>
          </xsd:sequence>
        </xsd:complexType>
      </xsd:element>
      <xsd:element name="RegisterUserResponse">
        <xsd:complexType><xsd:sequence>
          <xsd:element name="result" type="xsd:string"/>
          <xsd:element name="friend_code" type="xsd:string"/>
        </xsd:sequence></xsd:complexType>
      </xsd:element>

      <xsd:element name="GetContactByCodeRequest">
        <xsd:complexType><xsd:sequence>
          <xsd:element name="friend_code" type="xsd:string"/>
        </xsd:sequence></xsd:complexType>
      </xsd:element>
      <xsd:element name="GetContactByCodeResponse">
        <xsd:complexType><xsd:sequence>
          <xsd:element name="username" type="xsd:string"/>
          <xsd:element name="public_key" type="xsd:string"/>
        </xsd:sequence></xsd:complexType>
      </xsd:element>

      <xsd:element name="GetPublicKeyRequest">
        <xsd:complexType><xsd:sequence>
          <xsd:element name="username" type="xsd:string"/>
        </xsd:sequence></xsd:complexType>
      </xsd:element>
      <xsd:element name="GetPublicKeyResponse">
        <xsd:complexType><xsd:sequence>
          <xsd:element name="public_key" type="xsd:string"/>
        </xsd:sequence></xsd:complexType>
      </xsd:element>

      <xsd:element name="SendMessageRequest">
        <xsd:complexType><xsd:sequence>
          <xsd:element name="sender"      type="xsd:string"/>
          <xsd:element name="receiver"    type="xsd:string"/>
          <xsd:element name="xml_payload" type="xsd:string"/>
        </xsd:sequence></xsd:complexType>
      </xsd:element>
      <xsd:element name="SendMessageResponse">
        <xsd:complexType><xsd:sequence>
          <xsd:element name="result" type="xsd:string"/>
        </xsd:sequence></xsd:complexType>
      </xsd:element>

      <xsd:element name="GetMessagesRequest">
        <xsd:complexType><xsd:sequence>
          <xsd:element name="username" type="xsd:string"/>
        </xsd:sequence></xsd:complexType>
      </xsd:element>
      <xsd:element name="GetMessagesResponse">
        <xsd:complexType><xsd:sequence>
          <xsd:element name="messages" type="xsd:string"/>
        </xsd:sequence></xsd:complexType>
      </xsd:element>
    </xsd:schema>
  </types>

  <!-- Messages -->
  <message name="RegisterUserInput">  <part name="body" element="tns:RegisterUserRequest"/> </message>
  <message name="RegisterUserOutput"> <part name="body" element="tns:RegisterUserResponse"/> </message>
  <message name="GetPublicKeyInput">  <part name="body" element="tns:GetPublicKeyRequest"/> </message>
  <message name="GetPublicKeyOutput"> <part name="body" element="tns:GetPublicKeyResponse"/> </message>
  <message name="SendMessageInput">   <part name="body" element="tns:SendMessageRequest"/> </message>
  <message name="SendMessageOutput">  <part name="body" element="tns:SendMessageResponse"/> </message>
  <message name="GetMessagesInput">   <part name="body" element="tns:GetMessagesRequest"/> </message>
  <message name="GetMessagesOutput">  <part name="body" element="tns:GetMessagesResponse"/> </message>
  <message name="GetContactByCodeInput">  <part name="body" element="tns:GetContactByCodeRequest"/> </message>
  <message name="GetContactByCodeOutput"> <part name="body" element="tns:GetContactByCodeResponse"/> </message>

  <!-- PortType -->
  <portType name="SecureMessagingPortType">
    <operation name="RegisterUser">
      <input  message="tns:RegisterUserInput"/>
      <output message="tns:RegisterUserOutput"/>
    </operation>
    <operation name="GetPublicKey">
      <input  message="tns:GetPublicKeyInput"/>
      <output message="tns:GetPublicKeyOutput"/>
    </operation>
    <operation name="SendMessage">
      <input  message="tns:SendMessageInput"/>
      <output message="tns:SendMessageOutput"/>
    </operation>
    <operation name="GetMessages">
      <input  message="tns:GetMessagesInput"/>
      <output message="tns:GetMessagesOutput"/>
    </operation>
    <operation name="GetContactByCode">
      <input  message="tns:GetContactByCodeInput"/>
      <output message="tns:GetContactByCodeOutput"/>
    </operation>
  </portType>

  <!-- Binding -->
  <binding name="SecureMessagingBinding" type="tns:SecureMessagingPortType">
    <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
    <operation name="RegisterUser">
      <soap:operation soapAction="RegisterUser"/>
      <input><soap:body use="literal"/></input>
      <output><soap:body use="literal"/></output>
    </operation>
    <operation name="GetPublicKey">
      <soap:operation soapAction="GetPublicKey"/>
      <input><soap:body use="literal"/></input>
      <output><soap:body use="literal"/></output>
    </operation>
    <operation name="SendMessage">
      <soap:operation soapAction="SendMessage"/>
      <input><soap:body use="literal"/></input>
      <output><soap:body use="literal"/></output>
    </operation>
    <operation name="GetMessages">
      <soap:operation soapAction="GetMessages"/>
      <input><soap:body use="literal"/></input>
      <output><soap:body use="literal"/></output>
    </operation>
    <operation name="GetContactByCode">
      <soap:operation soapAction="GetContactByCode"/>
      <input><soap:body use="literal"/></input>
      <output><soap:body use="literal"/></output>
    </operation>
  </binding>

  <!-- Service -->
  <service name="SecureMessagingService">
    <port name="SecureMessagingPort" binding="tns:SecureMessagingBinding">
      <soap:address location="http://127.0.0.1:8000/soap"/>
    </port>
  </service>
</definitions>"""

# ─── Helpers ──────────────────────────────────────────────────────────────────
def _soap_envelope(body_content_el):
    """Wrap an lxml element in a SOAP Envelope > Body."""
    env  = etree.Element("{%s}Envelope" % NS_SOAP, nsmap=NSMAP)
    body = etree.SubElement(env, "{%s}Body" % NS_SOAP)
    body.append(body_content_el)
    return env

def _soap_fault(code, message):
    """Return a SOAP Fault response."""
    fault = etree.Element("{%s}Fault" % NS_SOAP)
    fc = etree.SubElement(fault, "faultcode");   fc.text = code
    fs = etree.SubElement(fault, "faultstring"); fs.text = message
    env = _soap_envelope(fault)
    xml_bytes = etree.tostring(env, xml_declaration=True, encoding="UTF-8", pretty_print=True)
    return Response(xml_bytes, status=500, content_type="text/xml; charset=utf-8")

def _xml_response(env_el, status=200):
    xml_bytes = etree.tostring(env_el, xml_declaration=True, encoding="UTF-8", pretty_print=True)
    return Response(xml_bytes, status=status, content_type="text/xml; charset=utf-8")

def _get_text(body_el, tag):
    """Get text of a child element by local name, ignoring namespace."""
    for child in body_el.iter():
        if etree.QName(child).localname == tag:
            return (child.text or "").strip()
    return None

# ─── SOAP Action Handlers ─────────────────────────────────────────────────────
def handle_register_user(body_el):
    username   = _get_text(body_el, "username")
    public_key = _get_text(body_el, "public_key")
    if not username or not public_key:
        return _soap_fault("Client", "username and public_key are required")
    friend_code = database.register_user(username, public_key)
    resp_el = etree.Element("{%s}RegisterUserResponse" % NS_SVC)
    result  = etree.SubElement(resp_el, "result")
    result.text = "Registration successful" if friend_code else "Registration failed"
    fc_el = etree.SubElement(resp_el, "friend_code")
    fc_el.text = friend_code if friend_code else ""
    return _xml_response(_soap_envelope(resp_el))

def handle_get_contact_by_code(body_el):
    friend_code = _get_text(body_el, "friend_code")
    contact = database.get_user_by_code(friend_code)
    resp_el = etree.Element("{%s}GetContactByCodeResponse" % NS_SVC)
    u_el = etree.SubElement(resp_el, "username")
    pk_el = etree.SubElement(resp_el, "public_key")
    
    if contact:
        u_el.text = contact[0]
        pk_el.text = contact[1]
    else:
        u_el.text = "Not found"
        pk_el.text = "Not found"
        
    return _xml_response(_soap_envelope(resp_el))

def handle_get_public_key(body_el):
    username = _get_text(body_el, "username")
    pub_key  = database.get_public_key(username)
    resp_el  = etree.Element("{%s}GetPublicKeyResponse" % NS_SVC)
    pk_el    = etree.SubElement(resp_el, "public_key")
    pk_el.text = pub_key if pub_key else "User not found"
    return _xml_response(_soap_envelope(resp_el))

def handle_send_message(body_el):
    sender      = _get_text(body_el, "sender")
    receiver    = _get_text(body_el, "receiver")
    xml_payload = _get_text(body_el, "xml_payload")
    if not all([sender, receiver, xml_payload]):
        return _soap_fault("Client", "sender, receiver, and xml_payload are required")
    ok = database.send_message(sender, receiver, xml_payload)
    resp_el = etree.Element("{%s}SendMessageResponse" % NS_SVC)
    result  = etree.SubElement(resp_el, "result")
    result.text = "Message sent successfully" if ok else "Failed to send message"
    return _xml_response(_soap_envelope(resp_el))

def handle_get_messages(body_el):
    username = _get_text(body_el, "username")
    messages = database.get_messages(username)
    
    # Build an XML fragment representing all messages
    msgs_el = etree.Element("messages")
    for msg in messages:
        m_el = etree.SubElement(msgs_el, "message")
        etree.SubElement(m_el, "id").text        = str(msg[0])
        etree.SubElement(m_el, "sender").text    = msg[1]
        etree.SubElement(m_el, "payload").text   = msg[2]
        etree.SubElement(m_el, "timestamp").text = msg[3]
    
    resp_el  = etree.Element("{%s}GetMessagesResponse" % NS_SVC)
    msgs_str = etree.SubElement(resp_el, "messages")
    msgs_str.text = etree.tostring(msgs_el, encoding="unicode")
    return _xml_response(_soap_envelope(resp_el))

# ─── Flask Routes ─────────────────────────────────────────────────────────────
@app.route("/", methods=["GET"])
def wsdl():
    return Response(WSDL, content_type="text/xml; charset=utf-8")

@app.route("/soap", methods=["POST"])
def soap_endpoint():
    try:
        raw_xml = request.data
        if not raw_xml:
            return _soap_fault("Client", "Empty request body")
        
        root    = etree.fromstring(raw_xml)
        body_el = root.find("{%s}Body" % NS_SOAP)
        if body_el is None:
            return _soap_fault("Client", "No SOAP Body found")
        
        # Detect action from SOAPAction header or first child element name
        soap_action = request.headers.get("SOAPAction", "").strip('"')
        if not soap_action:
            first_child = list(body_el)[0] if len(body_el) else None
            soap_action = etree.QName(first_child).localname if first_child is not None else ""
        
        action_map = {
            "RegisterUser": handle_register_user,
            "GetPublicKey": handle_get_public_key,
            "SendMessage":  handle_send_message,
            "GetMessages":  handle_get_messages,
            "GetContactByCode": handle_get_contact_by_code,
        }
        
        handler = action_map.get(soap_action)
        if handler is None:
            return _soap_fault("Client", f"Unknown action: {soap_action}")
        
        return handler(body_el)
    
    except etree.XMLSyntaxError as e:
        return _soap_fault("Client", f"Invalid XML: {e}")
    except Exception as e:
        return _soap_fault("Server", f"Internal server error: {e}")

# ─── Main ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    database.init_db()
    print("=" * 55)
    print("  Secure XML Messaging - SOAP Server")
    print("  WSDL  : http://127.0.0.1:8000/")
    print("  SOAP  : http://127.0.0.1:8000/soap")
    print("=" * 55)
    app.run(host="127.0.0.1", port=8000, debug=True, use_reloader=False)
