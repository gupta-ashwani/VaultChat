document.addEventListener('DOMContentLoaded', async () => {
    // DOM Elements
    const loginScreen = document.getElementById('login-screen');
    const appContainer = document.getElementById('app-container');
    const loginBtn = document.getElementById('login-btn');
    const loginUsername = document.getElementById('login-username');
    const loginStatus = document.getElementById('login-status');
    
    const myUsernameDisplay = document.getElementById('my-username');
    const myFriendCodeDisplay = document.getElementById('my-friend-code');
    const myAvatar = document.getElementById('my-avatar');
    
    const contactInput = document.getElementById('contact-input');
    const setContactBtn = document.getElementById('set-contact-btn');
    const headerContact = document.getElementById('header-contact');
    const contactsList = document.getElementById('contacts-list');
    
    const messagesContainer = document.getElementById('messages-container');
    const messageInput = document.getElementById('message-input');
    const sendBtn = document.getElementById('send-btn');
    
    const xmlPanel = document.getElementById('xml-panel');
    const toggleXmlBtn = document.getElementById('toggle-xml-btn');
    const closeXmlBtn = document.getElementById('close-xml-btn');
    const xmlCodeDisplay = document.getElementById('xml-code-display');

    // State
    let currentUser = null;
    let currentContact = null;
    let pollingInterval = null;

    // ─── Initialization (Auto-Login) ───
    try {
        const res = await fetch('/api/me');
        const data = await res.json();
        if (data.username && data.friend_code) {
            setupUserSession(data.username, data.friend_code);
        }
    } catch (e) {
        console.error("Failed to check session", e);
    }

    // ─── Authentication ───
    loginBtn.addEventListener('click', async () => {
        const username = loginUsername.value.trim();
        if (!username) return;
        
        loginBtn.disabled = true;
        loginStatus.textContent = 'Generating keys and connecting to SOAP server...';
        
        try {
            const response = await fetch('/api/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                setupUserSession(data.username, data.friend_code);
            } else {
                loginStatus.textContent = `Error: ${data.error}`;
                loginStatus.style.color = 'var(--danger)';
                loginBtn.disabled = false;
            }
        } catch (err) {
            loginStatus.textContent = `Network Error: ${err}`;
            loginStatus.style.color = 'var(--danger)';
            loginBtn.disabled = false;
        }
    });

    function setupUserSession(username, friendCode) {
        currentUser = username;
        myUsernameDisplay.textContent = username;
        myFriendCodeDisplay.textContent = `#${friendCode}`;
        myAvatar.textContent = username.charAt(0).toUpperCase();
        
        loginScreen.classList.add('hidden');
        appContainer.classList.remove('hidden');
        
        loadContacts();
        startPolling();
    }

    // ─── Contacts ───
    async function loadContacts() {
        try {
            const res = await fetch('/api/contacts');
            const data = await res.json();
            contactsList.innerHTML = '';
            
            data.contacts.forEach(c => {
                const div = document.createElement('div');
                div.className = 'contact-item';
                div.innerHTML = `
                    <div class="contact-avatar">${c.username.charAt(0).toUpperCase()}</div>
                    <div class="contact-details">
                        <span class="contact-name">${escapeHTML(c.username)}</span>
                        <span class="contact-code">#${escapeHTML(c.friend_code)}</span>
                    </div>
                `;
                
                div.addEventListener('click', () => {
                    // Remove active class from all, add to this one
                    document.querySelectorAll('.contact-item').forEach(el => el.classList.remove('active'));
                    div.classList.add('active');
                    selectContact(c.username);
                });
                
                contactsList.appendChild(div);
            });
        } catch (e) {
            console.error("Failed to load contacts", e);
        }
    }

    setContactBtn.addEventListener('click', async () => {
        const friendCode = contactInput.value.trim().toUpperCase();
        if (!friendCode) return;
        
        setContactBtn.disabled = true;
        setContactBtn.textContent = '...';
        
        try {
            const res = await fetch('/api/contacts', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ friend_code: friendCode })
            });
            const data = await res.json();
            
            if (res.ok) {
                contactInput.value = '';
                await loadContacts();
                selectContact(data.username);
            } else {
                alert(`Error: ${data.error}`);
            }
        } catch (e) {
            alert(`Error adding contact: ${e}`);
        } finally {
            setContactBtn.disabled = false;
            setContactBtn.textContent = 'Add';
        }
    });

    function selectContact(username) {
        currentContact = username;
        headerContact.textContent = `with ${username}`;
        
        messageInput.disabled = false;
        sendBtn.disabled = false;
        
        // Immediately load history for this contact
        pollMessages();
    }

    // ─── Sending Messages ───
    const sendMessage = async () => {
        const text = messageInput.value.trim();
        if (!text || !currentContact) return;
        
        messageInput.value = '';
        messageInput.disabled = true;
        sendBtn.disabled = true;
        
        try {
            await fetch('/api/send', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    receiver: currentContact,
                    message: text
                })
            });
            // Let the polling system pick up the newly sent message from local DB
            pollMessages();
        } catch (err) {
            console.error("Send error", err);
        } finally {
            messageInput.disabled = false;
            sendBtn.disabled = false;
            messageInput.focus();
        }
    };

    sendBtn.addEventListener('click', sendMessage);
    messageInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
    });

    // ─── Loading Chat History (Polling Local DB) ───
    const pollMessages = async () => {
        if (!currentUser || !currentContact) return;
        
        try {
            const response = await fetch(`/api/history?contact=${encodeURIComponent(currentContact)}`);
            if (!response.ok) return;
            
            const data = await response.json();
            
            // Only update DOM if number of messages changed (simple diff check)
            if (data.messages.length !== messagesContainer.children.length) {
                messagesContainer.innerHTML = ''; // clear and rebuild
                data.messages.forEach(msg => {
                    const msgEl = createMessageElement(msg.text, msg.is_sent, msg.signature_valid, msg.timestamp);
                    msgEl.dataset.xml = formatXml(msg.raw_xml || '<NoXMLFound/>');
                    messagesContainer.appendChild(msgEl);
                });
                scrollToBottom();
            }
        } catch (err) {
            console.error("Polling error:", err);
        }
    };

    const startPolling = () => {
        if (pollingInterval) clearInterval(pollingInterval);
        pollingInterval = setInterval(pollMessages, 2000); // Poll local DB every 2 seconds
    };

    // ─── UI Helpers ───
    const createMessageElement = (text, isSent, statusOrValid, timestamp = '') => {
        const div = document.createElement('div');
        div.className = `message ${isSent ? 'sent' : 'received'}`;
        
        const timeStr = timestamp ? new Date(timestamp + 'Z').toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}) : '';
        const sigClass = statusOrValid ? 'sig-valid' : 'sig-invalid';
        const sigText = statusOrValid ? 'SIG ✓' : 'SIG ✗';
        
        div.innerHTML = `
            <div class="message-content">${escapeHTML(text)}</div>
            <div class="message-meta">
                <span>${timeStr}</span>
                <span class="sig-badge ${sigClass}" title="${statusOrValid ? 'RSA Signature Verified' : 'Signature Failed / Tampered!'}">${sigText}</span>
            </div>
        `;
        
        div.addEventListener('click', () => {
            if (div.dataset.xml) {
                showXml(div.dataset.xml);
            }
        });
        
        return div;
    };

    const scrollToBottom = () => {
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    };

    const escapeHTML = (str) => {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    };
    
    // Basic XML formatter for readability
    const formatXml = (xml) => {
        let formatted = '';
        let reg = /(>)(<)(\/*)/g;
        xml = xml.replace(reg, '$1\r\n$2$3');
        let pad = 0;
        xml.split('\r\n').forEach((node) => {
            let indent = 0;
            if (node.match( /.+<\/\w[^>]*>$/ )) { indent = 0; }
            else if (node.match( /^<\/\w/ )) {
                if (pad != 0) { pad -= 1; }
            }
            else if (node.match( /^<\w[^>]*[^\/]>.*$/ )) { indent = 1; }
            else { indent = 0; }
            
            let padding = '';
            for (let i = 0; i < pad; i++) padding += '  ';
            formatted += padding + node + '\r\n';
            pad += indent;
        });
        return formatted;
    };

    // ─── XML Panel Toggle ───
    const showXml = (xmlStr) => {
        xmlCodeDisplay.textContent = xmlStr;
        xmlPanel.classList.remove('hidden');
    };

    toggleXmlBtn.addEventListener('click', () => {
        xmlPanel.classList.toggle('hidden');
    });

    closeXmlBtn.addEventListener('click', () => {
        xmlPanel.classList.add('hidden');
    });
});
