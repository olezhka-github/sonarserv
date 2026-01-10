const API_URL = "http://127.0.0.1:5001/api";
let CURRENT_USER = null;
let CURRENT_CHAT_ID = null;
let REFRESH_INTERVAL = null;
let STATUS_INTERVAL = null;
let TIMEZONE_OFFSET = 0;
let LAST_MESSAGE_COUNT = 0;
const closeBtn = document.getElementById("closeBtn")

// Глобальні функції (мають бути доступні для HTML-атрибутів onclick)

function getCookie(name) {
    const match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
    return match ? match[2] : null;
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) modal.style.display = 'none';
}

function openSettingsModal() {
    document.getElementById('settingsModal').style.display = 'flex';
}

function autoResize(textarea) {
    textarea.style.height = 'auto';
    textarea.style.height = textarea.scrollHeight + 'px';
}

function saveTimezone(value) {
    TIMEZONE_OFFSET = parseInt(value);
    localStorage.setItem('timezone', value);
    updateAllMessageTimes();
}

function updateAllMessageTimes() {
    const timeElements = document.querySelectorAll('.message-time');
    timeElements.forEach(element => {
        const utcTime = element.getAttribute('data-utc-time');
        if (utcTime) element.textContent = formatTime(utcTime);
    });
}

function formatTime(utcTimeString) {
    const date = new Date(utcTimeString);
    const adjustedDate = new Date(date.getTime() + TIMEZONE_OFFSET * 60 * 60 * 1000);
    const hours = adjustedDate.getUTCHours().toString().padStart(2, '0');
    const minutes = adjustedDate.getUTCMinutes().toString().padStart(2, '0');
    return `${hours}:${minutes}`;
}

async function sendMessage() {
    const input = document.getElementById('messageInput');
    if (!input) return;
    const text = input.value.trim();
    if (!text || !CURRENT_CHAT_ID) return;

    input.value = '';
    input.style.height = 'auto';

    try {
        await fetch(`${API_URL}/chat/send`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({
                chat_id: CURRENT_CHAT_ID,
                text: text
            })
        });

        LAST_MESSAGE_COUNT = 0;
        loadMessages(CURRENT_CHAT_ID);
        loadChats();
    } catch (err) {
        console.error('Send message error:', err);
    }
}

function administrationlink() {
    window.location.href = "/account"
}

async function logout() {
    try {
        const response = await fetch("http://127.0.0.1:5001/accountexit", {
            method: "GET",
            headers: { "Content-Type": "application/json" },
            credentials: 'include'
            
        });

        const data = await response.json();
        console.log(data);
        if (data.success) {
            console.log("redirectinf");
            window.location.href = "/login";
            console.log('redirected');
        } else {
            showStatus("❌ " + (data.message || "Помилка"), "#f87171");
        }
    } catch (error) {
        showStatus("❌ Не вдалося з'єднатися з сервером", "#f87171");
        console.error(error);
    }
}

function backToChats() {
    document.getElementById('sidebar').classList.remove('hidden');
    CURRENT_CHAT_ID = null;
    LAST_MESSAGE_COUNT = 0;

    if (REFRESH_INTERVAL) clearInterval(REFRESH_INTERVAL);
    if (STATUS_INTERVAL) clearInterval(STATUS_INTERVAL);

    document.getElementById('chatHeader').style.display = 'none';
    document.getElementById('inputArea').style.display = 'none';
    document.getElementById('messagesArea').innerHTML = `
        <div class="empty-state">
            <div class="empty-state-icon">💬</div>
            <div>Оберіть чат для початку спілкування</div>
        </div>`;

    document.querySelectorAll('.chat-item.active').forEach(item => item.classList.remove('active'));
}

// Функції завантаження даних
async function loadMessages(chatId) {
    try {
        const res = await fetch(`${API_URL}/chat/${chatId}`, { credentials: 'include' });
        const data = await res.json();
        if (data.success) {
            if (data.messages.length !== LAST_MESSAGE_COUNT) {
                LAST_MESSAGE_COUNT = data.messages.length;
                renderMessages(data.messages);
            }
        }
    } catch (err) {
        console.error('Load messages error:', err);
    }
}

async function loadChats() {
    try {
        const res = await fetch(`${API_URL}/chats`, { credentials: 'include' });
        const data = await res.json();
        if (data.success) renderChatsList(data.chats);
    } catch (err) {
        console.error('Load chats error:', err);
    }
}

async function updateContactStatus(username) {
    const statusEl = document.getElementById('isOnline');
    if (!statusEl) return;

    const textEl = statusEl.querySelector('.text');
    const dotEl = statusEl.querySelector('.dot');

    try {
        const res = await fetch(`${API_URL}/status/${username}`, { credentials: 'include' });
        const data = await res.json();

        if (data.success && data.status === 'online') {
            textEl.textContent = 'В мережі';
            statusEl.className = 'status-badge online';
            dotEl.style.backgroundColor = 'green';
        } else {
            textEl.textContent = 'Не в мережі';
            statusEl.className = 'status-badge offline';
            dotEl.style.backgroundColor = 'red';
        }
    } catch (err) {
        textEl.textContent = 'Невідомо';
    }
}

function renderMessages(messages) {
    const area = document.getElementById('messagesArea');
    const isScrolledToBottom = area.scrollHeight - area.clientHeight <= area.scrollTop + 50;

    area.innerHTML = messages.length === 0
        ? '<div class="empty-state"><div>Тут ще немає повідомлень...</div></div>'
        : '';

    messages.forEach(msg => {
        const isMe = msg.from === CURRENT_USER.username;
        const div = document.createElement('div');
        div.className = `message ${isMe ? 'sent' : ''}`;
        div.innerHTML = `
            <div class="message-avatar">${msg.from[0].toUpperCase()}</div>
            <div class="message-content-wrapper">
                <div class="message-content">
                    ${msg.text}
                    <div class="message-time" data-utc-time="${msg.time}">
                        ${formatTime(msg.time)}
                    </div>
                </div>
            </div>`;
        area.appendChild(div);
    });

    if (isScrolledToBottom || messages.length === 1) {
        area.scrollTop = area.scrollHeight;
    }
}

function renderChatsList(chats) {
    const listObj = document.getElementById('chatsList');
    listObj.innerHTML = '';
    chats.forEach(chat => {
        const div = document.createElement('div');
        div.className = `chat-item ${CURRENT_CHAT_ID === chat.id ? 'active' : ''}`;
        div.onclick = () => openChat(chat.id, chat.name);
        div.innerHTML = `
            <div class="chat-avatar">${chat.name[0].toUpperCase()}</div>
            <div class="chat-info">
                <div class="chat-name">${chat.name}</div>
                <div class="chat-last-msg">${chat.last_message || "Повідомлень немає"}</div>
            </div>`;
        listObj.appendChild(div);
    });
}

function openChat(chatId, chatName) {
    if (CURRENT_CHAT_ID !== chatId) {
        CURRENT_CHAT_ID = chatId;
        LAST_MESSAGE_COUNT = 0;
        document.getElementById('messagesArea').innerHTML = '<div class="empty-state">Завантаження...</div>';
    }

    if (window.innerWidth <= 768) document.getElementById('sidebar').classList.add('hidden');

    document.getElementById('chatHeader').style.display = 'flex';
    document.getElementById('inputArea').style.display = 'flex';
    document.getElementById('headerName').textContent = chatName;
    document.getElementById('headerAvatar').innerText = chatName[0].toUpperCase();

    updateContactStatus(chatName);

    if (REFRESH_INTERVAL) clearInterval(REFRESH_INTERVAL);
    loadMessages(chatId);
    REFRESH_INTERVAL = setInterval(() => loadMessages(chatId), 3000);

    if (STATUS_INTERVAL) clearInterval(STATUS_INTERVAL);
    STATUS_INTERVAL = setInterval(() => updateContactStatus(chatName), 5000);
}

// Ініціалізація при завантаженні сторінки
document.addEventListener("DOMContentLoaded", function () {
    const oncm = document.getElementById('openNewChatModalFunc');
    const cmc = document.getElementById('closeModalContact');
    const closeBtn = document.getElementById('closeSettingsBtn'); // переконайтесь, що цей ID є в HTML

    // Обробники подій
    if (oncm) oncm.onclick = openNewChatModal;
    if (cmc) cmc.onclick = () => closeModal('newChatModal');
    if (closeBtn) closeBtn.onclick = () => closeModal('settingsModal');

    const messageInput = document.getElementById('messageInput');
    if (messageInput) {
        messageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        });
    }

    // Закриття модалок по кліку на фон
    document.querySelectorAll('.modal-overlay').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) modal.style.display = 'none';
        });
    });

    checkAuth();
    setInterval(sendPing, 10000);
});

async function checkAuth() {
    try {
        const res = await fetch(`${API_URL}/me`, { credentials: 'include' });
        const data = await res.json();
        if (res.ok && data.success) {
            CURRENT_USER = data.user;
            loadTimezone();
            initApp();
        } else {
            window.location.href = '/login';
        }
    } catch (err) {
        window.location.href = '/login';
    }
}

function loadTimezone() {
    const saved = localStorage.getItem('timezone');
    TIMEZONE_OFFSET = saved !== null ? parseInt(saved) : 3;
    const select = document.getElementById('timezoneSelect');
    if (select) select.value = TIMEZONE_OFFSET.toString();
}

function initApp() {
    const logo = document.getElementById('logoName');
    if (logo) logo.textContent = CURRENT_USER.username;
    loadChats();
    setInterval(loadChats, 5000);
}

function sendPing() {
    fetch(`${API_URL}/ping`, { method: "POST", credentials: "include" }).catch(() => { });
}

async function openNewChatModal() {
    const modal = document.getElementById('newChatModal');
    const list = document.getElementById('contactsList');
    modal.style.display = 'flex';
    list.innerHTML = '<div>Завантаження...</div>';

    try {
        const res = await fetch(`${API_URL}/contacts`, { credentials: 'include' });
        const data = await res.json();
        list.innerHTML = '';
        if (data.success && data.contacts.length > 0) {
            data.contacts.forEach(contact => {
                const div = document.createElement('div');
                div.className = 'contact-list-item';
                div.innerHTML = `<span>${contact.username}</span>`;
                div.onclick = () => createChat(contact.username);
                list.appendChild(div);
            });
        } else {
            list.innerHTML = '<div>Контакти порожні</div>';
        }
    } catch (err) {
        list.innerHTML = '<div>Помилка</div>';
    }
}

async function createChat(targetUser) {
    try {
        const res = await fetch(`${API_URL}/chat/create`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ target_user: targetUser })
        });
        const data = await res.json();
        if (data.success) {
            closeModal('newChatModal');
            loadChats();
            openChat(data.chat_id, targetUser);
        }
    } catch (err) {
        alert('Помилка створення чату');
    }
    closeBtn.addEventListener('click', function () {
        closeModal('settingsModal')
    })
}