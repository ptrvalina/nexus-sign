'use strict';

// Conversations handed over to a person: an operator of the bank takes one
// from the queue, reads the history (customer, bot, earlier operators) and
// answers. Only conversations of the operator's own bank are listed; the
// customer sees operators as "agent". Every value is escaped before display.
//
// Uses api(), escapeHtml(), renderTable(), reportError() and state from admin.js.

const conversation = { current: null, after: 0 };

const conversationsEl = () => document.getElementById('conversations-table');
const conversationActiveEl = () => document.getElementById('conversation-active');

async function loadConversations() {
  if (!state.session || !['operator', 'administrator'].includes(state.session.role)) {
    document.getElementById('conversations-section').style.display = 'none';
    return;
  }
  const { conversations } = await api('/admin/api/conversations');
  renderTable(conversationsEl(), [
    { label: 'Topic', render: (c) => escapeHtml(c.topic) },
    { label: 'State', render: (c) => escapeHtml(c.state) },
    { label: 'Why', render: (c) => escapeHtml(c.handoverReason || '') },
    { label: 'Waiting since', render: (c) => escapeHtml(new Date(c.updatedAt).toLocaleString()) },
    { label: '', render: (c) => `<button data-conversation="${escapeHtml(c.conversationId)}">${c.state === 'WITH_AGENT' ? 'Open' : 'Take'}</button>` },
  ], conversations, 'No customer is waiting for a person.');
  for (const button of conversationsEl().querySelectorAll('button[data-conversation]')) {
    button.addEventListener('click', () => takeConversation(button.dataset.conversation).catch(reportError));
  }
}

function renderMessages(messages) {
  const box = document.getElementById('conversation-messages');
  for (const m of messages) {
    const line = document.createElement('div');
    line.style.margin = '4px 0';
    line.innerHTML = `<span class="muted">${escapeHtml(m.senderType)} · ${escapeHtml(new Date(m.createdAt).toLocaleTimeString())}</span><div style="white-space:pre-wrap">${escapeHtml(m.body)}</div>`
      + (m.attachment ? `<div class="muted">Attachment: ${escapeHtml(m.attachment.fileName)} (${escapeHtml(m.attachment.mediaType)}, SHA-256 ${escapeHtml(m.attachment.sha256.slice(0, 16))}…)</div>` : '');
    box.appendChild(line);
    conversation.after = Math.max(conversation.after, m.sequence);
  }
  box.scrollTop = box.scrollHeight;
}

async function takeConversation(conversationId) {
  const taken = await api(`/admin/api/conversations/${conversationId}/claim`, { method: 'POST', body: '{}' });
  conversation.current = taken;
  conversation.after = 0;
  document.getElementById('conversation-messages').innerHTML = '';
  document.getElementById('conversation-title').textContent = `${taken.topic} · NEXUS ID ${taken.nexusId}`;
  conversationActiveEl().style.display = '';
  await refreshMessages();
}

async function refreshMessages() {
  if (!conversation.current) return;
  const { messages } = await api(`/admin/api/conversations/${conversation.current.conversationId}/messages?after=${conversation.after}`);
  renderMessages(messages);
}

function leaveConversation() {
  conversation.current = null;
  conversationActiveEl().style.display = 'none';
  loadConversations().catch(reportError);
}

document.getElementById('conversation-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const input = document.getElementById('conversation-input');
  const body = input.value.trim();
  if (!body || !conversation.current) return;
  await api(`/admin/api/conversations/${conversation.current.conversationId}/messages`, {
    method: 'POST', body: JSON.stringify({ body, clientMessageId: crypto.randomUUID() }),
  }).catch(reportError);
  input.value = '';
  await refreshMessages().catch(reportError);
});
document.getElementById('conversation-release-btn').addEventListener('click', async () => {
  if (conversation.current) await api(`/admin/api/conversations/${conversation.current.conversationId}/release`, { method: 'POST', body: '{}' }).catch(reportError);
  leaveConversation();
});
document.getElementById('conversation-close-btn').addEventListener('click', async () => {
  if (!conversation.current || !confirm('Close this conversation?')) return;
  await api(`/admin/api/conversations/${conversation.current.conversationId}/close`, { method: 'POST', body: '{}' }).catch(reportError);
  leaveConversation();
});
document.getElementById('conversations-refresh-btn').addEventListener('click', () => loadConversations().catch(reportError));
setInterval(() => {
  if (!state.session) return;
  if (conversation.current) refreshMessages().catch(reportError);
  else loadConversations().catch(reportError);
}, 4000);
