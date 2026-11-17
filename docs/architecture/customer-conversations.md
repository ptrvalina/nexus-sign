# Conversations with the bank

Status: unreleased, planned for 2.0.0 (current version 2.0.0-rc.2). Implementation: `auth-core/src/services/conversationService.ts`, migration `029_customer_conversations.sql`, console `auth-core/public/admin/conversations.js`. Tests: `auth-core/test/integration/conversations.test.mjs` (PostgreSQL).

Chat with the bank, the bank's bot and the handover to a person (presentation pages 11 and 12) run inside the bank's app through the SDK. This is not a messenger: a conversation belongs to one NEXUS ID of one bank client, and only that customer's enrolled devices, that bank's backend and that bank's operators take part.

## Participants

| Who | How | Can |
|---|---|---|
| Customer | Device-signed requests from an enrolled device (`/v1/mobile/conversations…`) | Open a conversation (optionally about one of their payments), write, read, ask for a person, close |
| The bank's bot | Runs at the bank. Receives customer messages as the `conversation.message` webhook; answers with `POST /v1/conversations/{id}/bot-messages` (mTLS, bank token) | Answer while the conversation is `WITH_BOT`; hand over (`handover: true`); close |
| Operator of the bank | Console session with the operator role of that bank client (`/admin/api/conversations…`) | Take a waiting conversation, answer, put it back in the queue, close. Platform operators without a bank see nothing |

Auth Core does not run a bot and does not call outside services; which bot or assistant the bank uses is the bank's decision and stays in the bank's systems.

## States

`WITH_BOT` → `WAITING_FOR_AGENT` (the customer asks for a person, or the bot hands over) → `WITH_AGENT` (an operator takes it) → `WAITING_FOR_AGENT` (released) or `CLOSED`. Any open state can be closed. The trigger `conversations_lifecycle` enforces the transitions and keeps owner, topic and payment immutable.

## Messages

- Up to 4000 characters, NFC; control, invisible and bidi-override characters are refused (line breaks and tabs are allowed).
- Attachments are stored by the bank. A message carries the bank's reference, the SHA-256 of the content, the media type, a plain file name and the size (up to 50 MB); the app checks the downloaded content against the hash.
- Idempotent per sender and `clientMessageId`; the same id with other text is refused (`MESSAGE_ID_REUSED`).
- Numbered per conversation under the conversation's row lock, so concurrent messages get distinct numbers.
- Hash-chained: `messageHash = SHA-256(canonical JSON of conversation, sequence, sender type, sender, body, attachment, time, previous hash)`. `GET /v1/conversations/{id}/integrity` recomputes the chain; a changed or removed message is reported.
- Append-only (trigger `conversation_messages_append_only`): only `delivered_at` (set when the customer's app fetches the bank's messages) and `read_at` (`POST …/read`) are set, once each.
- To the customer an operator appears as `agent`; the bank sees the operator's username.

## Notifications

Every customer message, system notice and operator answer reaches the bank as `conversation.message`; the bank decides whether to push to the customer's app (push is the bank's infrastructure). The bot's own messages are not sent back to the bank.

## Not covered here

- Message bodies are stored in the Auth Core database in clear text, protected like the rest of the database (access control, encryption at rest by the bank). They are not end-to-end encrypted.
- No retention period is enforced; the bank sets one under its record-keeping rules.
- The SDK methods are written but have not been compiled or run on a device.
