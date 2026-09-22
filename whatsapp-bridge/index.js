require("dotenv").config({
    path: "../.env"
});

const {
    default: makeWASocket,
    useMultiFileAuthState,
    DisconnectReason,
    jidDecode
} = require("@whiskeysockets/baileys");

const qrcode = require("qrcode-terminal");
const axios = require("axios");


// ============================================================
// CONFIGURATION
// ============================================================

const FASTAPI_URL =
    "http://127.0.0.1:8000/webhook/message";

const FASTAPI_ACTIVITY_URL =
    "http://127.0.0.1:8000/webhook/activity";

const WEBHOOK_TOKEN =
    process.env.CMJR_WEBHOOK_TOKEN;

const API_TIMEOUT =
    30000;

const FORWARD_NOISY =
    process.env.CMJR_FORWARD_PRESENCE === "true";


// ============================================================
// VALIDATE CONFIGURATION
// ============================================================

if (!WEBHOOK_TOKEN) {
    console.error(
        "ERROR: CMJR_WEBHOOK_TOKEN is not configured."
    );

    process.exit(1);
}


// ============================================================
// HELPERS
// ============================================================

function isGroupJid(jid) {
    return (
        typeof jid === "string" &&
        jid.endsWith("@g.us")
    );
}


function isBroadcastJid(jid) {
    return (
        typeof jid === "string" &&
        jid.includes("broadcast")
    );
}


function getMessageText(message) {

    if (!message) {
        return null;
    }

    return (
        message.conversation ||

        message.extendedTextMessage?.text ||

        message.imageMessage?.caption ||

        message.videoMessage?.caption ||

        message.documentMessage?.caption ||

        message.buttonsResponseMessage?.selectedButtonId ||

        message.listResponseMessage?.singleSelectReply?.selectedRowId ||

        message.templateButtonReplyMessage?.selectedId ||

        null
    );
}


function getParticipant(msg) {

    /*
     * For group messages Baileys normally gives us:
     *
     * msg.key.participant
     *
     * For private chats there is no group participant,
     * so we fall back to remoteJid.
     */

    return (
        msg.key?.participant ||
        msg.key?.remoteJid ||
        "unknown"
    );
}


function getMessageType(message) {

    if (!message) {
        return "";
    }

    if (message.imageMessage) return "image";
    if (message.videoMessage) return "video";
    if (message.audioMessage) return "audio";
    if (message.stickerMessage) return "sticker";
    if (message.documentMessage) return "document";
    if (message.locationMessage) return "location";
    if (message.contactMessage) return "contact";
    if (message.contactsArrayMessage) return "contacts";
    if (message.pollCreationMessage) return "poll";
    if (message.pollCreationMessageV3) return "poll";
    if (message.reactionMessage) return "reaction";
    if (message.extendedTextMessage) return "text";
    if (message.buttonsMessage) return "buttons";
    if (message.listMessage) return "list";
    if (message.buttonsResponseMessage) return "text";
    if (message.listResponseMessage) return "text";
    if (message.templateButtonReplyMessage) return "text";

    return "";
}


function containsMedia(message) {

    return [
        "image",
        "video",
        "audio",
        "sticker",
        "document",
        "location",
        "contact"
    ].includes(
        getMessageType(message)
    );
}


function getChatType(jid) {

    if (isGroupJid(jid)) {
        return "group";
    }

    if (isBroadcastJid(jid)) {
        return "broadcast";
    }

    return "private";
}


function safeJson(value) {

    try {
        return JSON.stringify(
            value,
            null,
            2
        );
    } catch {
        return "[unserializable]";
    }
}


// ============================================================
// FASTAPI MESSAGE PROCESSOR
// ============================================================

async function sendToFastAPI(
    payloadData
) {

    const started =
        Date.now();


    const response =
        await axios.post(
            FASTAPI_URL,
            payloadData,
            {
                timeout: API_TIMEOUT,

                headers: {
                    "Content-Type":
                        "application/json",

                    "X-Webhook-Token":
                        WEBHOOK_TOKEN
                }
            }
        );


    const elapsed =
        Date.now() -
        started;


    return {
        data: response.data,
        elapsed: elapsed
    };
}


async function sendActivity(
    eventType,
    payload
) {

    try {

        const activityResponse =
            await axios.post(
                FASTAPI_ACTIVITY_URL,
                {
                    event_type: eventType,
                    ...payload
                },
                {
                    timeout: Math.min(
                        API_TIMEOUT,
                        5000
                    ),

                    headers: {
                        "Content-Type":
                            "application/json",

                        "X-Webhook-Token":
                            WEBHOOK_TOKEN
                    }
                }
            );

        return (
            activityResponse?.data ||
            null
        );

    } catch (error) {

        console.error(
            `Activity forwarding failed (${eventType}):`,
            error.message
        );

        return null;
    }
}


// ============================================================
// START WHATSAPP
// ============================================================

async function startWhatsApp() {

    console.log(
        "Loading WhatsApp authentication..."
    );


    const {
        state,
        saveCreds
    } =
        await useMultiFileAuthState(
            "./auth"
        );


    const sock =
        makeWASocket({
            auth: state
        });


    // ========================================================
    // SAVE CREDENTIALS
    // ========================================================

    sock.ev.on(
        "creds.update",
        saveCreds
    );


    // ========================================================
    // CONNECTION EVENTS
    // ========================================================

    sock.ev.on(
        "connection.update",
        async (update) => {

            const {
                connection,
                lastDisconnect,
                qr
            } = update;


            // ------------------------------------------------
            // QR CODE
            // ------------------------------------------------

            if (qr) {

                console.log(
                    "\nScan this QR code with WhatsApp:\n"
                );

                qrcode.generate(
                    qr,
                    {
                        small: true
                    }
                );
            }


            // ------------------------------------------------
            // CONNECTED
            // ------------------------------------------------

            if (connection === "open") {

                console.log(
                    "\n========================================"
                );

                console.log(
                    "WHATSAPP CONNECTED"
                );

                console.log(
                    "========================================"
                );


                // Discover groups
                try {

                    const groups =
                        await sock.groupFetchAllParticipating();


                    const groupList =
                        Object.values(groups);


                    console.log(
                        `Monitoring ${groupList.length} group(s).`
                    );


                    for (
                        const group
                        of groupList
                    ) {

                        console.log(
                            `GROUP: ${group.subject} | ${group.id}`
                        );
                    }


                    console.log(
                        "========================================\n"
                    );

                } catch (error) {

                    console.error(
                        "Could not retrieve group list:",
                        error.message
                    );
                }
            }


            // ------------------------------------------------
            // DISCONNECTED
            // ------------------------------------------------

            if (connection === "close") {

                const statusCode =
                    lastDisconnect
                        ?.error
                        ?.output
                        ?.statusCode;


                const shouldReconnect =
                    statusCode !==
                    DisconnectReason.loggedOut;


                console.log(
                    "WhatsApp disconnected."
                );


                if (shouldReconnect) {

                    console.log(
                        "Reconnecting..."
                    );


                    setTimeout(
                        () => {
                            startWhatsApp();
                        },
                        3000
                    );

                } else {

                    console.log(
                        "WhatsApp logged out."
                    );

                    console.log(
                        "The existing auth session is no longer valid."
                    );
                }
            }
        }
    );


    // ========================================================
    // GROUP PARTICIPANT ACTIVITY
    // ========================================================

    sock.ev.on(
        "group-participants.update",
        async (event) => {

            console.log(
                "\n----------------------------------------"
            );

            console.log(
                "GROUP PARTICIPANT ACTIVITY"
            );

            console.log(
                "Group:",
                event.id
            );

            console.log(
                "Action:",
                event.action
            );

            console.log(
                "Participants:",
                event.participants
            );


            /*
             * Possible actions include things such as:
             *
             * add
             * remove
             * promote
             * demote
             *
             * depending on what WhatsApp/Baileys provides.
             */


            console.log(
                "----------------------------------------\n"
            );


            // ------------------------------------------------
            // WELCOME NEW MEMBERS
            // ------------------------------------------------

            if (event.action === "add") {

                const botNumber = (
                    sock.user &&
                    sock.user.id
                ) ?
                    String(sock.user.id).split(":")[0] :
                    null;

                const incoming =
                    (event.participants || [])
                        .filter((participant) => {

                            if (!botNumber) {
                                return true;
                            }

                            const incomingNumber =
                                String(participant).split("@")[0];

                            return (
                                incomingNumber !==
                                botNumber
                            );
                        });

                if (incoming.length > 0) {

                    const activityResponse =
                        await sendActivity(
                            "group-participants.update",
                            {
                                id: event.id,
                                action: event.action,
                                participants: incoming
                            }
                        );

                    if (
                        activityResponse &&
                        activityResponse.reply &&
                        activityResponse.chat_id
                    ) {

                        console.log(
                            "Sending welcome:",
                            activityResponse.reply
                        );

                        await sock.sendMessage(
                            activityResponse.chat_id,
                            {
                                text: activityResponse.reply
                            }
                        );
                    }
                }
            } else {

                sendActivity(
                    "group-participants.update",
                    {
                        id: event.id,
                        action: event.action,
                        participants: event.participants
                    }
                );
            }
        }
    );


    // ========================================================
    // GROUP METADATA UPDATES
    // ========================================================

    sock.ev.on(
        "groups.update",
        async (updates) => {

            console.log(
                "\n----------------------------------------"
            );

            console.log(
                "GROUP UPDATE"
            );


            for (
                const update
                of updates
            ) {

                console.log(
                    safeJson(update)
                );
            }


            console.log(
                "----------------------------------------\n"
            );


            sendActivity(
                "groups.update",
                {
                    id: updates[0]?.id || "",
                    updates: updates
                }
            );
        }
    );


    // ========================================================
    // PRESENCE / USER ACTIVITY
    // ========================================================

    sock.ev.on(
        "presence.update",
        async (update) => {

            console.log(
                "\n----------------------------------------"
            );

            console.log(
                "PRESENCE UPDATE"
            );

            console.log(
                safeJson(update)
            );

            console.log(
                "----------------------------------------\n"
            );


            if (FORWARD_NOISY) {

                sendActivity(
                    "presence.update",
                    {
                        id: update.id,
                        presences: update.presences
                    }
                );
            }
        }
    );


    // ========================================================
    // CHAT UPDATES
    // ========================================================

    sock.ev.on(
        "chats.update",
        async (updates) => {

            console.log(
                "\n----------------------------------------"
            );

            console.log(
                "CHAT UPDATE"
            );

            console.log(
                safeJson(updates)
            );

            console.log(
                "----------------------------------------\n"
            );


            if (FORWARD_NOISY) {

                sendActivity(
                    "chats.update",
                    {
                        id: updates[0]?.id || "",
                        updates: updates
                    }
                );
            }
        }
    );


    // ========================================================
    // MESSAGE UPDATES
    // ========================================================

    sock.ev.on(
        "messages.update",
        async (updates) => {

            console.log(
                "\n----------------------------------------"
            );

            console.log(
                "MESSAGE UPDATE"
            );

            console.log(
                safeJson(updates)
            );

            console.log(
                "----------------------------------------\n"
            );


            for (
                const update
                of updates
            ) {

                if (
                    update.key?.fromMe
                ) {

                    continue;
                }

                sendActivity(
                    "messages.update",
                    {
                        chat_id: update.key?.remoteJid,
                        id: update.key?.id,
                        participant: update.key?.participant
                    }
                );
            }
        }
    );


    // ========================================================
    // MESSAGE DELETIONS
    // ========================================================

    sock.ev.on(
        "messages.delete",
        async (event) => {

            console.log(
                "\n----------------------------------------"
            );

            console.log(
                "MESSAGE DELETE"
            );

            console.log(
                safeJson(event)
            );

            console.log(
                "----------------------------------------\n"
            );


            const keys =
                Array.isArray(event.keys)
                    ? event.keys
                    : [event.key].filter(Boolean);


            for (
                const key
                of keys
            ) {

                if (
                    key?.fromMe
                ) {

                    continue;
                }

                sendActivity(
                    "messages.delete",
                    {
                        chat_id: key?.remoteJid,
                        id: key?.id,
                        participant: key?.participant
                    }
                );
            }
        }
    );


    // ========================================================
    // MESSAGE RECEIPTS
    // ========================================================

    sock.ev.on(
        "message-receipt.update",
        async (updates) => {

            console.log(
                "\n----------------------------------------"
            );

            console.log(
                "MESSAGE RECEIPT UPDATE"
            );

            console.log(
                safeJson(updates)
            );

            console.log(
                "----------------------------------------\n"
            );


            if (FORWARD_NOISY) {

                sendActivity(
                    "message-receipt.update",
                    {
                        id: updates[0]?.key?.remoteJid,
                        updates: updates
                    }
                );
            }
        }
    );


    // ========================================================
    // INCOMING MESSAGES
    // ========================================================

    sock.ev.on(
        "messages.upsert",
        async ({ messages }) => {

            for (
                const msg
                of messages
            ) {

                // --------------------------------------------
                // Validate
                // --------------------------------------------

                if (
                    !msg ||
                    !msg.message
                ) {
                    continue;
                }


                // --------------------------------------------
                // Ignore own messages
                // --------------------------------------------

                if (
                    msg.key?.fromMe
                ) {
                    continue;
                }


                const chatId =
                    msg.key?.remoteJid;


                if (!chatId) {
                    continue;
                }


                // --------------------------------------------
                // Ignore broadcasts
                // --------------------------------------------

                if (
                    isBroadcastJid(chatId)
                ) {
                    continue;
                }


                // --------------------------------------------
                // Determine chat type
                // --------------------------------------------

                const chatType =
                    getChatType(chatId);


                // --------------------------------------------
                // Determine participant
                // --------------------------------------------

                const participant =
                    getParticipant(msg);


                // --------------------------------------------
                // Extract text
                // --------------------------------------------

                const text =
                    getMessageText(
                        msg.message
                    );


                // --------------------------------------------
                // Detect message type
                // --------------------------------------------

                const messageType =
                    getMessageType(
                        msg.message
                    );


                const messageId =
                    msg.key?.id;


                const quotedMessageId =
                    msg.message?.extendedTextMessage
                        ?.contextInfo?.stanzaId ||
                    null;


                // --------------------------------------------
                // Non-text messages: forward metadata only,
                // never download media
                // --------------------------------------------

                if (!text) {

                    console.log(
                        "\n----------------------------------------"
                    );

                    console.log(
                        "NON-TEXT MESSAGE"
                    );

                    console.log(
                        "Chat:",
                        chatId
                    );

                    console.log(
                        "Type:",
                        chatType
                    );

                    console.log(
                        "Participant:",
                        participant
                    );

                    console.log(
                        "Message type:",
                        messageType || "unknown"
                    );

                    console.log(
                        "----------------------------------------\n"
                    );


                    if (
                        messageType &&
                        containsMedia(
                            msg.message
                        )
                    ) {

                        try {

                            const metadataResult =
                                await sendToFastAPI({
                                    sender: participant,
                                    text: "",
                                    chat_id: chatId,
                                    chat_type: chatType,
                                    participant: participant,
                                    message_id: messageId,
                                    message_type: messageType,
                                    timestamp:
                                        String(
                                            Date.now()
                                        )
                                });


                            console.log(
                                "FastAPI metadata response:",
                                metadataResult.data
                            );

                        } catch (error) {

                            console.error(
                                "FastAPI metadata request failed:",
                                error.message
                            );
                        }
                    }

                    continue;
                }


                const receivedAt =
                    Date.now();


                // =================================================
                // PRIVATE MESSAGE
                // =================================================

                if (
                    chatType === "private"
                ) {

                    console.log(
                        "\n========================================"
                    );

                    console.log(
                        "PRIVATE MESSAGE"
                    );

                    console.log(
                        "Sender:",
                        participant
                    );

                    console.log(
                        "Text:",
                        text
                    );

                }


                // =================================================
                // GROUP MESSAGE
                // =================================================

                if (
                    chatType === "group"
                ) {

                    console.log(
                        "\n========================================"
                    );

                    console.log(
                        "GROUP MESSAGE"
                    );

                    console.log(
                        "Group ID:",
                        chatId
                    );

                    console.log(
                        "Participant:",
                        participant
                    );

                    console.log(
                        "Text:",
                        text
                    );
                }


                // =================================================
                // SEND TO CMJR FASTAPI
                // =================================================

                try {

                    const result =
                        await sendToFastAPI({
                            sender: participant,
                            text: text,
                            chat_id: chatId,
                            chat_type: chatType,
                            participant: participant,
                            message_id: messageId,
                            message_type: messageType,
                            quoted_message_id: quotedMessageId,
                            timestamp:
                                String(
                                    receivedAt
                                )
                        });


                    const botResponse =
                        result.data;


                    console.log(
                        "FastAPI response:"
                    );

                    console.log(
                        botResponse
                    );


                    console.log(
                        "FastAPI processing:",
                        result.elapsed,
                        "ms"
                    );


                    // --------------------------------------------
                    // Extract bot response
                    // --------------------------------------------

                    let replyText =
                        null;


                    if (
                        typeof botResponse ===
                        "string"
                    ) {

                        replyText =
                            botResponse;

                    } else if (
                        botResponse?.text
                    ) {

                        replyText =
                            botResponse.text;

                    } else if (
                        botResponse?.message
                    ) {

                        replyText =
                            botResponse.message;

                    } else if (
                        botResponse?.response
                    ) {

                        replyText =
                            botResponse.response;

                    } else if (
                        botResponse?.reply
                    ) {

                        replyText =
                            botResponse.reply;
                    }


                    // --------------------------------------------
                    // Action requests (e.g. DELETE a message)
                    // --------------------------------------------

                    const actionRequest =
                        botResponse?.action_request;


                    if (
                        actionRequest &&
                        actionRequest.action ===
                            "DELETE"
                    ) {

                        const targetId =
                            actionRequest.target_message_id ||
                            quotedMessageId ||
                            messageId;


                        if (targetId) {

                            console.log(
                                "Deleting message:",
                                targetId
                            );


                            try {

                                await sock.sendMessage(
                                    chatId,
                                    {
                                        delete: {
                                            remoteJid: chatId,
                                            id: targetId,
                                            participant:
                                                msg.key?.participant,
                                            fromMe: false
                                        }
                                    }
                                );


                                console.log(
                                    "Message deleted."
                                );

                            } catch (deleteError) {

                                console.error(
                                    "Could not delete message:",
                                    deleteError.message
                                );
                            }
                        }
                    }


                    // --------------------------------------------
                    // No response
                    // --------------------------------------------

                    if (!replyText) {

                        console.log(
                            "FastAPI returned no reply text."
                        );

                        console.log(
                            "========================================\n"
                        );

                        continue;
                    }


                    // =================================================
                    // SEND RESPONSE BACK TO SAME CHAT
                    // =================================================

                    const beforeSend =
                        Date.now();


                    await sock.sendMessage(
                        chatId,
                        {
                            text:
                                String(replyText)
                        }
                    );


                    const afterSend =
                        Date.now();


                    console.log(
                        "WhatsApp reply sent."
                    );

                    console.log(
                        "WhatsApp send:",
                        afterSend -
                            beforeSend,
                        "ms"
                    );

                    console.log(
                        "Total:",
                        afterSend -
                            receivedAt,
                        "ms"
                    );


                } catch (error) {

                    // =============================================
                    // API ERROR
                    // =============================================

                    console.error(
                        "FastAPI request failed."
                    );


                    if (
                        error.response
                    ) {

                        console.error(
                            "HTTP status:",
                            error.response.status
                        );

                        console.error(
                            "Response:",
                            error.response.data
                        );

                    } else {

                        console.error(
                            "Error:",
                            error.message
                        );
                    }


                    // =============================================
                    // Error response to WhatsApp
                    // =============================================

                    try {

                        await sock.sendMessage(
                            chatId,
                            {
                                text:
                                    "CMJR-BOT is temporarily unavailable. Please try again."
                            }
                        );

                    } catch (
                        sendError
                    ) {

                        console.error(
                            "Could not send error message:",
                            sendError.message
                        );
                    }
                }


                console.log(
                    "========================================\n"
                );
            }
        }
    );
}


// ============================================================
// START
// ============================================================

console.log(
    "Starting CMJR-BOT WhatsApp monitor..."
);


startWhatsApp().catch(
    (error) => {

        console.error(
            "Fatal error:",
            error
        );
    }
);
