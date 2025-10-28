import copy
from dotenv import load_dotenv
from flask import Flask, request, jsonify, render_template, url_for
import hmac
import hashlib
import json
import logging
import os
from slack_sdk import WebClient
import sqlite3
import sys
import time
from slack_sdk.models import blocks
from werkzeug.datastructures import headers


_ = load_dotenv()

# Logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)


# Variables for testing
test_channel_id = "C08HXF60ER0"

# Slack Bot Client
SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN")
if not SLACK_BOT_TOKEN:
    raise ValueError("SLACK_BOT_TOKEN is not set in environment variables.")
slack_client = WebClient(token=SLACK_BOT_TOKEN)

SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET")
if not SLACK_SIGNING_SECRET:
    raise ValueError("SLACK_SIGNING_SECRET is not set in environment variables.")

# SQLite DB
DB_PATH = os.getenv("DB_PATH", "database.db")
if not DB_PATH:
    raise ValueError("DB_PATH is not set in environment variables.")
try:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    _ = cursor.execute("SELECT 1")
    conn.close()
except sqlite3.Error as e:
    raise Exception(f"Failed to connect to the database at {DB_PATH}: {e}")

# Other Config
PORT = int(os.getenv("PORT", 5000))
DEBUG = os.getenv("DEBUG", "True").lower() in ("true", "1")
MESSAGE_PREVIEW_LENGTH = 37  # Number of characters to show in message reply preview (before adding "..." if truncated)

# Other variables
with open("send_message_view.json", "r") as f:
    send_message_view = json.load(f)

with open("message_template.json", "r") as f:
    message_template = json.load(f)

with open("reply_template.json", "r") as f:
    reply_template = json.load(f)

with open("reply_view.json", "r") as f:
    reply_view = json.load(f)


# Slack info
auth_info = slack_client.auth_test()
if not auth_info["ok"]:
    raise ValueError("Failed to authenticate with Slack. Check your SLACK_BOT_TOKEN.")
WORKSPACE_URL = auth_info["url"]
BOT_USER_ID = auth_info["user_id"]


app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/slack/interactions", methods=["POST"])
def slack_interactions():
    if not verify_slack_request(request):
        logging.warning("Slack request verification failed.")
        return jsonify({"error": "Invalid request"}), 403

    payload = json.loads(request.form["payload"])
    if not payload:
        return jsonify({"error": "Missing payload"}), 400

    trigger_id = payload["trigger_id"]

    # Shortcut is triggered
    if payload.get("type") == "message_action":
        callback_id = payload["callback_id"]

        # Direct message in thread --------------------------------------------------------------------------------
        if callback_id == "dm_in_thread_open_modal":
            channel_id = payload["channel"]["id"]
            user_id = payload["user"]["id"]
            thread_ts = (
                payload["message"]["thread_ts"]
                if "thread_ts" in payload["message"]
                else payload["message"]["ts"]
            )

            # Generate the modal with metadata
            form = copy.deepcopy(send_message_view)
            form["private_metadata"] = json.dumps(
                {"channel_id": channel_id, "thread_ts": thread_ts}
            )

            # Open the modal view
            response = slack_client.views_open(view=form, trigger_id=trigger_id)
            if not response["ok"]:
                slack_client.chat_postEphemeral(
                    channel=channel_id,
                    user=user_id,
                    thread_ts=thread_ts,
                    text="Failed to open the message modal.",
                )
                logging.error("Failed to open the message modal.")
                return "", 200

        # Reply --------------------------------------------------------------------------------
        elif callback_id == "reply_open_modal":
            user_id = payload["user"]["id"]
            channel_id = payload["channel"]["id"]
            message_ts = payload["message"]["ts"]

            # Generate the modal with metadata
            form = copy.deepcopy(reply_view)
            form["private_metadata"] = json.dumps(
                {"channel_id": channel_id, "message_ts": message_ts}
            )

            # Open the modal view
            response = slack_client.views_open(view=form, trigger_id=trigger_id)
            if not response["ok"]:
                slack_client.chat_postEphemeral(
                    channel=channel_id,
                    user=user_id,
                    thread_ts=message_ts,
                    text="Failed to open reply modal.",
                )
                logging.error("Failed to open the reply modal.")
                return "", 200

        return "", 200

    # Modal window is submitted
    elif payload.get("type") == "view_submission":
        callback_id = payload["view"]["callback_id"]

        # DM in thread submission --------------------------------------------------------------------------------
        if callback_id == "dm_in_thread_submit_modal":
            sender_id = payload["user"]["id"]
            state_values = payload["view"]["state"]["values"]
            message_text = state_values["message_block"]["message"]["value"]

            sanitized_message_text = (
                message_text.replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("&", "&amp;")
            )

            recipients = state_values["recipients_block"]["recipients"][
                "selected_users"
            ]
            if not sender_id in recipients:
                recipients.append(sender_id)

            private_metadata = json.loads(payload["view"]["private_metadata"])
            channel_id = private_metadata["channel_id"]
            thread_ts = private_metadata["thread_ts"]

            # Send an ephemeral message to each recipient in the thread and get the timestamp
            sent_message_timestamps = []
            for i in range(len(recipients)):
                response = slack_client.chat_postEphemeral(
                    channel=channel_id,
                    user=recipients[i],
                    thread_ts=thread_ts,
                    blocks=generate_message(message_text, sender_id),
                    text=sanitized_message_text,
                )
                if response["ok"]:
                    sent_message_timestamps.append(response["message_ts"])
                    logging.info(f"Message sent to <@{recipients[i]}>.")
                else:
                    _ = slack_client.chat_postEphemeral(
                        channel=channel_id,
                        user=sender_id,
                        thread_ts=thread_ts,
                        text=f"Failed to send message to <@{recipients[i]}>.",
                    )
                    logging.error(f"Failed to send message to <@{recipients[i]}>.")

            # Log message, sender, and recipients to the database
            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                _ = cursor.execute(
                    "INSERT INTO sent_messages (sender, recipients, channel_id, message_text, sent_message_timestamps) VALUES (?, ?, ?, ?, ?)",
                    (
                        sender_id,
                        ",".join(recipients),
                        channel_id,
                        message_text,
                        ",".join(sent_message_timestamps),
                    ),
                )
                conn.commit()
                conn.close()
            except sqlite3.Error as e:
                print(f"Database error: {e}")

            return "", 200

        # Reply submission --------------------------------------------------------------------------------
        elif callback_id == "reply_submit_modal":
            sender_id = payload["user"]["id"]
            state_values = payload["view"]["state"]["values"]
            message_text = state_values["reply_input_block"]["reply_input"]["value"]
            sanitized_message_text = (
                message_text.replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("&", "&amp;")
            )

            private_metadata = json.loads(payload["view"]["private_metadata"])
            channel_id = private_metadata["channel_id"]
            message_ts = private_metadata["message_ts"]

            try:
                response = slack_client.users_info(user=sender_id)
                sender_display_name = (
                    response["user"]["profile"]["display_name"]
                    if response["ok"]
                    else "unknown_user"
                )
                sender_icon_url = (
                    response["user"]["profile"]["image_48"] if response["ok"] else ""
                )
            except Exception:
                # probably not a user
                sender_display_name = "unknown_user"
                sender_icon_url = ""

            slack_client.chat_postMessage(
                username=sender_display_name,
                icon_url=sender_icon_url,
                channel=channel_id,
                thread_ts=message_ts,
                blocks=generate_reply(
                    message=message_text,
                    sender=sender_id,
                    message_ts=message_ts,
                    channel_id=channel_id,
                ),
                text=f"{message_text.replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')}",
            )

            return "", 200

        else:
            logging.warning(f"Unsupported view submission callback_id: {callback_id}")
            return "", 200

    else:
        return jsonify({"error": "Unsupported interaction type"}), 400


# Verify the request comes from slack --------------------------------------------------------
def verify_slack_request(req):
    headers = req.headers
    slack_signature = headers.get("X-Slack-Signature", "")
    slack_request_timestamp = headers.get("X-Slack-Request-Timestamp", "")

    if not slack_signature or not slack_request_timestamp:
        return False

    if abs(time.time() - int(slack_request_timestamp)) > 60 * 5:
        return False

    body = req.get_data(as_text=False)

    if not SLACK_SIGNING_SECRET:
        raise ValueError("SLACK_SIGNING_SECRET is not set in environment variables.")

    sig_basestring = b"v0:" + slack_request_timestamp.encode() + b":" + body

    my_signature = (
        "v0="
        + hmac.new(
            SLACK_SIGNING_SECRET.encode(), sig_basestring, hashlib.sha256
        ).hexdigest()
    )

    if not hmac.compare_digest(my_signature, slack_signature):
        return False

    return True


# Fill in the message template with message contents ----------------------------------------
def generate_message(message, sender):
    filled_message = json.dumps(copy.deepcopy(message_template))
    filled_message = filled_message.replace("<MESSAGE_PLACEHOLDER>", message)
    filled_message = filled_message.replace("<SENDER_PLACEHOLDER>", f"<@{sender}>")
    filled_message = json.loads(filled_message)

    return filled_message["blocks"]


# Fill in the reply template with message contents ----------------------------------------
def generate_reply(message, sender, message_ts, channel_id):
    # Get original message
    # Join channel if bot is not a member
    response = slack_client.conversations_members(channel=channel_id)
    if response["ok"]:
        if slack_client.auth_test()["user_id"] not in response["members"]:
            _ = slack_client.conversations_join(channel=channel_id)

    response = slack_client.conversations_replies(
        channel=channel_id, ts=message_ts, limit=1
    )
    if not response["ok"] or len(response["messages"]) == 0:
        response = slack_client.conversations_history(
            channel=channel_id, oldest=message_ts, inclusive=True, limit=1
        )

    if not response["ok"] or len(response["messages"]) == 0:
        slack_client.chat_postEphemeral(
            channel=channel_id,
            user=sender,
            text="Failed to retrieve the original message.",
        )
        logging.error("Failed to retrieve the original message.")
        return ""

    original_message = response["messages"][0]["text"]
    original_message_full = response["messages"][0]
    is_bot_message = "bot_id" in response["messages"][0]
    original_message_sender = (
        original_message_full.get("user", "")
        or original_message_full.get("bot_id", "")
        or "unknown_user"
    )

    # Truncate original message
    if len(original_message) > MESSAGE_PREVIEW_LENGTH:
        truncated_original_message = original_message[0:MESSAGE_PREVIEW_LENGTH] + "..."
    else:
        truncated_original_message = original_message

    truncated_original_message = (
        truncated_original_message.replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("&", "&amp;")
    )

    # Get user info
    if is_bot_message:
        # Bot message
        response = slack_client.bots_info(bot=original_message_sender)
        if not response["ok"]:
            slack_client.chat_postEphemeral(
                channel=channel_id,
                user=sender,
                text="Failed to retrieve the original message sender info.",
            )
            logging.error("Failed to retrieve the original message sender info.")
            original_message_sender_username = "unknown_user"

        bot_id = response["bot"]["id"]
        if bot_id == BOT_USER_ID:
            # Get user name from previous message
            response = slack_client.conversations_replies(
                channel=channel_id, ts=message_ts, limit=2
            )
            if not response["ok"] or len(response["messages"]) < 2:
                slack_client.chat_postEphemeral(
                    channel=channel_id,
                    user=sender,
                    text="Failed to retrieve the original message sender info.",
                )
                logging.error("Failed to retrieve the original message sender info.")
                original_message_sender_username = "unknown_user"

            if "username" in response["messages"][1]:
                original_message_sender_username = response["messages"][1]["username"]

        else:
            original_message_sender_username = response["bot"]["name"]
    else:
        response = slack_client.users_info(user=original_message_sender)
        original_message_sender_username = (
            response["user"]["profile"]["display_name"]
            if response["ok"]
            else "unknown_user"
        )

    original_message_sender_username = (
        original_message_sender_username.replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("&", "&amp;")
    )

    # Get message link
    if original_message_sender_username:  # != "unknown_user" and not is_bot_message:
        response = slack_client.chat_getPermalink(
            channel=channel_id, message_ts=message_ts
        )
        print(response)
        if not response["ok"]:
            slack_client.chat_postEphemeral(
                channel=channel_id, user=sender, text="Failed to get message permalink."
            )
            logging.warning("Failed to get message permalink.")
            message_link = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
        else:
            message_link = response["permalink"]
    else:
        message_link = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"

    # Fill in the template
    filled_reply = json.dumps(copy.deepcopy(reply_template))
    filled_reply = filled_reply.replace(
        "<REPLIED_TO_USER_PROFILE>",
        f"<{WORKSPACE_URL}/team/{original_message_sender}|@{original_message_sender_username}>",
    )

    filled_reply = filled_reply.replace(
        "<SHORTENED_MESSAGE_PREVIEW>", f"<{message_link}|{truncated_original_message}>"
    )
    filled_reply = filled_reply.replace(
        "<MESSAGE_PLACEHOLDER>",
        message.replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("&", "&amp;")
        .replace(r'"', r"\""),
    )

    filled_reply = json.loads(filled_reply)

    return filled_reply["blocks"]


# Run the Flask app --------------------------------------------------------
if __name__ == "__main__":
    app.run(port=PORT, debug=DEBUG)
