import copy
from threading import ThreadError
from dotenv import load_dotenv
from flask import Flask, request, jsonify, render_template, url_for
import hmac
import hashlib
import json
import logging
import os
from flask.typing import HeaderValue, ResponseClass
from slack_sdk import WebClient
import sqlite3
import sys
import time
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
    cursor.execute("SELECT 1")
    conn.close()
except sqlite3.Error as e:
    raise Exception(f"Failed to connect to the database at {DB_PATH}: {e}")

# Other Config
PORT = int(os.getenv("PORT", 5000))
DEBUG = os.getenv("DEBUG", "True").lower() in ("true", "1")

# Other variables
with open("send_message_view.json", "r") as f:
    send_message_view = json.load(f)

with open("message_template.json", "r") as f:
    message_template = json.load(f)

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

    if payload.get("type") == "message_action":
        callback_id = payload["callback_id"]

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

        return "", 200

    elif payload.get("type") == "view_submission":
        callback_id = payload["view"]["callback_id"]

        if callback_id == "dm_in_thread_submit_modal":
            sender_id = payload["user"]["id"]
            state_values = payload["view"]["state"]["values"]
            message_text = state_values["message_block"]["message"]["value"]

            recipients = state_values["recipients_block"]["recipients"][
                "selected_users"
            ]
            recipients.append(sender_id)

            private_metadata = json.loads(payload["view"]["private_metadata"])
            channel_id = private_metadata["channel_id"]
            thread_ts = private_metadata["thread_ts"]

            # Send an ephemeral message to each recipient in the thread and get the timestamp
            print("Recipients:", recipients)
            sent_message_timestamps = []
            for i in range(len(recipients)):
                response = slack_client.chat_postEphemeral(
                    channel=channel_id,
                    user=recipients[i],
                    thread_ts=thread_ts,
                    text=message_text,
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
        else:
            logging.warning(f"Unsupported view submission callback_id: {callback_id}")
            return "", 200

    else:
        return jsonify({"error": "Unsupported interaction type"}), 400


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


# Fill in the message template with message contents
def generate_message(message, sender):
    filled_message = copy.deepcopy(message_template)
    filled_message.replace("<MESSAGE_PLACEHOLDER>", message)
    filled_message.replace("<SENDER_PLACEHOLDER>", sender)

    return filled_message


# Run the Flask app
if __name__ == "__main__":
    app.run(port=PORT, debug=DEBUG)
