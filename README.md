# DM in Thread

A slack bot to allow you to directly message specific users in a thread. (e.g. to try to make them stay on topic without cluttering the thread)
Usage

`DM in Thread` (Shortcut) - Open a window to send a message. From here you can specify the recipient(s) and the contents of your message.

`Reply` (Shortcut) - Open a window to send a message. The sent message is formatted as a reply to a previous message with a preview of the other person's message and a link to it. (It is similar to discord replies)

## Running Bot

1. Clone repository
git clone https://github.com/Person20020/dm-in-thread.git && cd dm-in-thread

2. Create python venv
python -m venv venv

3. Activate venv
source venv/bin/activate # Linux/MacOS
venv\Scripts\activate # Windows

4. Install dependencies
pip install -r requirements.txt

5. Create a .env file in the root directory with the following variables:

  ```
  SLACK_BOT_TOKEN=your-bot-token
  DB_PATH=path/to/your/sqlite/db
  PORT=your-port # optional, default is 5000
  ```

## Demo

Demo video

https://github.com/user-attachments/assets/cb55c4a2-f303-42b6-99de-75ff3e417348



## Tools

Built using Flask with a SQLite database.
