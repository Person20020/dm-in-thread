# DM in Thread

A slack bot to allow you to directly message specific users in a thread. (e.g. to try to make them stay on topic without cluttering the thread)
Usage

DM in Thread (Shortcut) - Open a window to send a message. From here you can specify the recipient(s) and the contents of your message.

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
### TODO WILL ADD LATER


## Tools

Built using Flask with a SQLite database.
