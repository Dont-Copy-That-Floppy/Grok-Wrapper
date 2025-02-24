#!/usr/bin/python3

import requests
import json
import sys
import time
from flask import Flask, request, jsonify
import threading
import queue
import pyotp
import os
try:
    from lib import my_secrets, my_crypto
except:
    from lib import my_crypto
    print("Setting up new creds...")
    print("Please input a password to store/retrieve your creds")
    crypto_session = my_crypto.SESSION("x.com")
    email = crypto_session.encrypt_str(input("Please input your login email\n"))
    password = crypto_session.encrypt_str(input("Please input your login password\n"))
    otp_secret = crypto_session.encrypt_str(input("Please input your login otp secret\n"))
    with open("lib/my_secrets.py", "w") as file:
        file.writelines(f"x_email = {email}\nx_password = {password}\nx_otp = {otp_secret}")
    from lib import my_secrets
    print("Creds setup finished\n")


class API:
    email = ""
    password = ""
    otp = ""

    def __init__(self) -> None:
        try:
            cookies = {}
            self.session = requests.session()
            requests.utils.add_dict_to_cookiejar(self.session.cookies, cookies)
            self.session.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/112.0"})
        except Exception as e:
            print("Session creation aborted due to %s" % e)

    def createNewGrokConvo(self) -> str:
        response = self.session.post("https://x.com/i/api/graphql/vvC5uy7pWWHXS2aDi1FZeA/CreateGrokConversation", json={"variables": {}, "queryId": "vvC5uy7pWWHXS2aDi1FZeA"})
        if response.status_code == 200:
            try:
                return json.loads(response.content)["data"]["create_grok_conversation"]["conversation_id"]
            except Exception as e:
                print(f"{response.text}\nFailed to convert new grok convo to json.\n")
                sys.exit()
        else:
            print(f"{response.text}\nFailed to retrieve new grok convo\n")
            sys.exit()

    def talk2grok(self, conversation_id: str, message: str, isDeepsearch: bool = False, isReasoning: bool = False) -> json:
        payload = {
            "responses": [{"message": message, "sender": 1, "promptSource": "", "fileAttachments": []}],
            "systemPromptName": "",
            "grokModelOptionId": "grok-3",
            "conversationId": conversation_id,
            "returnSearchResults": True,
            "returnCitations": True,
            "promptMetadata": {"promptSource": "NATURAL", "action": "INPUT"},
            "imageGenerationCount": 4,
            "requestFeatures": {"eagerTweets": True, "serverHistory": True},
            "enableCustomization": True,
            "enableSideBySide": True,
            "toolOverrides": {},
            "isDeepsearch": isDeepsearch,
            "isReasoning": isReasoning,
        }
        response = self.session.post("https://grok.x.com/2/grok/add_response.json", json=payload)
        if response.status_code == 200:
            try:
                return json.loads(response.content)["data"]["create_grok_conversation"]["conversation_id"]
            except Exception as e:
                print(f"{response.text}\nFailed to convert new grok convo to json.\n")
                sys.exit()
        else:
            print(f"{response.text}\nFailed to retrieve new grok convo\n")
            sys.exit()

    def convert_grok_to_openai(self, json_input: json) -> dict:
        lines = json_input.strip().splitlines()

        conversation_id = None
        message_parts = []

        for line in lines:
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue  # skip lines that aren't valid JSON

            # Check for conversation header info
            if "conversationId" in data:
                conversation_id = data.get("conversationId")
            # Extract assistant message parts
            elif "result" in data and "message" in data["result"]:
                message_parts.append(data["result"]["message"])

        # Concatenate all message parts (assuming spacing is handled in each part)
        final_message = "".join(message_parts).strip()

        # Build the OpenAI response structure
        openai_response = {
            "id": conversation_id,
            "object": "chat.completion",
            "created": int(time.time()),
            "model": "grok-3",
            "choices": [{"message": {"role": "assistant", "content": final_message}, "finish_reason": "stop", "index": 0}],
            "usage": {"prompt_tokens": 0, "completion_tokens": len(final_message.split()), "total_tokens": len(final_message.split())},
        }

        return openai_response

    def convert_openai_to_grok(self, conversation_id: str, openai_payload: dict) -> dict:
        # Extract message from the first choice, if present.
        message = ""
        if "choices" in openai_payload and openai_payload["choices"]:
            try:
                message = openai_payload["choices"][0]["message"]["content"]
            except (IndexError, KeyError):
                message = ""

        # Build the main response object.
        main_response = {
            "responses": [{"message": message, "sender": 1, "promptSource": "", "fileAttachments": []}],
            "systemPromptName": "",
            "grokModelOptionId": "grok-3",
            "conversationId": conversation_id,
            "returnSearchResults": True,
            "returnCitations": True,
            "promptMetadata": {"promptSource": "NATURAL", "action": "INPUT"},
            "imageGenerationCount": 4,
            "requestFeatures": {"eagerTweets": True, "serverHistory": True},
            "enableCustomization": True,
            "enableSideBySide": True,
            "toolOverrides": {},
            "isDeepsearch": False,
            "isReasoning": False,
        }

        return main_response

    def login(self) -> bool:
        """
        Auto login with creds. Return if success
        """
        nitter = NITTER()
        self.session = nitter.session

        if nitter.session_entry:
            return True
        else:
            return False

    def runServer(self, timeLength: int = 999999) -> None:
        """
        Run a translation server for openai compatible interfaces
        Input: timeLength, length of time in secs to run server
        """
        openai_server = OpenAI_SERVER()
        openai_server.run_threaded()
        print("OpenAI server is running on port 8080. Waiting for requests...")
        grok_conversation_id = self.createNewGrokConvo()
        print(f"New grok conversation start: {grok_conversation_id}")
        try:
            while True:
                try:
                    payload, result_queue = openai_server.payload_queue.get(timeout=1)
                except queue.Empty:
                    continue  # No payload available, keep waiting.

                # Process the payload.
                processed_result = self.convert_openai_to_grok(payload)
                grok_result = self.talk2grok(conversation_id=grok_conversation_id, message=processed_result)
                openai_mimic = self.convert_grok_to_openai(grok_result)
                result_queue.put(openai_mimic)
        except KeyboardInterrupt:
            print("Shutting down.")

        return None


class OpenAI_SERVER:
    def __init__(self, host="127.0.0.1", port=8080) -> None:
        self.app = Flask(__name__)
        self.host = host
        self.port = port
        # Queue to hold incoming payloads.
        self.payload_queue = queue.Queue()
        self.setup_routes()

    def setup_routes(self) -> None:
        @self.app.route("/", methods=["POST"])
        def translate_openai_request() -> json:
            try:
                # Get the OpenAI JSON payload from the request.
                payload = request.get_json(force=True)
            except Exception:
                return jsonify({"error": "Invalid JSON payload"}), 400

            # Create a queue for this request's result.
            result_queue = queue.Queue()
            self.payload_queue.put((payload, result_queue))

            # Wait for the result from the consumer.
            try:
                result = result_queue.get(timeout=10)
            except queue.Empty:
                return jsonify({"error": "Processing timed out"}), 504

            # Send back the processed result.
            return jsonify(result)

    def run_threaded(self) -> threading.Thread:
        """Runs the Flask server in a separate daemon thread."""
        server_thread = threading.Thread(target=self.app.run, kwargs={"host": self.host, "port": self.port}, daemon=True)
        server_thread.start()
        return server_thread
    
class NITTER:
    # license gpv4, author: zedeus
    TW_CONSUMER_KEY = '3nVuSoBZnx6U4vzUxf5w'
    TW_CONSUMER_SECRET = 'Bcs59EFbbsdF6Sl9Ng71smgStWEGwXXKSjYvPVt7qys'
    session_entry = {}

    def __init__(self, username, password, otp_secret):
        result = self.auth(username, password, otp_secret)
        if result is None:
            print("Authentication failed.")
            sys.exit(1)

        self.session_entry = {
            "oauth_token": result.get("oauth_token"),
            "oauth_token_secret": result.get("oauth_token_secret")
        }

        path = os.path.join(os.getcwd(), 'grok-session')
        try:
            with open(path, "a") as f:
                f.write(json.dumps(self.session_entry) + "\n")
            print("Authentication successful. Session appended to", path)
        except Exception as e:
            print(f"Failed to write session information: {e}")
            sys.exit(1)

    def auth(self, username, password, otp_secret):
        bearer_token_req = requests.post("https://api.twitter.com/oauth2/token",
            auth=(self.TW_CONSUMER_KEY, self.TW_CONSUMER_SECRET),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data='grant_type=client_credentials'
        ).json()
        bearer_token = ' '.join(str(x) for x in bearer_token_req.values())

        guest_token = requests.post(
            "https://api.twitter.com/1.1/guest/activate.json",
            headers={'Authorization': bearer_token}
        ).json().get('guest_token')

        if not guest_token:
            print("Failed to obtain guest token.")
            sys.exit(1)

        twitter_header = {
            'Authorization': bearer_token,
            "Content-Type": "application/json",
            "User-Agent": "TwitterAndroid/10.21.0-release.0 (310210000-r-0) ONEPLUS+A3010/9 (OnePlus;ONEPLUS+A3010;OnePlus;OnePlus3;0;;1;2016)",
            "X-Twitter-API-Version": '5',
            "X-Twitter-Client": "TwitterAndroid",
            "X-Twitter-Client-Version": "10.21.0-release.0",
            "OS-Version": "28",
            "System-User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ONEPLUS A3010 Build/PKQ1.181203.001)",
            "X-Twitter-Active-User": "yes",
            "X-Guest-Token": guest_token,
            "X-Twitter-Client-DeviceID": ""
        }

        self.session = requests.Session()
        self.session.headers = twitter_header

        task1 = self.session.post(
            'https://api.twitter.com/1.1/onboarding/task.json',
            params={
                'flow_name': 'login',
                'api_version': '1',
                'known_device_token': '',
                'sim_country_code': 'us'
            },
            json={
                "flow_token": None,
                "input_flow_data": {
                    "country_code": None,
                    "flow_context": {
                        "referrer_context": {
                            "referral_details": "utm_source=google-play&utm_medium=organic",
                            "referrer_url": ""
                        },
                        "start_location": {
                            "location": "deeplink"
                        }
                    },
                    "requested_variant": None,
                    "target_user_id": 0
                }
            }
        )

        self.session.headers['att'] = task1.headers.get('att')

        task2 = self.session.post(
            'https://api.twitter.com/1.1/onboarding/task.json',
            json={
                "flow_token": task1.json().get('flow_token'),
                "subtask_inputs": [{
                    "enter_text": {
                        "suggestion_id": None,
                        "text": username,
                        "link": "next_link"
                    },
                    "subtask_id": "LoginEnterUserIdentifier"
                }]
            }
        )

        task3 = self.session.post(
            'https://api.twitter.com/1.1/onboarding/task.json',
            json={
                "flow_token": task2.json().get('flow_token'),
                "subtask_inputs": [{
                    "enter_password": {
                        "password": password,
                        "link": "next_link"
                    },
                    "subtask_id": "LoginEnterPassword"
                }],
            }
        )

        for t3_subtask in task3.json().get('subtasks', []):
            if "open_account" in t3_subtask:
                return t3_subtask["open_account"]
            elif "enter_text" in t3_subtask:
                response_text = t3_subtask["enter_text"]["hint_text"]
                totp = pyotp.TOTP(otp_secret)
                generated_code = totp.now()
                task4resp = session.post(
                    "https://api.twitter.com/1.1/onboarding/task.json",
                    json={
                        "flow_token": task3.json().get("flow_token"),
                        "subtask_inputs": [
                            {
                                "enter_text": {
                                    "suggestion_id": None,
                                    "text": generated_code,
                                    "link": "next_link",
                                },
                                "subtask_id": "LoginTwoFactorAuthChallenge",
                            }
                        ],
                    }
                )
                task4 = task4resp.json()
                for t4_subtask in task4.get("subtasks", []):
                    if "open_account" in t4_subtask:
                        return t4_subtask["open_account"]

        return None

if __name__ == "__main__":
    print("Starting main program...")
    print("Please input your password used to store/retrieve your creds")
    crypto_session = my_crypto.SESSION("x.com")
    main = API()
    main.email = crypto_session.decrypt_str(my_secrets.x_email)
    main.password = crypto_session.decrypt_str(my_secrets.x_password)
    main.otp = crypto_session.decrypt_str(my_secrets.x_otp)
    if main.login():
        main_thread = threading.Thread(target=main.runServer, daemon=True)
        main_thread.start()
        print("Grok Processer is now running in parallel...")

    try:
        while True:
            key_input = input("If you wish to quit, please press q")
            if key_input[0] == "q":
                print("Thank you! Server shutting down")
                break
    except KeyboardInterrupt:
        print("Shutting down...")
