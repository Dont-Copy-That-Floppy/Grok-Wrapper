#!/usr/bin/python3

import requests
import json
import sys
import time
from flask import Flask, request, jsonify
import threading
import queue
try:
    from lib import my_secrets, my_crypto
except:
    from lib import my_crypto
    print("Setting up new creds...")
    print("Please input a password to store/retrieve your creds")
    crypto_session = my_crypto.SESSION("x.com")
    email = crypto_session.encrypt_str(input("Please input your login email\n"))
    password = crypto_session.encrypt_str(input("Please input your login password\n"))
    with open("lib/my_secrets.py", "w") as file:
        file.writelines(f"x_email = {email}\nx_password = {password}")
    from lib import my_secrets
    print("Creds setup finished\n")


class API:
    onboarding_payload = {
        "input_flow_data": {"flow_context": {"debug_overrides": {}, "start_location": {"location": "splash_screen"}}},
        "subtask_versions": {
            "action_list": 2,
            "alert_dialog": 1,
            "app_download_cta": 1,
            "check_logged_in_account": 1,
            "choice_selection": 3,
            "contacts_live_sync_permission_prompt": 0,
            "cta": 7,
            "email_verification": 2,
            "end_flow": 1,
            "enter_date": 1,
            "enter_email": 2,
            "enter_password": 5,
            "enter_phone": 2,
            "enter_recaptcha": 1,
            "enter_text": 5,
            "enter_username": 2,
            "generic_urt": 3,
            "in_app_notification": 1,
            "interest_picker": 3,
            "js_instrumentation": 1,
            "menu_dialog": 1,
            "notifications_permission_prompt": 2,
            "open_account": 2,
            "open_home_timeline": 1,
            "open_link": 1,
            "phone_verification": 4,
            "privacy_options": 1,
            "security_key": 3,
            "select_avatar": 4,
            "select_banner": 2,
            "settings_list": 7,
            "show_code": 1,
            "sign_up": 2,
            "sign_up_review": 4,
            "tweet_selection_urt": 1,
            "update_users": 1,
            "upload_media": 1,
            "user_recommendations_list": 4,
            "user_recommendations_urt": 1,
            "wait_spinner": 3,
            "web_modal": 1,
        },
    }
    email = ""
    password = ""

    def __init__(self) -> None:
        try:
            cookies = {}
            self.session = requests.session()
            requests.utils.add_dict_to_cookiejar(self.session.cookies, cookies)
            self.session.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/112.0"})
        except Exception as e:
            print("Session creation aborted due to %s" % e)

    def get2FA(self) -> str:
        two2fa_code = ""
        while True:
            two2fa_code = input("Please input 2fa code\n")
            if len(two2fa_code) == 6 and str(two2fa_code).isnumeric():
                break
            else:
                print("Wrong input. 2FA is 6 digits")

        return str(two2fa_code)

    def onboarding(self, step: int, payload: json = None) -> json:
        url = "https://api.x.com/1.1/onboarding/task.json"
        if step == 0:
            response = self.session.post(f"{url}?flow_name=login", json=self.onboarding_payload)
        else:
            if step == 1:
                payload = {**self.onboarding_payload, **{"subtask_inputs": [{"subtask_id": "LoginJsInstrumentationSubtask", "js_instrumentation": {"link": "next_link"}}]}}
            elif step == 2:
                payload = {
                    **self.onboarding_payload,
                    **{"subtask_inputs": [{"subtask_id": "LoginEnterUserIdentifierSSO", "settings_list": {"setting_responses": [{"key": "user_identifier", "response_data": {"text_data": {"result": self.email}}}], "link": "next_link"}}]},
                }
            elif step == 3:
                payload = {**self.onboarding_payload, **{"subtask_inputs": [{"subtask_id": "LoginEnterPassword", "enter_password": {"password": self.password, "link": "next_link"}}]}}
            elif step == 4:
                payload = {**self.onboarding_payload, **{"subtask_inputs": [{"subtask_id": "LoginTwoFactorAuthChallenge", "enter_text": {"text": self.get2FA(), "link": "next_link"}}]}}
            response = self.session.post(f"{url}", json=payload)

        if response.status_code == 200:
            try:
                return json.loads(response.content)
            except Exception as e:
                print(f"{response.text}\nFailed to convert response to json.\n")
                sys.exit()
        else:
            print(f"{response.text}\nFailed to retrieve on payload\n{payload}")
            sys.exit()

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
        response = self.session.post("https://grok.x.com/2/grok/add_response.json")
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
        self.session.get("https://x.com")
        for step in range(0, 5):
            result = self.onboarding(step=step)
            self.onboarding_payload = {"flow_token": result["flow_token"]}

        if result:
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


if __name__ == "__main__":
    print("Starting main program...")
    print("Please input your password used to store/retrieve your creds")
    crypto_session = my_crypto.SESSION("x.com")
    main = API()
    main.email = crypto_session.decrypt_str(my_secrets.x_email)
    main.password = crypto_session.decrypt_str(my_secrets.x_password)
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
