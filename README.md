## Overview

The **Grok OpenAI Wrapper** project provides a standardized interface to interact with X.com's services and Grok AI endpoints. The system handles:

- **Authentication:** A secure login flow that integrates with X.com APIs.
- **Data Aggregation:** Parsing and converting responses from Grok AI endpoints into an OpenAI-compatible protocol.
- **Extensibility:** A modular design that allows easy integration with other products and services that utilize OpenAI's API structure.

This project is ideal for developers looking to harness the combined power of X.com's Grok AI technology while maintaining compatibility with existing OpenAI-based workflows. Specifically [cursorai](https://www.cursor.com/).

---

## Getting Started

### Prerequisites

- X.com Premium Account
- Python 3.8 or later
- Optional: Virtual environment tools (e.g., `venv` or `virtualenv`)
- [Flask](https://flask.palletsprojects.com/) for serving API endpoints
- [pycryptodome](https://www.pycryptodome.org/)
- [requests](https://requests.readthedocs.io/en/latest/)
- [pyotp](https://github.com/pyauth/pyotp)

### Installation

1. **Clone the repository:**

   ```
   git clone https://github.com/Dont-Copy-That-Floppy/Grok-Wrapper
   cd Grok-Wrapper
   ```

2. **Optional: Create and activate a virtual environment:**

   ```
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install dependencies:**

   ```
   pip install -r requirements.txt
   ```

4. **Run Middleware:**

   ```
   python grok.py
   ```

---

## Integration with OpenAI Protocol

**Example Structure:**

```json
{
  "responses": [
    {
      "message": "Your message text here",
      "sender": 1,
      "promptSource": "",
      "fileAttachments": []
    }
  ],
  "systemPromptName": "",
  "grokModelOptionId": "grok-3",
  "conversationId": "unique_conversation_id",
  "returnSearchResults": true,
  "returnCitations": true,
  "promptMetadata": {
    "promptSource": "NATURAL",
    "action": "INPUT"
  },
  "imageGenerationCount": 4,
  "requestFeatures": {
    "eagerTweets": true,
    "serverHistory": true
  },
  "enableCustomization": true,
  "enableSideBySide": true,
  "toolOverrides": {},
  "isDeepsearch": false,
  "isReasoning": false
}
```

The integration layer takes queries to the localhost at port 8080 that are openai requests, formats them to grok's protocol, then sends them to grok's endpoint. When the response is received, it parses back to openai comaptible response and send the packet back to source. Effectively a simple wrapper proxy server.

---

## Usage Examples

To use the service insert this as the base url in cursor,

```
http://localhost:8080/
```

No authentication requireed.

---

---

## License

This project is licensed under the [GPLv3 License](LICENSE).

---

## Contact

For further inquiries or support, please contact:

- **Contact/Donate:** [LINKs](https://linktr.ee/f0ll0w.th3.wh1t3.r4bb1t)

---