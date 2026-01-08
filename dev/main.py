import logging
import os

from flask import Flask, jsonify, request

app = Flask(__name__)

def custom_payload_parser_plain_text():
    """Custom parser for text/plain to demonstrate GAE handler extensibility."""
    try:
        incoming_payload = request.data.decode('utf-8', errors='replace')
        return f"Parsed Plain Text: {incoming_payload}"
    except Exception:
        logging.exception("Failed to parse plain text payload")
        return "Error: Could not decode plain text data."

# Initialize GAE Logging
if os.getenv('GAE_ENV', '').startswith('standard'):
    import google.cloud.logging
    from google.cloud.logging_v2.handlers import setup_logging

    from flask_gae_logging import (
        FlaskGAEMaxLogLevelPropagateHandler,
        GaeLogSizeLimitFilter,
        GaeUrlib3FullPoolFilter,
        PayloadParser,
    )

    client = google.cloud.logging.Client()
    gae_log_handler = FlaskGAEMaxLogLevelPropagateHandler(
        app=app,
        client=client,
        log_headers=True,
        log_payload=True,
        builtin_payload_parsers=[content_type for content_type in PayloadParser.Defaults],
        custom_payload_parsers={
            "text/plain": custom_payload_parser_plain_text
        }
    )
    setup_logging(handler=gae_log_handler)
    gae_log_handler.addFilter(GaeLogSizeLimitFilter())
    gae_log_handler.addFilter(GaeUrlib3FullPoolFilter())

logging.getLogger().setLevel(logging.DEBUG)

@app.route('/info', methods=['GET'])
def info():
    logging.debug("Step 1: Debugging diagnostic")
    logging.info("Step 2: General information log")
    return jsonify({"message": "info"})

@app.route('/warning', methods=['GET'])
def warning():
    logging.debug("Step 1: Check system state")
    logging.info("Step 2: State is normal")
    logging.warning("Step 3: Resource usage approaching threshold")
    return jsonify({"message": "warning"})

@app.route('/error', methods=['GET'])
def error():
    logging.debug("Step 1: Internal check")
    logging.info("Step 2: Transaction started")
    logging.warning("Step 3: Retry attempted")
    logging.error("Step 4: Transaction failed after retries")
    return jsonify({"message": "error"})

@app.route('/exception', methods=['GET'])
def exception():
    logging.debug("Step 1: Preparing logic")
    logging.info("Step 2: Executing risky operation")
    logging.error("Step 3: Critical failure detected")
    raise ValueError("Simulated ValueError for GAE grouping demonstration")

@app.route('/http_exception', methods=['GET'])
def http_exception():
    logging.debug("Step 1: Looking up resource")
    logging.info("Step 2: Resource ID not found in database")
    return jsonify({"error": "Resource not found"}), 404

@app.route('/post_payload', methods=['POST'])
def post_payload():
    """Handles multiple content types to mirror how they are parsed."""
    content_type = request.headers.get('Content-Type', '')
    logging.debug(f"Handling POST request with Content-Type: {content_type}")

    # 1. Handle JSON
    if request.is_json:
        payload = request.get_json(silent=True)
        logging.info(f"Parsed as JSON: {payload}")
    
    # 2. Handle Form URL-Encoded
    elif content_type == "application/x-www-form-urlencoded":
        # Flask populates request.form for this content type
        payload = request.form.to_dict()
        logging.info(f"Parsed as Form URL-Encoded: {payload}")
    
    # 3. Fallback for Plain Text or others
    else:
        payload = request.data.decode('utf-8', errors='replace')
        logging.info(f"Parsed as Raw/Text: {payload}")

    return jsonify({
        "mirror_response": payload,
        "detected_type": str(type(payload)),
        "content_type_received": content_type
    }), 200

@app.route("/post_form", methods=["POST"])
def post_form():
    try:
        description = request.form.get("description")
        file = request.files.get("file")

        if not description or not file:
            logging.warning("Incomplete form submission received")
            return jsonify({"error": "Missing required fields"}), 400

        file_content = file.read()
        payload = {
            "description": description,
            "file_name": file.filename,
            "content_type": file.content_type,
            "file_size": len(file_content),
        }
        logging.info(f"Form submission processed: {payload}")
        return jsonify({"mirror_response": payload}), 200
    except Exception:
        logging.exception("Fatal error during multipart form processing")
        return jsonify({"error": "Form processing failed"}), 500