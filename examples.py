from flask import Flask, jsonify, request
import logging
import os
import traceback


app = Flask(__name__)


def custom_payload_parser_plain_text():
    try:
        incoming_payload = request.data.decode('utf-8')
        return f"This was the original request payload: {incoming_payload}"
    except Exception as e:
        return f"Failed to read request payload as plain text: {e} | {traceback.format_exc()}"


# Init logging
if os.getenv('GAE_ENV', '').startswith('standard'):
    import google.cloud.logging
    from google.cloud.logging_v2.handlers import setup_logging
    from flask_gae_logging import (
        FlaskGAEMaxLogLevelPropagateHandler,
        PayloadParser,
        GaeLogSizeLimitFilter,
        GaeUrlib3FullPoolFilter
    )

    client = google.cloud.logging.Client()
    # Optional - override/provide custom request payload parsers for certain content types
    gae_log_handler = FlaskGAEMaxLogLevelPropagateHandler(
        app=app,
        client=client,
        log_headers=True,
        log_payload=True,
        builtin_payload_parsers=[PayloadParser.Defaults.JSON],
        custom_payload_parsers={
            "text/plain": custom_payload_parser_plain_text
        }
    )
    setup_logging(handler=gae_log_handler)
    # Optional - add extra filters for the logger
    gae_log_handler.addFilter(GaeLogSizeLimitFilter())
    gae_log_handler.addFilter(GaeUrlib3FullPoolFilter())

logging.getLogger().setLevel(logging.DEBUG)


@app.route('/info', methods=['GET'])
def info():
    logging.debug("this is a debug")
    logging.info("this is an info")
    return jsonify({"message": "info"})


@app.route('/warning', methods=['GET'])
def warning():
    logging.debug("this is a debug")
    logging.info("this is an info")
    logging.warning("this is a warning")
    return jsonify({"message": "warning"})


@app.route('/error', methods=['GET'])
def error():
    logging.debug("this is a debug")
    logging.info("this is an info")
    logging.warning("this is a warning")
    logging.error("this is an error")
    return jsonify({"message": "error"})


@app.route('/exception', methods=['GET'])
def exception():
    logging.debug("this is a debug")
    logging.info("this is an info")
    logging.error("this is an error")
    raise ValueError("This is a value error")


@app.route('/http_exception', methods=['GET'])
def http_exception():
    logging.debug("this is a debug")
    logging.info("this is an info")
    return jsonify({"error": "Resource not found"}), 404


@app.route('/post_payload', methods=['POST'])
def post_payload():
    payload = request.json
    logging.debug("this is a debug")
    logging.info(payload)
    return jsonify({"mirror_response": payload}), 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)
