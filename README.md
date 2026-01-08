# flask-gae-logging
Custom Cloud Logging handler for Flask applications deployed in Google App Engine to ease out logs analysis and monitoring through Google Cloud Log Explorer.

## What problem does this package solve? Why do we need this?
- **Log Severity Mismatch**: When deploying Flask applications on Google App Engine with Python3 runtime and using `google-cloud-logging` the logs of each request lifecycle can be viewed into a group of the request lifecycle.
The groupped logs functionality is natively supported in `google-cloud-logging` and one can view logs by request lifecycle using the `request_log` logger in the Cloud Log Explorer.
However, the severity level of logs is not properly propagated throughout the request lifecycle to the parent log in groupped logs. This means that if a warning or error occurs at any point in the request, the parent log will not reflect the severity on the final outcome, making it harder to identify problematic requests.

- **Payload Logging Issues**: Capturing and logging request payloads was cumbersome, requiring extra logging in the handlers and extra deployments. This led to incomplete logs, making it harder to reproduce issues or analyze request content.

- **Inconsistent Log Structures**: The default logging setup lacked a consistent structure, which made it challenging to filter, search, and analyze logs in the Google Cloud Log Explorer.

## So what does it do? 
The `flask-gae-logging` module addresses these problems by:

- **Log Level Propagation**: The maximum log level observed during a request's lifecycle is propagated, ensuring that logs associated with a failed request reflect the appropriate severity. This improves the accuracy and utility of log searches based on severity.

- **Structured Payload Logging**: Request payloads are captured and logged in a structured format, even for non-dictionary JSON payloads. This ensures that all relevant request data is available for analysis, improving the ability to diagnose issues.

## Install
`pip install flask-gae-logging`

## Features:

- **Request Maximum Log Level Propagation**: Propagates the maximum log level throughout the request lifecycle, making it easier to search logs based on the severity of an issue.
- **Optional incoming request logging**: Opt in/out to log headers and payload of incoming requests into the `jsonPayload` field of the parent log.
- **Optional request headers logging**: Defaults to True. Headers dict lands into field `request_headers` in the `jsonPayload` of parent log.
- **Request Payload Logging**: Defaults to True. Incoming payload parsed lands into field `request_payload` in the `jsonPayload` of parent log. Parsing is based on content type with capability to override. Currenty embedded parsers for:
    - `application/json`
    - `application/x-www-form-urlencoded`
    - `multipart/form-data`
    - `text/plain`
- **Optional add-on log filters**: 
    - `GaeLogSizeLimitFilter` filter to drop log records if they exceed the maximum allowed size by google cloud logging.
    - `GaeUrlib3FullPoolFilter` filter to drop noisy 'Connection pool is full' warning logs
    from Google Cloud and App Engine internal libraries.

## API

- Initialization

```python
FlaskGAEMaxLogLevelPropagateHandler(
    app: Flask,
    request_logger_name: Optional[str] = None,
    log_payload: bool = False,
    log_headers: bool = False,
    builtin_payload_parsers: Optional[List["PayloadParser.Defaults"]] = None,
    custom_payload_parsers:  Optional[Dict[str, Callable[[], object]]] = None,
    *args, **kwargs
)
```

- Parameters
    - **app** (Flask): The Flask application instance.
    - **request_logger_name** (Optional[str], optional): The name of the Cloud Logging logger to use for request logs.
                                                    Defaults to the Google Cloud Project ID with the suffix '-request-logger'.

    - **log_payload** (bool, optional): Whether to log the request payload. If True, the payload for POST, PUT, PATCH, and DELETE requests will be logged. Defaults to False.

    - **log_headers** (bool, optional): Whether to log the request headers. Defaults to False.

    - **builtin_payload_parsers**  (List["PayloadParser.Defaults"], optional): A list of  built-in parser functions for logging request payloads. Defaults to None.
    - **custom_payload_parsers**  (Dict[str, Callable], optional): A dictionary mapping content types to custom parser functions for logging request payloads. If provided, these will override default parsers. Defaults to None.

    - ***args**: Additional arguments to pass to the superclass constructor. Any argument you would pass to CloudLoggingHandler.

    - ****kwargs**: Additional keyword arguments to pass to the superclass constructor. Any keyword argument you would pass to  CloudLoggingHandler.


## Example of usage

```python
import logging
import os

from flask import Flask, jsonify, request

app = Flask(__name__)


def custom_payload_parser_plain_text():
    # Custom parser for text/plain to demonstrate GAE handler extensibility.
    # Needs to return a serializable value to be logged
    incoming_payload = request.data.decode('utf-8', errors='replace')
    return f"Parsed Plain Text: {incoming_payload}"


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
        # Optional - opt in for logging payload and logs; defaults are False
        log_headers=True,
        log_payload=True,
        # Optional - opt in for all built in payload parsers; applicable only if log_payload is set True
        builtin_payload_parsers=[content_type for content_type in PayloadParser.Defaults],
        # Optional - override built in payload parsers or provide more; applicable only if log_payload is set True
        custom_payload_parsers={
            "text/plain": custom_payload_parser_plain_text
        }
    )
    setup_logging(handler=gae_log_handler)
    # Optional - add extra filters for the logger
    gae_log_handler.addFilter(GaeLogSizeLimitFilter())
    gae_log_handler.addFilter(GaeUrlib3FullPoolFilter())

logging.getLogger().setLevel(logging.DEBUG)


@app.errorhandler(Exception)
def handle_exception(e):
    logging.exception("Uncaught exception occurred")
    return jsonify({"error": str(e)}), 500


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
```

## How it looks in Google Cloud Log Explorer

### Logger selection
![Logger selection in google cloud log explorer](https://github.com/trebbble/flask-gae-logging/blob/main/images/logger_selection.jpg?raw=true)

### Groupped logs with propagated log severity to the parent log

![Grouped logs with propagated log severity to parent log](https://github.com/trebbble/flask-gae-logging/blob/main/images/groupped_logs.jpg?raw=true)

### Grouped logs in request with payload
![Grouped logs with payload](https://github.com/trebbble/flask-gae-logging/blob/main/images/request_with_payload.jpg?raw=true)

## Dependencies
This tool is built upon the following packages:

- `flask`: A lightweight WSGI web application framework. 
- `google-cloud-logging`: Google Cloud Logging API client library for logging and managing logs in Google Cloud Platform.


### Dev
- `uv sync --all-packages`
- Use `sample_app` folder for minimal Appengine app deployment of flask app that uses the local library `src` code via symlink.
    - If symlink is broken for any reason, create it again from inside the `sample_app` folder: `ln -s ../src/flask_gae_logging/ .`
    - Deploy the app: `gcloud app deploy  --version=v1 default.yaml --project=<PROJECT_ID> --account <ACCOUNT_EMAIL>`
    - Ping the sample app to generate logs for various cases in log explorer: `python3.12 ping_endpoints.py --project <PROJECT_ID>`