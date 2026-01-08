import logging
import os
import sys
import time
import traceback
from datetime import datetime
from enum import Enum
from typing import Callable, Dict, List, Optional

from flask import Flask, Response, g, has_app_context, request
from google.cloud.logging_v2.handlers import CloudLoggingHandler
from werkzeug.datastructures import FileStorage

GCLOUD_LOG_MAX_BYTE_SIZE = 1024 * 246


def bytes_repr(num, suffix='B'):
    for unit in ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"


def get_real_size(obj, seen=None):
    """
    Recursively finds the total memory footprint (deep size) of an object 
    and its members in bytes.
    """
    size = sys.getsizeof(obj)
    if seen is None:
        seen = set()
    obj_id = id(obj)
    if obj_id in seen:
        return 0

    seen.add(obj_id)
    if isinstance(obj, dict):
        size += sum([get_real_size(v, seen) for v in obj.values()])
        size += sum([get_real_size(k, seen) for k in obj.keys()])
    elif hasattr(obj, '__dict__'):
        size += get_real_size(obj.__dict__, seen)
    elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes, bytearray)):
        size += sum([get_real_size(i, seen) for i in obj])
    return size


class GaeLogSizeLimitFilter(logging.Filter):
    """
    Logging filter to manage the log message size based on the
    maximum log message size allowed by google cloud logging.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filter log records based on the maximum log message size allowed by google cloud logging.

        Args:
            record (logging.LogRecord): The log record to filter.

        Returns:
            bool: True to allow the log record, False to suppress it.
        """
        record_size = get_real_size(record.msg)
        if record_size > GCLOUD_LOG_MAX_BYTE_SIZE:
            logging.warning(f"Log entry with size {bytes_repr(record_size)} exceeds maximum size "
                            f"of {bytes_repr(GCLOUD_LOG_MAX_BYTE_SIZE)}."
                            f"Dropping logging record originated from: {record.filename}:{record.lineno}. "
                            f"Using print instead, check stdout/stderr for print with timestamp: "
                            f"{datetime.fromtimestamp(record.created).isoformat()}")

            print(
                f"{datetime.fromtimestamp(record.created).isoformat()} [{record.levelname}] | {record.name} | "
                f"{record.pathname}:{record.lineno} | {record.funcName} - {record.getMessage()}\n"
                + (
                    f"\nException:\n{''.join(traceback.format_exception(*record.exc_info))}" if record.exc_info else "")
            )

            return False

        return True


class GaeUrlib3FullPoolFilter(logging.Filter):
    """
    Logging filter to suppress noisy 'Connection pool is full' warning logs
    from Google Cloud and App Engine internal libraries.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filter noisy 'Connection pool is full' warning logs
        from Google Cloud and App Engine internal libraries.

        Args:
            record (logging.LogRecord): The log record to filter.

        Returns:
            bool: True to allow the log record, False to suppress it.
        """
        if "Connection pool is full, discarding connection: appengine.googleapis.internal" in record.getMessage():
            return False

        if "Connection pool is full, discarding connection: storage.googleapis.com" in record.getMessage():
            return False

        return True


class FlaskRequestLifecycleLog:
    """
    Utility class for managing the maximum log level in the Flask request lifecycle.
    """
    REQUEST_MAX_LOG_LEVEL = "request_max_log_level"

    @classmethod
    def get_max_log_level(cls) -> int:
        """
        Get the current maximum log level set in the request lifecycle.

        Returns:
            int: The maximum log level.
        """
        return g.get(cls.REQUEST_MAX_LOG_LEVEL, logging.NOTSET)

    @classmethod
    def set_max_log_level(cls, value: int) -> None:
        """
        Set the maximum log level in the request lifecycle.

        Args:
            value (int): The maximum log level to set.
        """
        setattr(g, cls.REQUEST_MAX_LOG_LEVEL, int(value))


class FlaskLogFilter(logging.Filter):
    """
    Logging filter to manage the maximum log level in the Flask request lifecycle.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filter log records based on the maximum log level set in the request lifecycle.

        Args:
            record (logging.LogRecord): The log record to filter.

        Returns:
            bool: True to allow the log record, False to suppress it.
        """
        if has_app_context():
            if record.levelno > FlaskRequestLifecycleLog.get_max_log_level():
                FlaskRequestLifecycleLog.set_max_log_level(record.levelno)

        return True


class PayloadParser:

    class Defaults(Enum):
        JSON = "application/json"
        FORM_URLENCODED = "application/x-www-form-urlencoded"
        MULTIPART_FORM = "multipart/form-data"
        PLAIN_TEXT = "text/plain"

    _BUILTIN_PARSERS: Dict[str, Callable[[], object]] = {
            Defaults.JSON.value: lambda: PayloadParser._safe_call(PayloadParser._parse_json),
            Defaults.FORM_URLENCODED.value: lambda: PayloadParser._safe_call(PayloadParser._parse_form_urlencoded),
            Defaults.MULTIPART_FORM.value: lambda: PayloadParser._safe_call(PayloadParser._parse_multipart_form),
            Defaults.PLAIN_TEXT.value: lambda: PayloadParser._safe_call(PayloadParser._parse_plain_text),
    }

    def __init__(
            self,
            builtin_parsers: Optional[List["PayloadParser.Defaults"]] = None,
            custom_parsers: Optional[Dict[str, Callable[[], object]]] = None
    ):
        self.parsers: Dict[str, Callable[[], object]] = {}

        if builtin_parsers:
            for default in builtin_parsers:
                if default.value in self._BUILTIN_PARSERS:
                    self.parsers[default.value] = self._BUILTIN_PARSERS[default.value]

        if custom_parsers:
            self.parsers.update(custom_parsers)

    @staticmethod
    def _parse_json():
        return request.get_json()

    @staticmethod
    def _parse_form_urlencoded():
        return request.form.to_dict()

    @staticmethod
    def _parse_multipart_form():
        form_data = request.form.to_dict()
        file_data = [
            {
                'form_field': value.name,
                'filename': value.filename,
                'mimetype': value.mimetype
            }
            for _, value in request.files.items() if isinstance(value, FileStorage)
        ]
        return {
            'form_data': form_data,
            'file_data': file_data
        }

    @staticmethod
    def _parse_plain_text():
        return request.data.decode('utf-8')

    def get_parser(self, content_type: str) -> Optional[Callable]:
        """
        Returns the parser function for the given content type.
        """
        return self.parsers.get(content_type)

    @staticmethod
    def _safe_call(parser_fn: Callable):
        try:
            return parser_fn()
        except Exception as e:
            return f"Parser error: {e} | {traceback.format_exc()}"


class FlaskGAEMaxLogLevelPropagateHandler(CloudLoggingHandler):
    """
    Custom Cloud Logging handler for Flask applications deployed in Google AppEngine
    to propagate the maximum log level throughout the request lifecycle and log structured data.

    Example::

        import logging
        import os
        from flask import Flask

        app = Flask(__name__)

        # Init logging
        if os.getenv('GAE_ENV', '').startswith('standard'):
            import google.cloud.logging
            from google.cloud.logging_v2.handlers import setup_logging
            from flask_gae_logging import FlaskGAEMaxLogLevelPropagateHandler

            client = google.cloud.logging.Client()
            gae_log_handler = FlaskGAEMaxLogLevelPropagateHandler(app=app, client=client)
            setup_logging(handler=gae_log_handler)

        logging.getLogger().setLevel(logging.DEBUG)
    """
    REQUEST_LOGGER_SUFFIX: str = '-request-logger'
    LOG_LVL_TO_SEVERITY: dict = {
        logging.NOTSET: 'DEFAULT',
        logging.DEBUG: 'DEBUG',
        logging.INFO: 'INFO',
        logging.WARNING: 'WARNING',
        logging.ERROR: 'ERROR',
        logging.CRITICAL: 'CRITICAL',
    }

    def __init__(
            self,
            app: Flask,
            request_logger_name: Optional[str] = None,
            log_payload: bool = False,
            log_headers: bool = False,
            builtin_payload_parsers: Optional[List["PayloadParser.Defaults"]] = None,
            custom_payload_parsers:  Optional[Dict[str, Callable[[], object]]] = None,
            *args, **kwargs
    ) -> None:
        """
        Initialize the handler.

        Args:
            app: The Flask application instance.
            request_logger_name (str): The name of the Cloud Logging logger to use for request logs.
                Defaults to the Google Cloud Project ID with '-request-logger' suffix.
            log_payload (bool): Whether to log the request payload (if any) or not.
                Defaults to False.
            log_headers (bool): Whether to log the request headers.
                Defaults to False.
            builtin_payload_parsers (List["PayloadParser.Defaults"], optional): A list of  built-in
                parser functions for logging request payloads.
                Defaults to None.
            custom_payload_parsers (Dict[str, Callable], optional): A dictionary mapping content types to custom
                parser functions for logging request payloads. If provided, these will override default parsers.
                Defaults to None.
            *args: Additional arguments to pass to the superclass constructor.
            **kwargs: Additional keyword arguments to pass to the superclass constructor.
        """
        super().__init__(*args, **kwargs)
        self._request_logger = self.client.logger(
            name=request_logger_name or f"{os.getenv('GOOGLE_CLOUD_PROJECT')}{self.REQUEST_LOGGER_SUFFIX}",
            resource=self.resource
        )
        self.log_payload = log_payload
        self.log_headers = log_headers
        self.payload_parsers = PayloadParser(
            builtin_parsers=builtin_payload_parsers,
            custom_parsers=custom_payload_parsers
        )
        self._flask_filter = FlaskLogFilter()
        self.addFilter(self._flask_filter)
        self._wrap_flask_app(app)

    def filter(self, record):
        """
        Custom filter logic that ensures user-added filters are respected
        before applying the internal FlaskLogFilter for severity propagation.

        Only propagates severity for logs that pass user-added filters.
        """

        for f in self.filters:

            if f is self._flask_filter:
                continue

            if hasattr(f, 'filter'):
                result = f.filter(record)
            else:
                result = f(record)

            if not result:
                return False

            if isinstance(result, logging.LogRecord):
                record = result

        result = self._flask_filter.filter(record)
        if not result:
            return False
        if isinstance(result, logging.LogRecord):
            return result

        return record

    def _log_level_to_severity(self, log_level: int) -> str:
        """
        Map Python logging levels (DEBUG, INFO, etc.) to their corresponding Google Cloud Logging severity levels.

        Args:
            log_level (int): The logging level.

        Returns:
            str: The corresponding Cloud Logging severity.
        """
        return self.LOG_LVL_TO_SEVERITY.get(log_level, self.LOG_LVL_TO_SEVERITY[logging.NOTSET])

    @staticmethod
    def _setup_timing() -> None:
        """
        Set up start time for request.
        This function is added as a before_request function in wrapped
        Flask app.
        """
        g.request_start_time = time.time()

    @staticmethod
    def _get_trace_id() -> str:
        """
        Extract the trace ID from the 'X-Cloud-Trace-Context' header in Google Cloud Platform (GCP) requests.

        Returns:
            str: The trace ID.
        """
        return (f"projects/{os.environ['GOOGLE_CLOUD_PROJECT']}/traces/"
                f"{request.headers['X-Cloud-Trace-Context'].split('/')[0]}")

    @staticmethod
    def _truncate_log_on_cap(log_payload, trace_id):
        logging_payload_size = get_real_size(log_payload)
        if logging_payload_size > GCLOUD_LOG_MAX_BYTE_SIZE:
            print(f"Request payload that was skipped in parent log with trace_id {trace_id}: {log_payload}")
            log_payload = (f"Request logging payload with size {bytes_repr(logging_payload_size)} "
                           f"exceeds maximum size of {bytes_repr(GCLOUD_LOG_MAX_BYTE_SIZE)}, "
                           f"truncating request body payload from log and using print instead."
                           f"Check stdout/stderr for print with trace_id {trace_id}.")

        return log_payload

    def _emit_parent(self, response: Response) -> Response:
        """
        Log structured data after handling request and right before
        returning a response.
        Severity of log is determined based on the maximum log level
        captured in Flask request g object.
        This function is added as an after_request in wrapped
        Flask app.

        Args:
            response: The response object.

        Returns:
            Response: The response object.
        """
        trace_id = self._get_trace_id()
        request_max_log_level = FlaskRequestLifecycleLog.get_max_log_level()
        severity = self._log_level_to_severity(request_max_log_level)

        http_request = {
            'requestMethod': request.method,
            'requestUrl': request.url,
            'status': response.status_code,
            'userAgent': request.headers.get('USER-AGENT'),
            'responseSize': response.content_length,
            'latency': f'{(time.time() - g.request_start_time):.6f}s',
            'remoteIp': request.remote_addr
        }

        logging_payload = {}

        if self.log_headers:
            logging_payload['request_headers'] = dict(request.headers)

        if self.log_payload and request.method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
            content_type = request.headers.get("content-type", "").split(";")[0].strip()
            payload_parser = self.payload_parsers.get_parser(content_type)

            if not payload_parser:
                request_payload = f"Unsupported content type {content_type}. Skipping payload logging."
            else:
                try:
                    request_payload = payload_parser()
                except Exception as e:
                    request_payload = (
                        f"Parser of request payload for content type "
                        f"{content_type} failed: {e} | {traceback.format_exc()}"
                    )

            if request_payload:
                logging_payload['request_payload'] = self._truncate_log_on_cap(request_payload, trace_id)

        self._request_logger.log_struct(
            info=logging_payload,
            resource=self.resource,
            trace=trace_id,
            http_request=http_request,
            severity=severity
        )
        return response

    def _wrap_flask_app(self, app: Flask) -> None:
        """
        Wrap Flask application to add start time of request
        and emit a parent structured log before returning a response.

        Args:
            app: The Flask application instance.
        """
        with app.app_context():
            app.before_request(self._setup_timing)
            app.after_request(self._emit_parent)
