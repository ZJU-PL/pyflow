from __future__ import annotations

import pytest

from pyflow.analysis.ifds.modeling.calls import STATE_CLOSE, STATE_OPEN, STATE_USE
from pyflow.analysis.ifds.modeling.presets import (
    TAINT_PRESETS,
    TAINT_SINK_PRESETS,
    TAINT_SANITIZER_PRESETS,
    NULLNESS_PRESETS,
    TYPESTATE_OPEN_PRESETS,
    TYPESTATE_CLOSE_PRESETS,
    TYPESTATE_USE_PRESETS,
    merge_presets,
)


def test_taint_presets_include_input_source():
    assert TAINT_PRESETS.model_for_name("input").taint_source is True


def test_taint_presets_include_http_source():
    assert TAINT_PRESETS.model_for_name("requests.get").taint_source is True
    assert TAINT_PRESETS.model_for_name("requests.post").taint_source is True


def test_taint_presets_include_env_source():
    assert TAINT_PRESETS.model_for_name("os.environ.get").taint_source is True
    assert TAINT_PRESETS.model_for_name("os.getenv").taint_source is True


def test_taint_sink_presets_include_os_system():
    assert TAINT_SINK_PRESETS.model_for_name("os.system").taint_sink is True


def test_taint_sink_presets_include_subprocess():
    assert TAINT_SINK_PRESETS.model_for_name("subprocess.run").taint_sink is True


def test_taint_sink_presets_include_eval():
    assert TAINT_SINK_PRESETS.model_for_name("eval").taint_sink is True
    assert TAINT_SINK_PRESETS.model_for_name("exec").taint_sink is True


def test_taint_sink_presets_include_sql():
    assert TAINT_SINK_PRESETS.model_for_name("sqlite3.Cursor.execute").taint_sink is True


def test_taint_sanitizer_presets_include_string_methods():
    assert TAINT_SANITIZER_PRESETS.model_for_name("str.strip").taint_sanitizer is True
    assert TAINT_SANITIZER_PRESETS.model_for_name("str.replace").taint_sanitizer is True


def test_taint_sanitizer_presets_include_html_escape():
    assert TAINT_SANITIZER_PRESETS.model_for_name("html.escape").taint_sanitizer is True


def test_taint_sanitizer_presets_include_type_conversion():
    assert TAINT_SANITIZER_PRESETS.model_for_name("int").taint_sanitizer is True
    assert TAINT_SANITIZER_PRESETS.model_for_name("float").taint_sanitizer is True


def test_taint_sanitizer_presets_include_crypto():
    assert TAINT_SANITIZER_PRESETS.model_for_name("hashlib.sha256").taint_sanitizer is True


def test_nullness_presets_regex():
    assert NULLNESS_PRESETS.model_for_name("re.match").nullness_nullable_return is True
    assert NULLNESS_PRESETS.model_for_name("re.search").nullness_nullable_return is True


def test_nullness_presets_dict_methods():
    assert NULLNESS_PRESETS.model_for_name("get").nullness_nullable_return is True


def test_nullness_presets_getattr():
    assert NULLNESS_PRESETS.model_for_name("getattr").nullness_nullable_return is True


def test_typestate_open_presets_file():
    model = TYPESTATE_OPEN_PRESETS.model_for_name("open")
    assert model is not None
    assert STATE_OPEN in model.typestate_actions
    assert model.track_method_receiver is True


def test_typestate_close_presets():
    model = TYPESTATE_CLOSE_PRESETS.model_for_name("close")
    assert model is not None
    assert STATE_CLOSE in model.typestate_actions


def test_typestate_use_presets_file():
    assert STATE_USE in TYPESTATE_USE_PRESETS.model_for_name("read").typestate_actions
    assert STATE_USE in TYPESTATE_USE_PRESETS.model_for_name("write").typestate_actions


def test_typestate_use_presets_socket():
    assert STATE_USE in TYPESTATE_USE_PRESETS.model_for_name("send").typestate_actions
    assert STATE_USE in TYPESTATE_USE_PRESETS.model_for_name("recv").typestate_actions


def test_typestate_lock_patterns():
    assert TYPESTATE_OPEN_PRESETS.model_for_name("threading.Lock").resource_arg_positions == frozenset()
    assert TYPESTATE_USE_PRESETS.model_for_name("acquire").resource_arg_positions == frozenset()


def test_presets_do_not_unexpectedly_sink_or_source():
    assert TAINT_SINK_PRESETS.model_for_name("print").taint_source is False
    assert TAINT_PRESETS.model_for_name("input").taint_sink is False


def test_merge_presets_combines_sources():
    from pyflow.analysis.ifds.modeling.presets import (
        IO_SOURCES,
        OS_ENV_SOURCES,
    )
    merged = merge_presets(IO_SOURCES, OS_ENV_SOURCES)
    assert merged.model_for_name("input").taint_source is True
    assert merged.model_for_name("os.getenv").taint_source is True
    assert merged.model_for_name("unknown") is None


def test_merge_presets_empty():
    result = merge_presets()
    assert result.model_for_name("anything") is None


def test_merge_presets_single():
    from pyflow.analysis.ifds.modeling.presets import IO_SOURCES
    result = merge_presets(IO_SOURCES)
    assert result.model_for_name("input").taint_source is True


def test_xml_sources():
    from pyflow.analysis.ifds.modeling.presets import XML_SOURCES
    assert XML_SOURCES.model_for_name("xml.etree.ElementTree.parse").taint_source is True
    assert XML_SOURCES.model_for_name("lxml.etree.parse").taint_source is True
    assert XML_SOURCES.model_for_name("defusedxml.ElementTree.parse").taint_source is True


def test_xml_sinks():
    from pyflow.analysis.ifds.modeling.presets import XML_SINKS
    assert XML_SINKS.model_for_name("lxml.etree.tostring").taint_sink is True
    assert XML_SINKS.model_for_name("lxml.html.fromstring").taint_sink is True


def test_xpath_sinks():
    from pyflow.analysis.ifds.modeling.presets import XPATH_SINKS
    assert XPATH_SINKS.model_for_name("lxml.etree._Element.xpath").taint_sink is True
    assert XPATH_SINKS.model_for_name("xml.etree.ElementTree.Element.find").taint_sink is True


def test_ldap_sinks():
    from pyflow.analysis.ifds.modeling.presets import LDAP_SINKS
    assert LDAP_SINKS.model_for_name("ldap.ldapobject.SimpleLDAPObject.search").taint_sink is True
    assert LDAP_SINKS.model_for_name("ldap3.Connection.search").taint_sink is True


def test_nosql_sinks():
    from pyflow.analysis.ifds.modeling.presets import NOSQL_SINKS
    assert NOSQL_SINKS.model_for_name("pymongo.collection.Collection.find").taint_sink is True
    assert NOSQL_SINKS.model_for_name("redis.Redis.execute_command").taint_sink is True
    assert NOSQL_SINKS.model_for_name("elasticsearch.Elasticsearch.search").taint_sink is True
    assert NOSQL_SINKS.model_for_name("cassandra.cluster.Session.execute").taint_sink is True


def test_path_traversal_sinks():
    from pyflow.analysis.ifds.modeling.presets import PATH_TRAVERSAL_SINKS
    assert PATH_TRAVERSAL_SINKS.model_for_name("tarfile.TarFile.extractall").taint_sink is True
    assert PATH_TRAVERSAL_SINKS.model_for_name("zipfile.ZipFile.extractall").taint_sink is True
    assert PATH_TRAVERSAL_SINKS.model_for_name("shutil.unpack_archive").taint_sink is True


def test_ssrf_sinks():
    from pyflow.analysis.ifds.modeling.presets import SSRF_SINKS
    assert SSRF_SINKS.model_for_name("urllib.request.urlopen").taint_sink is True
    assert SSRF_SINKS.model_for_name("httpx.AsyncClient.get").taint_sink is True
    assert SSRF_SINKS.model_for_name("aiohttp.ClientSession.get").taint_sink is True


def test_ftp_sinks():
    from pyflow.analysis.ifds.modeling.presets import FTP_SINKS
    assert FTP_SINKS.model_for_name("ftplib.FTP.retrbinary").taint_sink is True


def test_smtp_sinks():
    from pyflow.analysis.ifds.modeling.presets import SMTP_SINKS
    assert SMTP_SINKS.model_for_name("smtplib.SMTP.sendmail").taint_sink is True


def test_cmd_injection_sanitizers():
    from pyflow.analysis.ifds.modeling.presets import CMD_INJECTION_SANITIZERS
    assert CMD_INJECTION_SANITIZERS.model_for_name("shlex.quote").taint_sanitizer is True
    assert CMD_INJECTION_SANITIZERS.model_for_name("pipes.quote").taint_sanitizer is True


def test_markup_sanitizers():
    from pyflow.analysis.ifds.modeling.presets import MARKUP_SANITIZERS
    assert MARKUP_SANITIZERS.model_for_name("markupsafe.escape").taint_sanitizer is True
    assert MARKUP_SANITIZERS.model_for_name("bleach.clean").taint_sanitizer is True
    assert MARKUP_SANITIZERS.model_for_name("django.utils.html.escape").taint_sanitizer is True
    assert MARKUP_SANITIZERS.model_for_name("nh3.clean").taint_sanitizer is True


def test_http_request_sources():
    from pyflow.analysis.ifds.modeling.presets import HTTP_REQUEST_SOURCES
    assert HTTP_REQUEST_SOURCES.model_for_name("flask.request.args.get").taint_source is True
    assert HTTP_REQUEST_SOURCES.model_for_name("django.http.HttpRequest.GET.get").taint_source is True
    assert HTTP_REQUEST_SOURCES.model_for_name("fastapi.Request.query_params.get").taint_source is True
    assert HTTP_REQUEST_SOURCES.model_for_name("sanic.request.Request.args.get").taint_source is True
    assert HTTP_REQUEST_SOURCES.model_for_name("falcon.Request.get_param").taint_source is True
    assert HTTP_REQUEST_SOURCES.model_for_name("bottle.request.query.get").taint_source is True
    assert HTTP_REQUEST_SOURCES.model_for_name("tornado.httputil.HTTPServerRequest.get_argument").taint_source is True
    assert HTTP_REQUEST_SOURCES.model_for_name("starlette.requests.Request.query_params.get").taint_source is True
    assert HTTP_REQUEST_SOURCES.model_for_name("aiohttp.web_request.Request.query.get").taint_source is True
    assert HTTP_REQUEST_SOURCES.model_for_name("pyramid.request.Request.params.get").taint_source is True


def test_config_nullable():
    from pyflow.analysis.ifds.modeling.presets import CONFIG_NULLABLE
    assert CONFIG_NULLABLE.model_for_name("configparser.ConfigParser.get").nullness_nullable_return is True


def test_iter_nullable():
    from pyflow.analysis.ifds.modeling.presets import ITER_NULLABLE
    assert ITER_NULLABLE.model_for_name("next").nullness_nullable_return is True


def test_chain_nullable():
    from pyflow.analysis.ifds.modeling.presets import CHAIN_NULLABLE
    assert CHAIN_NULLABLE.model_for_name("json.loads").nullness_nullable_return is True
    assert CHAIN_NULLABLE.model_for_name("base64.b64decode").nullness_nullable_return is True


def test_http_typestate():
    from pyflow.analysis.ifds.modeling.presets import (
        HTTP_TYPESTATE_CLOSE,
        HTTP_TYPESTATE_OPEN,
        HTTP_TYPESTATE_USE,
    )
    assert STATE_OPEN in HTTP_TYPESTATE_OPEN.model_for_name("requests.Session").typestate_actions
    assert STATE_USE in HTTP_TYPESTATE_USE.model_for_name("get").typestate_actions
    assert STATE_CLOSE in HTTP_TYPESTATE_CLOSE.model_for_name("close").typestate_actions


def test_cursor_typestate():
    from pyflow.analysis.ifds.modeling.presets import (
        CURSOR_TYPESTATE_CLOSE,
        CURSOR_TYPESTATE_OPEN,
        CURSOR_TYPESTATE_USE,
    )
    assert STATE_OPEN in CURSOR_TYPESTATE_OPEN.model_for_name("sqlite3.Connection.cursor").typestate_actions
    assert STATE_CLOSE in CURSOR_TYPESTATE_CLOSE.model_for_name("close").typestate_actions
    assert STATE_USE in CURSOR_TYPESTATE_USE.model_for_name("execute").typestate_actions


def test_header_injection_sanitizers():
    from pyflow.analysis.ifds.modeling.presets import HEADER_INJECTION_SANITIZERS
    assert HEADER_INJECTION_SANITIZERS.model_for_name("email.utils.formataddr").taint_sanitizer is True


def test_merged_presets_include_new_categories():
    assert TAINT_SINK_PRESETS.model_for_name("pymongo.collection.Collection.find").taint_sink is True
    assert TAINT_SINK_PRESETS.model_for_name("ldap.ldapobject.SimpleLDAPObject.search").taint_sink is True
    assert TAINT_SANITIZER_PRESETS.model_for_name("shlex.quote").taint_sanitizer is True
    assert TAINT_SANITIZER_PRESETS.model_for_name("bleach.clean").taint_sanitizer is True
    assert TAINT_PRESETS.model_for_name("flask.request.args.get").taint_source is True
    assert NULLNESS_PRESETS.model_for_name("next").nullness_nullable_return is True
    assert NULLNESS_PRESETS.model_for_name("configparser.ConfigParser.get").nullness_nullable_return is True
    assert STATE_OPEN in TYPESTATE_OPEN_PRESETS.model_for_name("requests.Session").typestate_actions
    assert STATE_CLOSE in TYPESTATE_CLOSE_PRESETS.model_for_name("cleanup").typestate_actions


def test_message_queue_sources():
    from pyflow.analysis.ifds.modeling.presets import MESSAGE_QUEUE_SOURCES
    assert MESSAGE_QUEUE_SOURCES.model_for_name("kafka.KafkaConsumer").taint_source is True
    assert MESSAGE_QUEUE_SOURCES.model_for_name("pika.channel.Channel.basic_get").taint_source is True
    assert MESSAGE_QUEUE_SOURCES.model_for_name("celery.app.task.Task.request").taint_source is True
    assert MESSAGE_QUEUE_SOURCES.model_for_name("redis.Redis.brpop").taint_source is True
    assert MESSAGE_QUEUE_SOURCES.model_for_name("zmq.Socket.recv").taint_source is True
    assert MESSAGE_QUEUE_SOURCES.model_for_name("google.cloud.pubsub_v1.SubscriberClient.pull").taint_source is True


def test_message_queue_sinks():
    from pyflow.analysis.ifds.modeling.presets import MESSAGE_QUEUE_SINKS
    assert MESSAGE_QUEUE_SINKS.model_for_name("kafka.KafkaProducer.send").taint_sink is True
    assert MESSAGE_QUEUE_SINKS.model_for_name("pika.channel.Channel.basic_publish").taint_sink is True
    assert MESSAGE_QUEUE_SINKS.model_for_name("google.cloud.pubsub_v1.PublisherClient.publish").taint_sink is True
    assert MESSAGE_QUEUE_SINKS.model_for_name("boto3.client.sqs.send_message").taint_sink is True
    assert MESSAGE_QUEUE_SINKS.model_for_name("boto3.client.sns.publish").taint_sink is True


def test_websocket_sources():
    from pyflow.analysis.ifds.modeling.presets import WEBSOCKET_SOURCES
    assert WEBSOCKET_SOURCES.model_for_name("websockets.server.WebSocketServerProtocol.recv").taint_source is True
    assert WEBSOCKET_SOURCES.model_for_name("aiohttp.web_ws.WebSocketResponse.receive").taint_source is True
    assert WEBSOCKET_SOURCES.model_for_name("tornado.websocket.WebSocketHandler.on_message").taint_source is True
    assert WEBSOCKET_SOURCES.model_for_name("socketio.AsyncServer.on").taint_source is True


def test_websocket_sinks():
    from pyflow.analysis.ifds.modeling.presets import WEBSOCKET_SINKS
    assert WEBSOCKET_SINKS.model_for_name("websockets.server.WebSocketServerProtocol.send").taint_sink is True
    assert WEBSOCKET_SINKS.model_for_name("aiohttp.web_ws.WebSocketResponse.send_str").taint_sink is True
    assert WEBSOCKET_SINKS.model_for_name("socketio.AsyncServer.emit").taint_sink is True


def test_graphql_sources():
    from pyflow.analysis.ifds.modeling.presets import GRAPHQL_SOURCES
    assert GRAPHQL_SOURCES.model_for_name("graphql.parse").taint_source is True
    assert GRAPHQL_SOURCES.model_for_name("strawberry.Schema.execute").taint_source is True


def test_file_format_sinks():
    from pyflow.analysis.ifds.modeling.presets import FILE_FORMAT_SINKS
    assert FILE_FORMAT_SINKS.model_for_name("csv.writer.writerow").taint_sink is True
    assert FILE_FORMAT_SINKS.model_for_name("openpyxl.Workbook.save").taint_sink is True
    assert FILE_FORMAT_SINKS.model_for_name("xlsxwriter.worksheet.Worksheet.write").taint_sink is True
    assert FILE_FORMAT_SINKS.model_for_name("pandas.DataFrame.to_csv").taint_sink is True
    assert FILE_FORMAT_SINKS.model_for_name("pandas.DataFrame.to_excel").taint_sink is True
    assert FILE_FORMAT_SINKS.model_for_name("reportlab.platypus.SimpleDocTemplate.build").taint_sink is True
    assert FILE_FORMAT_SINKS.model_for_name("fpdf.FPDF.output").taint_sink is True
    assert FILE_FORMAT_SINKS.model_for_name("weasyprint.HTML.write_pdf").taint_sink is True
    assert FILE_FORMAT_SINKS.model_for_name("python_docx.Document.add_paragraph").taint_sink is True
    assert FILE_FORMAT_SINKS.model_for_name("pillow.Image.open").taint_sink is True


def test_dns_sinks():
    from pyflow.analysis.ifds.modeling.presets import DNS_SINKS
    assert DNS_SINKS.model_for_name("socket.gethostbyname").taint_sink is True
    assert DNS_SINKS.model_for_name("dns.resolver.Resolver.resolve").taint_sink is True


def test_email_sources():
    from pyflow.analysis.ifds.modeling.presets import EMAIL_SOURCES
    assert EMAIL_SOURCES.model_for_name("email.parser.Parser.parsestr").taint_source is True
    assert EMAIL_SOURCES.model_for_name("imaplib.IMAP4.fetch").taint_source is True


def test_cloud_storage_sinks():
    from pyflow.analysis.ifds.modeling.presets import CLOUD_STORAGE_SINKS
    assert CLOUD_STORAGE_SINKS.model_for_name("boto3.client.s3.upload_file").taint_sink is True
    assert CLOUD_STORAGE_SINKS.model_for_name("boto3.client.dynamodb.put_item").taint_sink is True
    assert CLOUD_STORAGE_SINKS.model_for_name("google.cloud.storage.Blob.upload_from_string").taint_sink is True
    assert CLOUD_STORAGE_SINKS.model_for_name("google.cloud.firestore.DocumentReference.set").taint_sink is True
    assert CLOUD_STORAGE_SINKS.model_for_name("azure.storage.blob.BlobClient.upload_blob").taint_sink is True


def test_webhook_sinks():
    from pyflow.analysis.ifds.modeling.presets import WEBHOOK_SINKS
    assert WEBHOOK_SINKS.model_for_name("slack_sdk.WebClient.chat_postMessage").taint_sink is True
    assert WEBHOOK_SINKS.model_for_name("discord.Webhook.send").taint_sink is True
    assert WEBHOOK_SINKS.model_for_name("twilio.rest.Client.messages.create").taint_sink is True
    assert WEBHOOK_SINKS.model_for_name("sendgrid.SendGridAPIClient.send").taint_sink is True
    assert WEBHOOK_SINKS.model_for_name("telegram.Bot.send_message").taint_sink is True


def test_file_upload_sources():
    from pyflow.analysis.ifds.modeling.presets import FILE_UPLOAD_SOURCES
    assert FILE_UPLOAD_SOURCES.model_for_name("werkzeug.datastructures.FileStorage.stream").taint_source is True
    assert FILE_UPLOAD_SOURCES.model_for_name("django.core.files.uploadedfile.UploadedFile.read").taint_source is True
    assert FILE_UPLOAD_SOURCES.model_for_name("starlette.datastructures.UploadFile.read").taint_source is True


def test_url_validation_sanitizers():
    from pyflow.analysis.ifds.modeling.presets import URL_VALIDATION_SANITIZERS
    assert URL_VALIDATION_SANITIZERS.model_for_name("urllib.parse.urlparse").taint_sanitizer is True
    assert URL_VALIDATION_SANITIZERS.model_for_name("django.utils.http.url_has_allowed_host_and_scheme").taint_sanitizer is True


def test_file_path_sanitizers():
    from pyflow.analysis.ifds.modeling.presets import FILE_PATH_SANITIZERS
    assert FILE_PATH_SANITIZERS.model_for_name("os.path.basename").taint_sanitizer is True
    assert FILE_PATH_SANITIZERS.model_for_name("werkzeug.utils.secure_filename").taint_sanitizer is True


def test_query_nullable():
    from pyflow.analysis.ifds.modeling.presets import QUERY_NULLABLE
    assert QUERY_NULLABLE.model_for_name("fetchone").nullness_nullable_return is True
    assert QUERY_NULLABLE.model_for_name("scalar").nullness_nullable_return is True


def test_subprocess_typestate():
    from pyflow.analysis.ifds.modeling.presets import (
        SUBPROCESS_TYPESTATE_CLOSE,
        SUBPROCESS_TYPESTATE_OPEN,
        SUBPROCESS_TYPESTATE_USE,
    )
    assert STATE_OPEN in SUBPROCESS_TYPESTATE_OPEN.model_for_name("subprocess.Popen").typestate_actions
    assert STATE_CLOSE in SUBPROCESS_TYPESTATE_CLOSE.model_for_name("terminate").typestate_actions
    assert STATE_USE in SUBPROCESS_TYPESTATE_USE.model_for_name("poll").typestate_actions


def test_final_merged_regression():
    assert TAINT_PRESETS.model_for_name("kafka.KafkaConsumer").taint_source is True
    assert TAINT_SINK_PRESETS.model_for_name("pandas.DataFrame.to_csv").taint_sink is True
    assert TAINT_SINK_PRESETS.model_for_name("slack_sdk.WebClient.chat_postMessage").taint_sink is True
    assert TAINT_SINK_PRESETS.model_for_name("discord.Webhook.send").taint_sink is True
    assert TAINT_SANITIZER_PRESETS.model_for_name("urllib.parse.urlparse").taint_sanitizer is True
    assert TAINT_SANITIZER_PRESETS.model_for_name("os.path.basename").taint_sanitizer is True
    assert TAINT_PRESETS.model_for_name("email.parser.Parser.parsestr").taint_source is True
    assert NULLNESS_PRESETS.model_for_name("fetchone").nullness_nullable_return is True
    assert STATE_OPEN in TYPESTATE_OPEN_PRESETS.model_for_name("subprocess.Popen").typestate_actions
