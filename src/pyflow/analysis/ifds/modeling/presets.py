from __future__ import annotations

from .calls import STATE_CLOSE, STATE_OPEN, STATE_USE, CallModel, CallModelRegistry


def _source(name: str) -> CallModel:
    return CallModel(name=name, source_kinds=frozenset({"untrusted"}))


def _sink(name: str) -> CallModel:
    return CallModel(name=name, sink_kinds=frozenset({"dangerous"}))


def _sanitizer(name: str) -> CallModel:
    return CallModel(name=name, sanitizer_kinds=frozenset({"*"}))


def _nullable(name: str) -> CallModel:
    return CallModel(name=name, nullness_nullable_return=True)


def _typestate_open(
    name: str,
    *,
    resource_arg_positions=frozenset({0}),
    track_receiver=True,
    protocol: str = "resource",
    receiver_types=frozenset(),
    module_prefixes=frozenset(),
) -> CallModel:
    return CallModel(
        name=name,
        typestate_actions=frozenset({STATE_OPEN}),
        typestate_action_protocols=frozenset({(STATE_OPEN, protocol)}),
        resource_arg_positions=resource_arg_positions,
        track_method_receiver=track_receiver,
        receiver_types=receiver_types,
        module_prefixes=module_prefixes,
    )


def _typestate_close(
    name: str,
    *,
    resource_arg_positions=frozenset({0}),
    track_receiver=True,
    protocol: str = "resource",
    receiver_types=frozenset(),
) -> CallModel:
    return CallModel(
        name=name,
        typestate_actions=frozenset({STATE_CLOSE}),
        typestate_action_protocols=frozenset({(STATE_CLOSE, protocol)}),
        resource_arg_positions=resource_arg_positions,
        track_method_receiver=track_receiver,
        receiver_types=receiver_types,
    )


def _typestate_use(
    name: str,
    *,
    resource_arg_positions=frozenset({0}),
    track_receiver=True,
    protocol: str = "resource",
    receiver_types=frozenset(),
) -> CallModel:
    return CallModel(
        name=name,
        typestate_actions=frozenset({STATE_USE}),
        typestate_action_protocols=frozenset({(STATE_USE, protocol)}),
        resource_arg_positions=resource_arg_positions,
        track_method_receiver=track_receiver,
        receiver_types=receiver_types,
    )


IO_SOURCES = CallModelRegistry([
    _source("input"),
    _source("sys.stdin.read"),
    _source("sys.stdin.readline"),
])

IO_SINKS = CallModelRegistry([
    _sink("print"),
    _sink("sys.stdout.write"),
    _sink("sys.stderr.write"),
])

FILE_SOURCES = CallModelRegistry([
    _source("open"),
    _source("io.open"),
    _source("pathlib.Path.read_text"),
    _source("pathlib.Path.read_bytes"),
])

FILE_SINKS = CallModelRegistry([
    _sink("open"),
    _sink("io.open"),
    _sink("shutil.copy"),
    _sink("shutil.move"),
    _sink("shutil.copyfile"),
    _sink("os.remove"),
    _sink("os.unlink"),
    _sink("os.rename"),
    _sink("os.mkdir"),
    _sink("os.makedirs"),
    _sink("pathlib.Path.write_text"),
    _sink("pathlib.Path.write_bytes"),
    _sink("pathlib.Path.mkdir"),
    _sink("pathlib.Path.unlink"),
    _sink("pathlib.Path.rename"),
])

STRING_SANITIZERS = CallModelRegistry([
    _sanitizer("str.strip"),
    _sanitizer("str.lstrip"),
    _sanitizer("str.rstrip"),
    _sanitizer("str.replace"),
    _sanitizer("str.upper"),
    _sanitizer("str.lower"),
    _sanitizer("str.capitalize"),
    _sanitizer("str.title"),
    _sanitizer("str.encode"),
    _sanitizer("bytes.decode"),
    _sanitizer("html.escape"),
    _sanitizer("urllib.parse.quote"),
    _sanitizer("urllib.parse.quote_plus"),
    _sanitizer("urllib.parse.urlencode"),
    _sanitizer("re.escape"),
])

TYPE_CONVERSION_SANITIZERS = CallModelRegistry([
    _sanitizer("int"),
    _sanitizer("float"),
    _sanitizer("bool"),
    _sanitizer("str"),
    _sanitizer("bytes"),
    _sanitizer("complex"),
    _sanitizer("decimal.Decimal"),
])

COLLECTION_MUTATORS = CallModelRegistry([
    CallModel(name="append", typestate_actions=frozenset()),
    CallModel(name="extend", typestate_actions=frozenset()),
    CallModel(name="insert", typestate_actions=frozenset()),
    CallModel(name="update", typestate_actions=frozenset()),
    CallModel(name="add", typestate_actions=frozenset()),
    CallModel(name="remove", typestate_actions=frozenset()),
    CallModel(name="discard", typestate_actions=frozenset()),
    CallModel(name="pop", typestate_actions=frozenset()),
])

COLLECTION_ACCESSORS = CallModelRegistry([
    CallModel(name="get", typestate_actions=frozenset()),
    CallModel(name="items", typestate_actions=frozenset()),
    CallModel(name="keys", typestate_actions=frozenset()),
    CallModel(name="values", typestate_actions=frozenset()),
])

OS_SUBPROCESS_SINKS = CallModelRegistry([
    _sink("os.system"),
    _sink("os.popen"),
    _sink("os.execv"),
    _sink("os.execve"),
    _sink("os.execl"),
    _sink("os.execle"),
    _sink("os.execvp"),
    _sink("os.execvpe"),
    _sink("os.spawnl"),
    _sink("os.spawnle"),
    _sink("os.spawnlp"),
    _sink("os.spawnlpe"),
    _sink("os.spawnv"),
    _sink("os.spawnve"),
    _sink("os.spawnvp"),
    _sink("os.spawnvpe"),
    _sink("subprocess.run"),
    _sink("subprocess.call"),
    _sink("subprocess.check_call"),
    _sink("subprocess.check_output"),
    _sink("subprocess.Popen"),
    _sink("subprocess.Popen.communicate"),
])

OS_ENV_SOURCES = CallModelRegistry([
    _source("os.environ.get"),
    _source("os.getenv"),
    _source("os.environ"),
])

OS_PATH_SINKS = CallModelRegistry([
    _sink("os.path.join"),
    _sink("os.path.abspath"),
    _sink("os.path.realpath"),
    _sink("os.path.expanduser"),
    _sink("os.path.dirname"),
    _sink("os.path.basename"),
])

DYNAMIC_CODE_SINKS = CallModelRegistry([
    _sink("eval"),
    _sink("exec"),
    _sink("compile"),
    _sink("__import__"),
    _sink("importlib.import_module"),
    _sink("importlib.util.spec_from_loader"),
])

SERIALIZATION_SINKS = CallModelRegistry([
    _sink("pickle.loads"),
    _sink("pickle.load"),
    _sink("yaml.load"),
    _sink("yaml.safe_load"),
    _sink("json.loads"),
    _sink("json.load"),
    _sink("marshal.loads"),
    _sink("marshal.load"),
    _sink("ast.literal_eval"),
])

SERIALIZATION_SANITIZERS = CallModelRegistry([
    _sanitizer("json.dumps"),
    _sanitizer("json.dump"),
    _sanitizer("repr"),
    _sanitizer("str"),
])

HTTP_SOURCES = CallModelRegistry([
    _source("requests.get"),
    _source("requests.post"),
    _source("requests.put"),
    _source("requests.patch"),
    _source("requests.delete"),
    _source("requests.head"),
    _source("requests.request"),
    _source("urllib.request.urlopen"),
    _source("urllib.request.urlretrieve"),
    _source("http.client.HTTPConnection.request"),
    _source("httpx.get"),
    _source("httpx.post"),
    _source("httpx.request"),
    _source("aiohttp.ClientSession.get"),
    _source("aiohttp.ClientSession.post"),
    _source("aiohttp.ClientSession.request"),
])

HTTP_SINKS = CallModelRegistry([
    _sink("urllib.request.urlopen"),
    _sink("urllib.request.urlretrieve"),
    _sink("requests.Session.get"),
    _sink("requests.Session.post"),
])

SQL_SINKS = CallModelRegistry([
    _sink("sqlite3.Cursor.execute"),
    _sink("sqlite3.Cursor.executemany"),
    _sink("sqlite3.Cursor.executescript"),
    _sink("sqlite3.Connection.execute"),
    _sink("sqlite3.connect"),
    _sink("psycopg2.cursor.execute"),
    _sink("psycopg2.cursor.executemany"),
    _sink("psycopg2.connect"),
    _sink("MySQLdb.cursor.execute"),
    _sink("MySQLdb.connect"),
    _sink("pymysql.cursor.execute"),
    _sink("pymysql.connect"),
    _sink("sqlalchemy.engine.Engine.execute"),
    _sink("sqlalchemy.orm.Session.execute"),
    _sink("django.db.connection.cursor"),
    _sink("django.db.connection.cursor.execute"),
])

XML_SOURCES = CallModelRegistry([
    _source("xml.etree.ElementTree.parse"),
    _source("xml.etree.ElementTree.fromstring"),
    _source("xml.etree.ElementTree.iterparse"),
    _source("xml.etree.ElementTree.XMLParser"),
    _source("lxml.etree.parse"),
    _source("lxml.etree.fromstring"),
    _source("lxml.etree.iterparse"),
    _source("lxml.etree.XMLParser"),
    _source("lxml.objectify.parse"),
    _source("defusedxml.ElementTree.parse"),
    _source("defusedxml.ElementTree.fromstring"),
])

XML_SINKS = CallModelRegistry([
    _sink("xml.etree.ElementTree.tostring"),
    _sink("xml.etree.ElementTree.SubElement"),
    _sink("lxml.etree.tostring"),
    _sink("lxml.etree.SubElement"),
    _sink("lxml.html.fromstring"),
    _sink("lxml.html.parse"),
])

XPATH_SINKS = CallModelRegistry([
    _sink("xml.etree.ElementTree.Element.find"),
    _sink("xml.etree.ElementTree.Element.findall"),
    _sink("xml.etree.ElementTree.Element.findtext"),
    _sink("xml.etree.ElementTree.Element.iterfind"),
    _sink("lxml.etree._Element.find"),
    _sink("lxml.etree._Element.findall"),
    _sink("lxml.etree._Element.findtext"),
    _sink("lxml.etree._Element.iterfind"),
    _sink("lxml.etree._Element.xpath"),
    _sink("lxml.etree.XPath"),
    _sink("lxml.etree.XPathEvaluator"),
])

LDAP_SINKS = CallModelRegistry([
    _sink("ldap.ldapobject.SimpleLDAPObject.search"),
    _sink("ldap.ldapobject.SimpleLDAPObject.search_s"),
    _sink("ldap.ldapobject.SimpleLDAPObject.search_ext"),
    _sink("ldap.ldapobject.SimpleLDAPObject.search_ext_s"),
    _sink("ldap3.Connection.search"),
    _sink("ldap3.Connection.extend.standard.paged_search"),
])

NOSQL_SINKS = CallModelRegistry([
    _sink("pymongo.collection.Collection.find"),
    _sink("pymongo.collection.Collection.find_one"),
    _sink("pymongo.collection.Collection.aggregate"),
    _sink("pymongo.collection.Collection.update_one"),
    _sink("pymongo.collection.Collection.update_many"),
    _sink("pymongo.collection.Collection.delete_one"),
    _sink("pymongo.collection.Collection.delete_many"),
    _sink("pymongo.collection.Collection.insert_one"),
    _sink("pymongo.collection.Collection.insert_many"),
    _sink("redis.Redis.execute_command"),
    _sink("redis.Redis.eval"),
    _sink("redis.Redis.evalsha"),
    _sink("redis.StrictRedis.execute_command"),
    _sink("elasticsearch.Elasticsearch.search"),
    _sink("elasticsearch.Elasticsearch.index"),
    _sink("elasticsearch.Elasticsearch.update"),
    _sink("elasticsearch.Elasticsearch.delete"),
    _sink("couchdb.Database.view"),
    _sink("couchdb.Database.find"),
    _sink("cassandra.cluster.Session.execute"),
    _sink("cassandra.cluster.Session.execute_async"),
])

PATH_TRAVERSAL_SINKS = CallModelRegistry([
    _sink("tarfile.TarFile.extract"),
    _sink("tarfile.TarFile.extractall"),
    _sink("tarfile.open"),
    _sink("zipfile.ZipFile.extract"),
    _sink("zipfile.ZipFile.extractall"),
    _sink("shutil.unpack_archive"),
    _sink("shutil.rmtree"),
    _sink("shutil.copytree"),
])

SSRF_SINKS = CallModelRegistry([
    _sink("urllib.request.urlopen"),
    _sink("urllib.request.urlretrieve"),
    _sink("urllib.request.Request"),
    _sink("http.client.HTTPConnection.request"),
    _sink("http.client.HTTPSConnection.request"),
    _sink("urllib3.PoolManager.request"),
    _sink("urllib3.connectionpool.HTTPConnectionPool.urlopen"),
    _sink("httpx.AsyncClient.get"),
    _sink("httpx.AsyncClient.post"),
    _sink("httpx.AsyncClient.request"),
    _sink("aiohttp.ClientSession.get"),
    _sink("aiohttp.ClientSession.post"),
    _sink("aiohttp.ClientSession.request"),
    _sink("socket.create_connection"),
    _sink("socket.socket.connect"),
])

FTP_SINKS = CallModelRegistry([
    _sink("ftplib.FTP.connect"),
    _sink("ftplib.FTP.login"),
    _sink("ftplib.FTP.retrbinary"),
    _sink("ftplib.FTP.retrlines"),
    _sink("ftplib.FTP.storbinary"),
    _sink("ftplib.FTP.storlines"),
])

SMTP_SINKS = CallModelRegistry([
    _sink("smtplib.SMTP.sendmail"),
    _sink("smtplib.SMTP.send_message"),
    _sink("smtplib.SMTP_SSL.sendmail"),
])

CMD_INJECTION_SANITIZERS = CallModelRegistry([
    _sanitizer("shlex.quote"),
    _sanitizer("shlex.split"),
    _sanitizer("pipes.quote"),
    _sanitizer("subprocess.list2cmdline"),
])

MARKUP_SANITIZERS = CallModelRegistry([
    _sanitizer("markupsafe.escape"),
    _sanitizer("markupsafe.Markup.escape"),
    _sanitizer("markupsafe.Markup.striptags"),
    _sanitizer("bleach.clean"),
    _sanitizer("bleach.linkify"),
    _sanitizer("django.utils.html.escape"),
    _sanitizer("django.utils.html.strip_tags"),
    _sanitizer("django.utils.html.format_html"),
    _sanitizer("nh3.clean"),
])

HTTP_REQUEST_SOURCES = CallModelRegistry([
    _source("flask.request.args.get"),
    _source("flask.request.args.getlist"),
    _source("flask.request.form.get"),
    _source("flask.request.form.getlist"),
    _source("flask.request.json.get"),
    _source("flask.request.get_json"),
    _source("flask.request.data"),
    _source("flask.request.headers.get"),
    _source("flask.request.cookies.get"),
    _source("flask.request.files.get"),
    _source("flask.request.values.get"),
    _source("django.http.HttpRequest.GET.get"),
    _source("django.http.HttpRequest.GET.getlist"),
    _source("django.http.HttpRequest.POST.get"),
    _source("django.http.HttpRequest.POST.getlist"),
    _source("django.http.HttpRequest.body"),
    _source("django.http.HttpRequest.headers.get"),
    _source("django.http.HttpRequest.COOKIES.get"),
    _source("django.http.HttpRequest.FILES.get"),
    _source("django.http.HttpRequest.META.get"),
    _source("fastapi.Request.query_params.get"),
    _source("fastapi.Request.path_params.get"),
    _source("fastapi.Request.headers.get"),
    _source("fastapi.Request.cookies.get"),
    _source("fastapi.Request.json"),
    _source("fastapi.Request.body"),
    _source("fastapi.Request.form"),
    _source("sanic.request.Request.args.get"),
    _source("sanic.request.Request.form.get"),
    _source("sanic.request.Request.json.get"),
    _source("sanic.request.Request.body"),
    _source("sanic.request.Request.headers.get"),
    _source("sanic.request.Request.cookies.get"),
    _source("falcon.Request.get_param"),
    _source("falcon.Request.get_header"),
    _source("falcon.Request.media"),
    _source("falcon.Request.stream"),
    _source("falcon.Request.bounded_stream"),
    _source("bottle.request.query.get"),
    _source("bottle.request.forms.get"),
    _source("bottle.request.json"),
    _source("bottle.request.body"),
    _source("bottle.request.headers.get"),
    _source("bottle.request.cookies.get"),
    _source("bottle.request.files.get"),
    _source("werkzeug.datastructures.MultiDict.get"),
    _source("werkzeug.datastructures.ImmutableMultiDict.get"),
    _source("werkzeug.ImmutableMultiDict.get"),
    _source("pyramid.request.Request.params.get"),
    _source("pyramid.request.Request.GET.get"),
    _source("pyramid.request.Request.POST.get"),
    _source("pyramid.request.Request.json_body"),
    _source("pyramid.request.Request.body"),
    _source("tornado.httputil.HTTPServerRequest.get_argument"),
    _source("tornado.httputil.HTTPServerRequest.get_body_argument"),
    _source("tornado.httputil.HTTPServerRequest.get_query_argument"),
    _source("tornado.httputil.HTTPServerRequest.body"),
    _source("starlette.requests.Request.query_params.get"),
    _source("starlette.requests.Request.path_params.get"),
    _source("starlette.requests.Request.headers.get"),
    _source("starlette.requests.Request.cookies.get"),
    _source("starlette.requests.Request.json"),
    _source("starlette.requests.Request.body"),
    _source("starlette.requests.Request.form"),
    _source("aiohttp.web_request.Request.query.get"),
    _source("aiohttp.web_request.Request.post"),
    _source("aiohttp.web_request.Request.headers.get"),
    _source("aiohttp.web_request.Request.cookies.get"),
    _source("aiohttp.web_request.Request.json"),
    _source("aiohttp.web_request.Request.text"),
    _source("aiohttp.web_request.Request.read"),
])

CONFIG_NULLABLE = CallModelRegistry([
    _nullable("configparser.ConfigParser.get"),
    _nullable("configparser.ConfigParser.getint"),
    _nullable("configparser.ConfigParser.getfloat"),
    _nullable("configparser.ConfigParser.getboolean"),
    _nullable("configparser.SectionProxy.get"),
    _nullable("tomllib.load"),
    _nullable("tomli.load"),
    _nullable("toml.load"),
])

ITER_NULLABLE = CallModelRegistry([
    _nullable("next"),
    _nullable("iter"),
])

CHAIN_NULLABLE = CallModelRegistry([
    _nullable("json.loads"),
    _nullable("yaml.safe_load"),
    _nullable("pickle.loads"),
    _nullable("pickle.load"),
    _nullable("ast.literal_eval"),
    _nullable("ast.parse"),
    _nullable("struct.unpack"),
    _nullable("base64.b64decode"),
    _nullable("base64.b32decode"),
    _nullable("binascii.unhexlify"),
    _nullable("binascii.a2b_base64"),
])

HTTP_TYPESTATE_OPEN = CallModelRegistry([
    _typestate_open("requests.Session", track_receiver=False),
    _typestate_open("httpx.Client", track_receiver=False),
    _typestate_open("httpx.AsyncClient", track_receiver=False),
    _typestate_open("aiohttp.ClientSession", track_receiver=False),
    _typestate_open("urllib3.PoolManager", track_receiver=False),
])

HTTP_TYPESTATE_CLOSE = CallModelRegistry([
    _typestate_close("close"),
])

HTTP_TYPESTATE_USE = CallModelRegistry([
    _typestate_use("get"),
    _typestate_use("post"),
    _typestate_use("put"),
    _typestate_use("patch"),
    _typestate_use("delete"),
    _typestate_use("head"),
    _typestate_use("request"),
    _typestate_use("send"),
])

TEMP_CLEANUP_CLOSE = CallModelRegistry([
    _typestate_close("cleanup", resource_arg_positions=frozenset()),
    _typestate_close("close"),
])

CURSOR_TYPESTATE_OPEN = CallModelRegistry([
    _typestate_open("sqlite3.Connection.cursor", resource_arg_positions=frozenset()),
    _typestate_open("psycopg2.connection.cursor", resource_arg_positions=frozenset()),
    _typestate_open("MySQLdb.connection.cursor", resource_arg_positions=frozenset()),
])

CURSOR_TYPESTATE_CLOSE = CallModelRegistry([
    _typestate_close("close", resource_arg_positions=frozenset()),
])

CURSOR_TYPESTATE_USE = CallModelRegistry([
    _typestate_use("execute", resource_arg_positions=frozenset()),
    _typestate_use("executemany", resource_arg_positions=frozenset()),
    _typestate_use("fetchone", resource_arg_positions=frozenset()),
    _typestate_use("fetchmany", resource_arg_positions=frozenset()),
    _typestate_use("fetchall", resource_arg_positions=frozenset()),
])

HEADER_INJECTION_SANITIZERS = CallModelRegistry([
    _sanitizer("werkzeug.http.parse_options_header"),
    _sanitizer("email.header.Header.encode"),
    _sanitizer("email.utils.formataddr"),
    _sanitizer("urllib.parse.urlencode"),
])


REGEX_NULLABLE = CallModelRegistry([
    _nullable("re.match"),
    _nullable("re.search"),
    _nullable("re.fullmatch"),
    _nullable("re.compile"),
])

DICT_NULLABLE = CallModelRegistry([
    _nullable("get"),
    _nullable("pop"),
    _nullable("setdefault"),
])

ATTRIBUTE_NULLABLE = CallModelRegistry([
    _nullable("getattr"),
])

ENV_NULLABLE = CallModelRegistry([
    _nullable("os.environ.get"),
    _nullable("os.getenv"),
])

FILE_TYPESTATE_OPEN = CallModelRegistry([
    _typestate_open("open"),
    _typestate_open("io.open"),
    _typestate_open("tempfile.NamedTemporaryFile"),
    _typestate_open("tempfile.TemporaryFile"),
    _typestate_open("tempfile.mkstemp"),
])

FILE_TYPESTATE_CLOSE = CallModelRegistry([
    _typestate_close("close"),
])

FILE_TYPESTATE_USE = CallModelRegistry([
    _typestate_use("read"),
    _typestate_use("readline"),
    _typestate_use("readlines"),
    _typestate_use("write"),
    _typestate_use("writelines"),
    _typestate_use("seek"),
    _typestate_use("tell"),
    _typestate_use("truncate"),
    _typestate_use("flush"),
    _typestate_use("send"),
    _typestate_use("recv"),
])

SOCKET_TYPESTATE_OPEN = CallModelRegistry([
    _typestate_open("socket.socket"),
    _typestate_open("socket.create_connection"),
])

SOCKET_TYPESTATE_CLOSE = CallModelRegistry([
    _typestate_close("close"),
    _typestate_close("shutdown"),
])

SOCKET_TYPESTATE_USE = CallModelRegistry([
    _typestate_use("send"),
    _typestate_use("sendall"),
    _typestate_use("sendto"),
    _typestate_use("recv"),
    _typestate_use("recvfrom"),
    _typestate_use("connect"),
    _typestate_use("bind"),
    _typestate_use("listen"),
    _typestate_use("accept"),
])

LOCK_TYPESTATE_OPEN = CallModelRegistry([
    _typestate_open(
        "threading.Lock",
        resource_arg_positions=frozenset(),
        protocol="lock",
        module_prefixes=frozenset({"threading"}),
    ),
    _typestate_open(
        "threading.RLock",
        resource_arg_positions=frozenset(),
        protocol="lock",
        module_prefixes=frozenset({"threading"}),
    ),
    _typestate_open(
        "threading.Semaphore",
        resource_arg_positions=frozenset(),
        protocol="lock",
        module_prefixes=frozenset({"threading"}),
    ),
    _typestate_open(
        "threading.BoundedSemaphore",
        resource_arg_positions=frozenset(),
        protocol="lock",
        module_prefixes=frozenset({"threading"}),
    ),
    _typestate_open(
        "multiprocessing.Lock",
        resource_arg_positions=frozenset(),
        protocol="lock",
        module_prefixes=frozenset({"multiprocessing"}),
    ),
    _typestate_open(
        "asyncio.Lock",
        resource_arg_positions=frozenset(),
        protocol="lock",
        module_prefixes=frozenset({"asyncio"}),
    ),
])

LOCK_TYPESTATE_CLOSE = CallModelRegistry([
    _typestate_close(
        "release",
        resource_arg_positions=frozenset(),
        protocol="lock",
        receiver_types=frozenset(
            {
                "threading.Lock",
                "threading.RLock",
                "threading.Semaphore",
                "threading.BoundedSemaphore",
                "multiprocessing.Lock",
                "asyncio.Lock",
            }
        ),
    ),
])

LOCK_TYPESTATE_USE = CallModelRegistry([
    _typestate_use(
        "acquire",
        resource_arg_positions=frozenset(),
        protocol="lock",
        receiver_types=frozenset(
            {
                "threading.Lock",
                "threading.RLock",
                "threading.Semaphore",
                "threading.BoundedSemaphore",
                "multiprocessing.Lock",
                "asyncio.Lock",
            }
        ),
    ),
])

SQL_TYPESTATE_OPEN = CallModelRegistry([
    _typestate_open("sqlite3.connect"),
    _typestate_open("psycopg2.connect"),
    _typestate_open("MySQLdb.connect"),
    _typestate_open("pymysql.connect"),
    _typestate_open("sqlalchemy.create_engine"),
])

SQL_TYPESTATE_CLOSE = CallModelRegistry([
    _typestate_close("close"),
])

SQL_TYPESTATE_USE = CallModelRegistry([
    _typestate_use("execute"),
    _typestate_use("executemany"),
    _typestate_use("executescript"),
    _typestate_use("cursor"),
])

CRYPTO_SANITIZERS = CallModelRegistry([
    _sanitizer("hashlib.md5"),
    _sanitizer("hashlib.sha1"),
    _sanitizer("hashlib.sha256"),
    _sanitizer("hashlib.sha512"),
    _sanitizer("hashlib.sha384"),
    _sanitizer("hashlib.blake2b"),
    _sanitizer("hashlib.blake2s"),
    _sanitizer("hmac.new"),
])

TEMPLATE_SINKS = CallModelRegistry([
    _sink("jinja2.Template.render"),
    _sink("jinja2.Environment.from_string"),
    _sink("mako.template.Template.render"),
    _sink("django.template.Template.render"),
    _sink("django.shortcuts.render"),
])

LOGGING_SINKS = CallModelRegistry([
    _sink("logging.debug"),
    _sink("logging.info"),
    _sink("logging.warning"),
    _sink("logging.error"),
    _sink("logging.critical"),
    _sink("logging.log"),
    _sink("logging.Logger.debug"),
    _sink("logging.Logger.info"),
    _sink("logging.Logger.warning"),
    _sink("logging.Logger.error"),
    _sink("logging.Logger.critical"),
    _sink("logging.Logger.log"),
])

MESSAGE_QUEUE_SOURCES = CallModelRegistry([
    _source("kafka.KafkaConsumer"),
    _source("kafka.KafkaConsumer.poll"),
    _source("confluent_kafka.Consumer.poll"),
    _source("confluent_kafka.Consumer.consume"),
    _source("pika.channel.Channel.basic_get"),
    _source("pika.channel.Channel.consume"),
    _source("pika.BlockingConnection.channel"),
    _source("kombu.messaging.Consumer.receive"),
    _source("celery.app.task.Task.request"),
    _source("redis.Redis.brpop"),
    _source("redis.Redis.blpop"),
    _source("redis.Redis.lpop"),
    _source("redis.Redis.rpop"),
    _source("redis.Redis.xread"),
    _source("redis.Redis.xreadgroup"),
    _source("nats.aio.client.Client.subscribe"),
    _source("zmq.Socket.recv"),
    _source("zmq.Socket.recv_json"),
    _source("zmq.Socket.recv_pyobj"),
    _source("zmq.asyncio.Socket.recv"),
    _source("google.cloud.pubsub_v1.SubscriberClient.pull"),
])

MESSAGE_QUEUE_SINKS = CallModelRegistry([
    _sink("kafka.KafkaProducer.send"),
    _sink("confluent_kafka.Producer.produce"),
    _sink("pika.channel.Channel.basic_publish"),
    _sink("kombu.messaging.Producer.publish"),
    _sink("redis.Redis.publish"),
    _sink("redis.Redis.lpush"),
    _sink("redis.Redis.rpush"),
    _sink("redis.Redis.xadd"),
    _sink("redis.Redis.set"),
    _sink("redis.Redis.hset"),
    _sink("nats.aio.client.Client.publish"),
    _sink("zmq.Socket.send"),
    _sink("zmq.Socket.send_json"),
    _sink("zmq.Socket.send_pyobj"),
    _sink("google.cloud.pubsub_v1.PublisherClient.publish"),
    _sink("boto3.client.sqs.send_message"),
    _sink("boto3.client.sqs.send_message_batch"),
    _sink("boto3.client.sns.publish"),
    _sink("boto3.client.sns.publish_batch"),
])

WEBSOCKET_SOURCES = CallModelRegistry([
    _source("websockets.legacy.server.WebSocketServerProtocol.recv"),
    _source("websockets.server.WebSocketServerProtocol.recv"),
    _source("websockets.server.WebSocketServerProtocol.receive"),
    _source("aiohttp.web_ws.WebSocketResponse.receive"),
    _source("aiohttp.web_ws.WebSocketResponse.receive_str"),
    _source("aiohttp.web_ws.WebSocketResponse.receive_json"),
    _source("aiohttp.web_ws.WebSocketResponse.receive_bytes"),
    _source("tornado.websocket.WebSocketHandler.on_message"),
    _source("django.channels.consumer.AsyncConsumer"),
    _source("django.channels.consumer.SyncConsumer"),
    _source("socketio.AsyncServer.on"),
    _source("flask_socketio.SocketIO.on"),
])

WEBSOCKET_SINKS = CallModelRegistry([
    _sink("websockets.server.WebSocketServerProtocol.send"),
    _sink("aiohttp.web_ws.WebSocketResponse.send_str"),
    _sink("aiohttp.web_ws.WebSocketResponse.send_json"),
    _sink("aiohttp.web_ws.WebSocketResponse.send_bytes"),
    _sink("tornado.websocket.WebSocketHandler.write_message"),
    _sink("socketio.AsyncServer.emit"),
    _sink("socketio.AsyncServer.send"),
    _sink("flask_socketio.SocketIO.emit"),
    _sink("flask_socketio.SocketIO.send"),
])

GRAPHQL_SOURCES = CallModelRegistry([
    _source("graphql.language.parser.parse"),
    _source("graphql.parse"),
    _source("graphql.graphql"),
    _source("graphene.Schema.execute"),
    _source("strawberry.Schema.execute"),
    _source("strawberry.Schema.execute_sync"),
    _source("ariadne.graphql"),
    _source("ariadne.make_executable_schema"),
])

GRPC_SOURCES = CallModelRegistry([
    _source("grpc.aio.ServerInterceptor.intercept_service"),
    _source("grpc.ServerInterceptor.intercept_service"),
])

FILE_FORMAT_SINKS = CallModelRegistry([
    _sink("csv.writer"),
    _sink("csv.writer.writerow"),
    _sink("csv.writer.writerows"),
    _sink("csv.DictWriter.writeheader"),
    _sink("csv.DictWriter.writerow"),
    _sink("csv.DictWriter.writerows"),
    _sink("openpyxl.Workbook.create_sheet"),
    _sink("openpyxl.Workbook.save"),
    _sink("openpyxl.worksheet.worksheet.Worksheet.append"),
    _sink("openpyxl.worksheet.worksheet.Worksheet.cell"),
    _sink("xlsxwriter.Workbook.add_worksheet"),
    _sink("xlsxwriter.Workbook.close"),
    _sink("xlsxwriter.worksheet.Worksheet.write"),
    _sink("xlsxwriter.worksheet.Worksheet.write_string"),
    _sink("xlsxwriter.worksheet.Worksheet.write_rich_string"),
    _sink("xlwt.Workbook.add_sheet"),
    _sink("xlwt.Workbook.save"),
    _sink("xlwt.Worksheet.write"),
    _sink("pandas.DataFrame.to_csv"),
    _sink("pandas.DataFrame.to_excel"),
    _sink("pandas.DataFrame.to_json"),
    _sink("pandas.DataFrame.to_html"),
    _sink("pandas.DataFrame.to_xml"),
    _sink("reportlab.platypus.Paragraph"),
    _sink("reportlab.platypus.SimpleDocTemplate.build"),
    _sink("fpdf.FPDF.output"),
    _sink("fpdf.FPDF.cell"),
    _sink("fpdf.FPDF.write"),
    _sink("weasyprint.HTML.write_pdf"),
    _sink("weasyprint.HTML.write_png"),
    _sink("python_docx.Document.add_paragraph"),
    _sink("python_docx.Document.add_heading"),
    _sink("python_docx.Document.save"),
    _sink("python_pptx.Presentation.save"),
    _sink("pillow.Image.open"),
    _sink("pillow.Image.save"),
    _sink("pillow.ImageDraw.Draw.text"),
])

DNS_SINKS = CallModelRegistry([
    _sink("socket.gethostbyname"),
    _sink("socket.gethostbyname_ex"),
    _sink("socket.getaddrinfo"),
    _sink("dns.resolver.Resolver.resolve"),
    _sink("dns.resolver.Resolver.query"),
    _sink("dns.query.tcp"),
    _sink("dns.query.udp"),
    _sink("dns.query.https"),
    _sink("dns.query.tls"),
    _sink("dns.message.make_query"),
])

EMAIL_SOURCES = CallModelRegistry([
    _source("email.parser.Parser.parsestr"),
    _source("email.parser.BytesParser.parsebytes"),
    _source("email.parser.BytesFeedParser.feed"),
    _source("email.message.EmailMessage.get_body"),
    _source("email.message.EmailMessage.get_content"),
    _source("email.message.EmailMessage.get_payload"),
    _source("imaplib.IMAP4.fetch"),
    _source("imaplib.IMAP4.search"),
    _source("poplib.POP3.retr"),
    _source("poplib.POP3.top"),
])

CLOUD_STORAGE_SINKS = CallModelRegistry([
    _sink("boto3.client.s3.upload_file"),
    _sink("boto3.client.s3.upload_fileobj"),
    _sink("boto3.client.s3.put_object"),
    _sink("boto3.resource.s3.Object.put"),
    _sink("boto3.client.dynamodb.put_item"),
    _sink("boto3.client.dynamodb.update_item"),
    _sink("boto3.client.dynamodb.batch_write_item"),
    _sink("boto3.client.dynamodb.query"),
    _sink("google.cloud.storage.Client.bucket"),
    _sink("google.cloud.storage.Bucket.blob"),
    _sink("google.cloud.storage.Blob.upload_from_string"),
    _sink("google.cloud.storage.Blob.upload_from_filename"),
    _sink("google.cloud.datastore.Client.put"),
    _sink("google.cloud.firestore.Client.collection"),
    _sink("google.cloud.firestore.CollectionReference.add"),
    _sink("google.cloud.firestore.CollectionReference.document"),
    _sink("google.cloud.firestore.DocumentReference.set"),
    _sink("google.cloud.firestore.DocumentReference.update"),
    _sink("azure.storage.blob.BlobServiceClient.get_blob_client"),
    _sink("azure.storage.blob.BlobClient.upload_blob"),
    _sink("azure.cosmos.CosmosClient.get_database_client"),
    _sink("azure.cosmos.DatabaseProxy.get_container_client"),
    _sink("azure.cosmos.ContainerProxy.create_item"),
])

WEBHOOK_SINKS = CallModelRegistry([
    _sink("requests.post"),
    _sink("slack_sdk.WebClient.chat_postMessage"),
    _sink("slack_sdk.WebClient.chat_update"),
    _sink("slack_sdk.WebClient.chat_postEphemeral"),
    _sink("slack_sdk.WebClient.files_upload"),
    _sink("discord.Webhook.send"),
    _sink("discord.Client.send_message"),
    _sink("discord.abc.Messageable.send"),
    _sink("discord.TextChannel.send"),
    _sink("twilio.rest.Client.messages.create"),
    _sink("twilio.rest.Client.calls.create"),
    _sink("sendgrid.SendGridAPIClient.send"),
    _sink("sendgrid.helpers.mail.Mail"),
    _sink("telegram.Bot.send_message"),
    _sink("telegram.Bot.send_photo"),
    _sink("telegram.Bot.send_document"),
    _sink("atproto_client.Client.send_post"),
])

FILE_UPLOAD_SOURCES = CallModelRegistry([
    _source("werkzeug.datastructures.FileStorage.stream"),
    _source("werkzeug.datastructures.FileStorage.read"),
    _source("werkzeug.datastructures.FileStorage.save"),
    _source("werkzeug.datastructures.FileStorage.filename"),
    _source("django.core.files.uploadedfile.UploadedFile.read"),
    _source("django.core.files.uploadedfile.UploadedFile.chunks"),
    _source("django.core.files.uploadedfile.UploadedFile.name"),
    _source("django.core.files.uploadedfile.TemporaryUploadedFile.temporary_file_path"),
    _source("starlette.datastructures.UploadFile.read"),
    _source("starlette.datastructures.UploadFile.filename"),
    _source("aiohttp.web_request.FileField.read"),
    _source("aiohttp.web_request.FileField.filename"),
])

URL_VALIDATION_SANITIZERS = CallModelRegistry([
    _sanitizer("urllib.parse.urlparse"),
    _sanitizer("urllib.parse.urlsplit"),
    _sanitizer("urllib.parse.urljoin"),
    _sanitizer("werkzeug.urls.url_parse"),
    _sanitizer("werkzeug.urls.url_encode"),
    _sanitizer("django.utils.http.url_has_allowed_host_and_scheme"),
    _sanitizer("django.utils.http.is_safe_url"),
])

FILE_PATH_SANITIZERS = CallModelRegistry([
    _sanitizer("os.path.basename"),
    _sanitizer("os.path.normpath"),
    _sanitizer("os.path.realpath"),
    _sanitizer("pathlib.PurePath.name"),
    _sanitizer("werkzeug.utils.secure_filename"),
    _sanitizer("django.utils.text.get_valid_filename"),
])

QUERY_NULLABLE = CallModelRegistry([
    _nullable("fetchone"),
    _nullable("fetchmany"),
    _nullable("first"),
    _nullable("one_or_none"),
    _nullable("scalar"),
    _nullable("scalar_one_or_none"),
])

SUBPROCESS_TYPESTATE_OPEN = CallModelRegistry([
    _typestate_open("subprocess.Popen", resource_arg_positions=frozenset()),
    _typestate_open("asyncio.subprocess.create_subprocess_exec", resource_arg_positions=frozenset()),
    _typestate_open("asyncio.subprocess.create_subprocess_shell", resource_arg_positions=frozenset()),
])

SUBPROCESS_TYPESTATE_CLOSE = CallModelRegistry([
    _typestate_close("terminate", resource_arg_positions=frozenset()),
    _typestate_close("kill", resource_arg_positions=frozenset()),
    _typestate_close("wait", resource_arg_positions=frozenset()),
    _typestate_close("communicate", resource_arg_positions=frozenset()),
])

SUBPROCESS_TYPESTATE_USE = CallModelRegistry([
    _typestate_use("poll", resource_arg_positions=frozenset()),
    _typestate_use("stdin.write", resource_arg_positions=frozenset()),
    _typestate_use("stdout.read", resource_arg_positions=frozenset()),
    _typestate_use("stderr.read", resource_arg_positions=frozenset()),
])

TEMP_DIR_TYPESTATE_OPEN = CallModelRegistry([
    _typestate_open("tempfile.TemporaryDirectory"),
    _typestate_open("tempfile.mkdtemp"),
])

TEMP_DIR_TYPESTATE_CLOSE = CallModelRegistry([
    _typestate_close("cleanup", resource_arg_positions=frozenset()),
])

TAINT_PRESETS = IO_SOURCES.merged(
    FILE_SOURCES,
    OS_ENV_SOURCES,
    HTTP_SOURCES,
    XML_SOURCES,
    HTTP_REQUEST_SOURCES,
    MESSAGE_QUEUE_SOURCES,
    WEBSOCKET_SOURCES,
    GRAPHQL_SOURCES,
    GRPC_SOURCES,
    EMAIL_SOURCES,
    FILE_UPLOAD_SOURCES,
)

TAINT_SINK_PRESETS = IO_SINKS.merged(
    FILE_SINKS,
    OS_SUBPROCESS_SINKS,
    OS_PATH_SINKS,
    DYNAMIC_CODE_SINKS,
    SERIALIZATION_SINKS,
    HTTP_SINKS,
    SQL_SINKS,
    TEMPLATE_SINKS,
    LOGGING_SINKS,
    XML_SINKS,
    XPATH_SINKS,
    LDAP_SINKS,
    NOSQL_SINKS,
    PATH_TRAVERSAL_SINKS,
    SSRF_SINKS,
    FTP_SINKS,
    SMTP_SINKS,
    MESSAGE_QUEUE_SINKS,
    WEBSOCKET_SINKS,
    FILE_FORMAT_SINKS,
    DNS_SINKS,
    CLOUD_STORAGE_SINKS,
    WEBHOOK_SINKS,
)

TAINT_SANITIZER_PRESETS = STRING_SANITIZERS.merged(
    TYPE_CONVERSION_SANITIZERS,
    SERIALIZATION_SANITIZERS,
    CRYPTO_SANITIZERS,
    CMD_INJECTION_SANITIZERS,
    MARKUP_SANITIZERS,
    HEADER_INJECTION_SANITIZERS,
    URL_VALIDATION_SANITIZERS,
    FILE_PATH_SANITIZERS,
)

NULLNESS_PRESETS = REGEX_NULLABLE.merged(
    DICT_NULLABLE,
    ATTRIBUTE_NULLABLE,
    ENV_NULLABLE,
    CONFIG_NULLABLE,
    ITER_NULLABLE,
    CHAIN_NULLABLE,
    QUERY_NULLABLE,
)

TYPESTATE_OPEN_PRESETS = FILE_TYPESTATE_OPEN.merged(
    SOCKET_TYPESTATE_OPEN,
    LOCK_TYPESTATE_OPEN,
    SQL_TYPESTATE_OPEN,
    HTTP_TYPESTATE_OPEN,
    CURSOR_TYPESTATE_OPEN,
    SUBPROCESS_TYPESTATE_OPEN,
    TEMP_DIR_TYPESTATE_OPEN,
)

TYPESTATE_CLOSE_PRESETS = FILE_TYPESTATE_CLOSE.merged(
    SOCKET_TYPESTATE_CLOSE,
    LOCK_TYPESTATE_CLOSE,
    SQL_TYPESTATE_CLOSE,
    HTTP_TYPESTATE_CLOSE,
    TEMP_CLEANUP_CLOSE,
    CURSOR_TYPESTATE_CLOSE,
    SUBPROCESS_TYPESTATE_CLOSE,
    TEMP_DIR_TYPESTATE_CLOSE,
)

TYPESTATE_USE_PRESETS = FILE_TYPESTATE_USE.merged(
    SOCKET_TYPESTATE_USE,
    LOCK_TYPESTATE_USE,
    SQL_TYPESTATE_USE,
    HTTP_TYPESTATE_USE,
    CURSOR_TYPESTATE_USE,
    SUBPROCESS_TYPESTATE_USE,
)


def merge_presets(*registries: CallModelRegistry) -> CallModelRegistry:
    if not registries:
        return CallModelRegistry()
    result = registries[0]
    for r in registries[1:]:
        result = result.merged(r)
    return result
