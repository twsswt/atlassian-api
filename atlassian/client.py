#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from __future__ import print_function

"""
This project is a clone of the jira-python project (https://jira-python.readthedocs.org/en/latest/), with added support
for Confluence.

This module implements a friendly (well, friendlier) abstract interface between the raw JSON responses from Atlassian
products (JIRA and Confluence) and the Resource/dict abstractions provided by this library.
"""

import copy
import json
import logging

try:  # Python 2.7+
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):

        def emit(self, record):
            pass

import calendar
import datetime
import hashlib
import requests
import sys
import warnings

from six.moves.urllib.parse import urlparse

# GreenHopper specific resources
from atlassian.exceptions import AtlassianError
from atlassian.resilientsession import ResilientSession

from atlassian import __version__
from atlassian.utils import json_loads
from pkg_resources import parse_version

try:
    from collections import OrderedDict
except ImportError:
    # noinspection PyUnresolvedReferences
    from ordereddict import OrderedDict

try:
    # noinspection PyUnresolvedReferences
    from requests_toolbelt import MultipartEncoder
except ImportError:
    pass

try:
    from requests_jwt import JWTAuth
except ImportError:
    pass


logging.getLogger('jira').addHandler(NullHandler())


def _get_template_list(data):
    template_list = []
    if 'projectTemplates' in data:
        template_list = data['projectTemplates']
    elif 'projectTemplatesGroupedByType' in data:
        for group in data['projectTemplatesGroupedByType']:
            template_list.extend(group['projectTemplates'])
    return template_list


def _field_worker(fields=None, **fieldargs):
    if fields is not None:
        return {'fields': fields}
    return {'fields': fieldargs}


class ResultList(list):

    def __init__(self, iterable=None, _startAt=None, _maxResults=None, _total=None, _isLast=None):
        if iterable is not None:
            list.__init__(self, iterable)
        else:
            list.__init__(self)

        self.startAt = _startAt
        self.maxResults = _maxResults
        # Optional parameters:
        self.isLast = _isLast
        self.total = _total


class QshGenerator(object):

    def __init__(self, context_path):
        self.context_path = context_path

    def __call__(self, req):
        parse_result = urlparse(req.url)

        path = parse_result.path[len(self.context_path):] if len(self.context_path) > 1 else parse_result.path
        query = '&'.join(sorted(parse_result.query.split("&")))
        qsh = '%(method)s&%(path)s&%(query)s' % {'method': req.method.upper(), 'path': path, 'query': query}

        return hashlib.sha256(qsh).hexdigest()


class Atlassian(object):

    DEFAULT_OPTIONS = {
        "rest_path": "api",
        "context_path": "/",
        "verify": True,
        "resilient": True,
        "async": False,
        "client_cert": None,
        "check_update": False,
        "headers": {
            'Cache-Control': 'no-cache',
            # 'Accept': 'application/json;charset=UTF-8',  # default for REST
            'Content-Type': 'application/json',  # ;charset=UTF-8',
            # 'Accept': 'application/json',  # default for REST
            # 'Pragma': 'no-cache',
            # 'Expires': 'Thu, 01 Jan 1970 00:00:00 GMT'
            'X-Atlassian-Token': 'no-check'
        }
    }

    def __init__(self,
                 default_url_pattern=None,
                 server=None,
                 options=None,
                 basic_auth=None,
                 oauth=None,
                 jwt=None,
                 kerberos=False,
                 validate=False,
                 async=False,
                 max_retries=3,
                 proxies=None,
                 timeout=None):

        self._default_url_pattern=default_url_pattern

        self.sys_version_info = tuple([i for i in sys.version_info])

        if options is None:
            options = {}
            if server and hasattr(server, 'keys'):
                warnings.warn(
                    "Old API usage, use Atlassian(url) or Atlassian(options={'server': url}, when using dictionary "
                    "always use named parameters.",
                    DeprecationWarning)
                options = server
                server = None

        if server:
            options['server'] = server
        if async:
            options['async'] = async

        self.logging = logging

        self._options = copy.copy(Atlassian.DEFAULT_OPTIONS)

        self._options.update(options)

        self._rank = None

        # Rip off trailing slash since all urls depend on that
        if self._options['server'].endswith('/'):
            self._options['server'] = self._options['server'][:-1]

        context_path = urlparse(self._options['server']).path
        if len(context_path) > 0:
            self._options['context_path'] = context_path

        self._try_magic()

        if oauth:
            self._create_oauth_session(oauth, timeout)
        elif basic_auth:
            self._create_http_basic_session(*basic_auth, timeout=timeout)
            self._session.headers.update(self._options['headers'])
        elif jwt:
            self._create_jwt_session(jwt, timeout)
        elif kerberos:
            self._create_kerberos_session(timeout)
        else:
            verify = self._options['verify']
            self._session = ResilientSession(timeout=timeout)
            self._session.verify = verify
        self._session.headers.update(self._options['headers'])

        self._session.max_retries = max_retries

        if proxies:
            self._session.proxies = proxies

        if validate:
            # This will raise an Exception if you are not allowed to login.
            # It's better to fail faster than later.
            user = self.session()
            if user.raw is None:
                auth_method = (
                    oauth or basic_auth or jwt or kerberos or "anonymous"
                )
                raise AtlassianError("Can not log in with %s" % str(auth_method))

        self.deploymentType = None

        if self._options['check_update'] and not Atlassian.checked_version:
            Atlassian._check_update_()
            Atlassian.checked_version = True

    def client_info(self):
        """Get the server this client is connected to."""
        return self._options['server']

    @staticmethod
    def _check_update_(self):
        """Check if the current version of the library is outdated."""
        try:
            data = requests.get("https://pypi.python.org/pypi/jira/json", timeout=2.001).json()

            released_version = data['info']['version']
            if parse_version(released_version) > parse_version(__version__):
                warnings.warn(
                    """
                    You are running an outdated version of JIRA Python %s. Current version is %s. Do not file any bugs
                     against older versions.
                     """ % (__version__, released_version))
        except requests.RequestException:
            pass
        except Exception as e:
            logging.warning(e)

    def __del__(self):
        """Destructor for Atlassian instance."""
        session = getattr(self, "_session", None)
        if session is not None:
            if self.sys_version_info < (3, 4, 0):  # workaround for https://github.com/kennethreitz/requests/issues/2303
                try:
                    session.close()
                except TypeError:
                    # TypeError: "'NoneType' object is not callable"
                    # Could still happen here because other references are also
                    # in the process to be torn down, see warning section in
                    # https://docs.python.org/2/reference/datamodel.html#object.__del__
                    pass

    def _check_for_html_error(self, content):
        """
        JIRA has the bad habit of returning errors in pages with 200 and embedding the error in a huge webpage.
        """
        if '<!-- SecurityTokenMissing -->' in content:
            logging.warning("Got SecurityTokenMissing")
            raise AtlassianError("SecurityTokenMissing: %s" % content)
            return False
        return True

    def _fetch_pages(self, item_type, items_key, request_path, startAt=0, maxResults=10, params=None, paging=False):
        """Fetch pages.

        :param item_type: Type of single item. ResultList of such items will be returned.
        :param items_key: Path to the items in JSON returned from server.
                Set it to None, if response is an array, and not a JSON object.
        :param request_path: path in request URL
        :param startAt: index of the first record to be fetched
        :param maxResults: Maximum number of items to return.
                If maxResults evaluates as False, it will try to get all items in batches.
        :param params: Params to be used in all requests. Should not contain startAt and maxResults,
                        as they will be added for each request created from this function.
        :return: ResultList
        """
        page_params = params.copy() if params else {}
        if startAt:
            page_params['startAt'] = startAt
            page_params['start'] = startAt
        if maxResults:
            page_params['maxResults'] = maxResults
            page_params['limit'] = maxResults

        items, is_more_items = self.get_resource_and_items(request_path, page_params, item_type, items_key)

        if paging:
            page_size = len(items)
            page_start = page_size
            page_params['maxResults'] = page_size
            page_params['limit'] = page_size
            while is_more_items:
                page_params['startAt'] = page_start
                page_params['start'] = page_start

                next_items, is_more_items = self.get_resource_and_items(request_path, page_params, item_type, items_key)

                if items:
                    items.extend(next_items)
                    page_start += page_size

        start_at_from_response = 0
        max_results_from_response = 1
        total = 1

        return ResultList(items, start_at_from_response, max_results_from_response, total, not is_more_items)

    @staticmethod
    def _is_more_items(resource):
        is_last = resource.get('isLast')
        if is_last is None:
            _links = resource.get('_links')
            if _links is not None:
                return 'next' in _links
            else:
                return False
        else:
            return not is_last

    def get_resource_and_items(self, request_path, page_params, item_type, items_key):

        resource = self._get_json(request_path, params=page_params)

        if resource:
            try:
                items = [item_type(self._options, self._session, raw_issue_json)
                        for raw_issue_json in  (resource[items_key] if items_key else resource)]

                return items, self._is_more_items(resource)
            except KeyError as e:
                # improving the error text so we know why it happened
                raise KeyError(str(e) + " : " + json.dumps(resource))

        return None, False

    def _get_url(self, path, base_url_pattern=None):
        options = self._options.copy()
        options.update({'path': path})
        return (base_url_pattern if base_url_pattern is not None else self._default_url_pattern).format(**options)

    def _get_json(self, path, url_pattern=None, params=None):
        url = self._get_url(path, url_pattern)
        r = self._session.get(url, params=params)
        try:
            r_json = json_loads(r)
        except ValueError as e:
            logging.error("%s\n%s" % (e, r.text))
            raise e
        return r_json

    def _try_magic(self):
        try:
            import magic
            import weakref
        except ImportError:
            self._magic = None
        else:
            try:
                _magic = magic.Magic(flags=magic.MAGIC_MIME_TYPE)

                def cleanup(x):
                    _magic.close()

                self._magic_weakref = weakref.ref(self, cleanup)
                self._magic = _magic
            except TypeError:
                self._magic = None
            except AttributeError:
                self._magic = None

    def _create_http_basic_session(self, username, password, timeout=None):
        verify = self._options['verify']
        self._session = ResilientSession(timeout=timeout)
        self._session.verify = verify
        self._session.auth = (username, password)
        self._session.cert = self._options['client_cert']

    def _create_oauth_session(self, oauth, timeout):
        verify = self._options['verify']

        from oauthlib.oauth1 import SIGNATURE_RSA
        from requests_oauthlib import OAuth1

        oauth = OAuth1(
            oauth['consumer_key'],
            rsa_key=oauth['key_cert'],
            signature_method=SIGNATURE_RSA,
            resource_owner_key=oauth['access_token'],
            resource_owner_secret=oauth['access_token_secret'])
        self._session = ResilientSession(timeout)
        self._session.verify = verify
        self._session.auth = oauth

    def _create_kerberos_session(self, timeout):
        verify = self._options['verify']

        from requests_kerberos import HTTPKerberosAuth
        from requests_kerberos import OPTIONAL

        self._session = ResilientSession(timeout=timeout)
        self._session.verify = verify
        self._session.auth = HTTPKerberosAuth(mutual_authentication=OPTIONAL)

    def _create_jwt_session(self, jwt, timeout):
        try:
            jwt_auth = JWTAuth(jwt['secret'], alg='HS256')
        except NameError as e:
            logging.error("JWT authentication requires requests_jwt")
            raise e
        jwt_auth.add_field("iat", lambda req: Atlassian._timestamp())
        jwt_auth.add_field("exp", lambda req: Atlassian._timestamp(datetime.timedelta(minutes=3)))
        jwt_auth.add_field("qsh", QshGenerator(self._options['context_path']))
        for f in jwt['payload'].items():
            jwt_auth.add_field(f[0], f[1])
        self._session = ResilientSession(timeout=timeout)
        self._session.verify = self._options['verify']
        self._session.auth = jwt_auth

    @staticmethod
    def _timestamp(dt=None):
        t = datetime.datetime.utcnow()
        if dt is not None:
            t += dt
        return calendar.timegm(t.timetuple())

