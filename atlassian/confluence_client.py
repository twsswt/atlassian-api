from atlassian.client import Atlassian

import copy


class Confluence(Atlassian):

    DEFAULT_OPTIONS = {
        "server": "http://localhost:2990/confluence",
    }

    CONFLUENCE_BASE_URL = '{server}/rest/{rest_path}/{path}'

    def __init__(self,
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

        _options = copy.copy(Confluence.DEFAULT_OPTIONS)
        _options.update(options if type(options) is dict else {})

        super().__init__(Confluence.CONFLUENCE_BASE_URL, server, _options, basic_auth, oauth, jwt, kerberos, validate,
                         async, max_retries, proxies, timeout)
        pass
