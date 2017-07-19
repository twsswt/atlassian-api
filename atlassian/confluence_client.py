from atlassian.client import Atlassian

from atlassian.resources import Content, History

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

    def search_content(self, jql_str, startAt=0, maxResults=50, validate_query=True, fields=list(), expand=None):

        search_params = {
            "jql": jql_str,
            "startAt": startAt,
            "validateQuery": validate_query,
            "fields": fields,
            "expand": expand
        }

        results = self._fetch_pages(Content, 'results', 'content', startAt, maxResults, search_params)

        return results

    def content_by_id(self, page_id, version, expand=None):
        search_params = {
            "status": "historical",
            "expand": expand,
            "version": version
        }

        path = "content/{page_id}".format(**{'page_id': page_id})
        return self._get_json(path,  params=search_params)
