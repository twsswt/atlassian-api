# -*- coding: utf-8 -*-
"""The root of JIRA package namespace."""
from __future__ import unicode_literals
from pbr.version import VersionInfo

_v = VersionInfo('jira').semantic_version()
__version__ = _v.release_string()
version_info = _v.version_tuple()

from atlassian.resources import Comment  # noqa: E402
from atlassian.resources import Issue  # noqa: E402
from atlassian.resources import Priority  # noqa: E402
from atlassian.resources import Project  # noqa: E402
from atlassian.resources import Role  # noqa: E402
from atlassian.resources import User  # noqa: E402
from atlassian.resources import Watchers  # noqa: E402
from atlassian.resources import Worklog  # noqa: E402

from atlassian.resources import Content

from atlassian.config import get_jira  # noqa: E402
from atlassian.exceptions import AtlassianError  # noqa: E402

from atlassian.jira_client import JIRA  # noqa: E402
from atlassian.confluence_client import Confluence

__all__ = (
    'Confluence'
    'Content'
    'Comment',
    '__version__',
    'Issue',
    'JIRA',
    'AtlassianError',
    'Priority',
    'Project',
    'Role',
    'User',
    'version_info',
    'Watchers',
    'Worklog',
    'get_jira'
)
