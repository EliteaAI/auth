#!/usr/bin/python3
# coding=utf-8

#   Copyright 2026 EPAM Systems
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" Module """

import re
import time
import json
import hashlib
import functools
from typing import Optional

import flask  # pylint: disable=E0401
from flask import request, make_response  # pylint: disable=E0401

import redis  # pylint: disable=E0401
import cachetools  # pylint: disable=E0401
import pygeoip  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401
from pylon.core.tools import module  # pylint: disable=E0611,E0401
from pylon.core.tools.context import Context as Holder  # pylint: disable=E0611,E0401

from .models.pd.permissions import Permissions

try:
    from tools import constants as c  # pylint: disable=E0401
    from tools import config as cfg  # pylint: disable=E0401
except:  # pylint: disable=W0702
    c = Holder()
    c.DEFAULT_MODE = "default"
    c.ALLOW_CORS = False
    cfg = None


def generate_permissions(permission_dict: dict[str, str]) -> set[str]:
    """ Prepare permission set """
    # actions = {'edit', 'create', 'delete', 'view'}
    actions = set()
    if user_action := permission_dict.pop('action', None):
        actions.add(user_action)
    result = set()
    parent = ""
    for scope_name, scope in permission_dict.items():
        if not scope:
            break
        parent += scope
        if scope_name == 'item':
            for action in actions:
                result.add(parent + '.' + action)
        else:
            result.add(parent)
        parent += '.'

    return result


def generate_permissions_from_string(permission_string: str) -> set[str]:
    """
    Generate permissions from string.

    :param permission_string: String with permissions.

    :return: generated list of permissions.
    """
    permission_dict = {
        'section': None,
        'subsection': None,
        'item': None,
        'action': None
    }
    permissions = permission_string.split('.')

    for permission_part, permission in zip(permissions, permission_dict.keys()):
        permission_dict[permission] = permission_part

    return generate_permissions(permission_dict)


def has_access(user_permissions: set, required_permissions: list | dict) -> bool:
    """ Check access """
    if isinstance(required_permissions, dict):
        required_permissions = Permissions.parse_obj(required_permissions).permissions

    # from collections import defaultdict
    # import json
    # debug_dict = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    # for i in user_permissions:
    #     try:
    #         s, ss, it, a = i.split('.')
    #         debug_dict[s][ss][it].append(a)
    #     except ValueError:
    #         ...
    #
    # log.info(
    #     '\nhas access: %s\nfound_permission:\n%s\nrequired:\n%s\nuser:\n%s\ndebug_dict:\n%s',
    #     bool(set(required_permissions).intersection(set(user_permissions))),
    #     set(required_permissions).intersection(set(user_permissions)),
    #     set(required_permissions),
    #     set(user_permissions),
    #     json.dumps(dict(debug_dict), indent=2)
    # )

    if not required_permissions:
        return True

    return bool(set(required_permissions).intersection(set(user_permissions)))


class Module(module.ModuleModel):  # pylint: disable=R0902
    """ Pylon module """

    def __init__(self, context, descriptor):
        self.context = context
        self.descriptor = descriptor
        # Decorators
        self.decorators = Holder()
        # RPC proxies
        self._rpcs = [
            [
                "get_referenced_auth_context",
                "auth_get_referenced_auth_context"
            ],
            ["get_session_cookie_name", "auth_get_session_cookie_name"],
            #
            ["register_auth_provider", "auth_register_auth_provider"],
            ["unregister_auth_provider", "auth_unregister_auth_provider"],
            #
            ["register_auth_processor", "auth_register_auth_processor"],
            ["unregister_auth_processor", "auth_unregister_auth_processor"],
            #
            [
                "register_credential_handler",
                "auth_register_credential_handler"
            ],
            [
                "unregister_credential_handler",
                "auth_unregister_credential_handler"
            ],
            #
            ["register_success_mapper", "auth_register_success_mapper"],
            ["unregister_success_mapper", "auth_unregister_success_mapper"],
            #
            ["register_info_mapper", "auth_register_info_mapper"],
            ["unregister_info_mapper", "auth_unregister_info_mapper"],
            #
            ["add_user", "auth_add_user"],
            ["update_user", "auth_update_user"],
            ["delete_user", "auth_delete_user"],
            ["get_user", "auth_get_user"],
            ["list_users", "auth_list_users"],
            ["list_users_paginated", "auth_list_users_paginated"],
            #
            ["add_user_provider", "auth_add_user_provider"],
            ["remove_user_provider", "auth_remove_user_provider"],
            ["get_user_from_provider", "auth_get_user_from_provider"],
            ["list_user_providers", "auth_list_user_providers"],
            #
            ["add_group", "auth_add_group"],
            ["delete_group", "auth_delete_group"],
            ["get_group", "auth_get_group"],
            ["list_groups", "auth_list_groups"],
            ["walk_group_tree", "auth_walk_group_tree"],
            #
            ["add_group_provider", "auth_add_group_provider"],
            ["remove_group_provider", "auth_remove_group_provider"],
            ["get_group_from_provider", "auth_get_group_from_provider"],
            ["list_group_providers", "auth_list_group_providers"],
            #
            ["add_user_group", "auth_add_user_group"],
            ["remove_user_group", "auth_remove_user_group"],
            ["get_user_group_ids", "auth_get_user_group_ids"],
            ["get_user_groups", "auth_get_user_groups"],
            ["list_user_groups", "auth_list_user_groups"],
            #
            ["add_scope", "auth_add_scope"],
            ["delete_scope", "auth_delete_scope"],
            ["get_scope", "auth_get_scope"],
            ["list_scopes", "auth_list_scopes"],
            ["walk_scope_tree", "auth_walk_scope_tree"],
            #
            ["add_group_permission", "auth_add_group_permission"],
            ["remove_group_permission", "auth_remove_group_permission"],
            ["get_group_permissions", "auth_get_group_permissions"],
            ["list_group_permissions", "auth_list_group_permissions"],
            #
            ["add_user_permission", "auth_add_user_permission"],
            ["remove_user_permission", "auth_remove_user_permission"],
            ["get_user_permissions", "auth_get_user_permissions"],
            ["list_user_permissions", "auth_list_user_permissions"],
            #
            ["add_token", "auth_add_token"],
            ["delete_token", "auth_delete_token"],
            ["get_token", "auth_get_token"],
            ["list_tokens", "auth_list_tokens"],
            ["encode_token", "auth_encode_token"],
            ["decode_token", "auth_decode_token"],
            #
            ["get_token_permissions", "auth_get_token_permissions"],
            #
            ["get_roles", "auth_get_roles"],
            ["get_permissions", "auth_get_permissions"],
            ["set_permission_for_role", "auth_set_permission_for_role"],
            ["remove_permission_from_role", "auth_remove_permission_from_role"],
            ["insert_permissions", "auth_insert_permissions"],
            ["get_user_roles", "auth_get_user_roles"],
            ["add_role", "auth_add_role"],
            ["delete_role", "auth_delete_role"],
            ["update_role_name", "auth_update_role_name"],
            ["assign_user_to_role", "auth_assign_user_to_role"],
            ["remove_user_from_role", "auth_remove_user_from_role"],
            #
            ["add_project_role", "auth_add_project_role"],
            ["update_project_role", "auth_update_project_role"],
            ["delete_project_role", "auth_delete_project_role"],
            ["get_project_role", "auth_get_project_role"],
            ["list_project_roles", "auth_list_project_roles"],
            ["add_project_role_permission", "auth_add_project_role_permission"],
            ["delete_project_role_permission", "auth_delete_project_role_permission"],
            ["list_project_role_permissions", "auth_list_project_role_permissions"],
            ["add_project_user_role", "auth_add_project_user_role"],
            ["delete_project_user_role", "auth_delete_project_user_role"],
            ["update_project_user_roles", "auth_update_project_user_roles"],
            ["list_project_user_roles", "auth_list_project_user_roles"],
            ["get_project_user_permissions", "auth_get_project_user_permissions"],
            ["check_user_in_project", "auth_check_user_in_project"],
            ["check_user_in_projects", "auth_check_user_in_projects"],
            ["list_project_users", "auth_list_project_users"],
            ["apply_project_roles_snapshot", "auth_apply_project_roles_snapshot"],
        ]
        # SIO auth data
        self.sio_users = {}  # sid -> auth_data
        self.local_permissions = set()
        #
        self.auth_mode = "traefik"
        self.public_rules = []  # [rule]
        # Caches
        self.get_user_permissions_cache = cachetools.TTLCache(maxsize=20480, ttl=60)
        self.get_token_permissions_cache = cachetools.TTLCache(maxsize=20480, ttl=60)
        self.get_user_cache = cachetools.TTLCache(maxsize=20480, ttl=60)
        self.get_token_cache = cachetools.TTLCache(maxsize=20480, ttl=60)
        self.get_project_permissions_cache = cachetools.TTLCache(maxsize=20480, ttl=60)  # Direct project permissions cache
        # Redis cache for auth_authorize (under load optimization)
        self._redis_client = None
        self._auth_cache_ttl = 60  # seconds

    #
    # Redis auth cache helpers
    #

    def _register_openapi(self):
        """Register API endpoints with OpenAPI registry."""
        try:
            from tools import openapi_registry # pylint: disable=E0401,C0415
        except ImportError:  # pylint: disable=W0702
            # Standalone mode - OpenAPI registration not available
            return
        #
        from .api import v2 as api_v2
        openapi_registry.register_plugin(
            plugin_name="auth",
            version=self.descriptor.metadata.get("version", "1.0.0"),
            description="Auth API endpoints",
            api_module=api_v2,
        )

    def get_cache_redis_client(self):
        """ Lazy init Redis client for auth caching """
        redis_config = self.descriptor.config.get("redis_config", None)  # pylint: disable=E1101
        #
        if self._redis_client is None and (redis_config is not None or cfg is not None):
            try:
                if not redis_config:
                    redis_config = {
                        "host": getattr(cfg, 'REDIS_HOST', 'redis'),
                        "port": getattr(cfg, 'REDIS_PORT', 6379),
                        "db": 0,  # Use DB 0 for consistency with other caches
                        "username": getattr(cfg, 'REDIS_USER', ''),
                        "password": getattr(cfg, 'REDIS_PASSWORD', ''),
                        "ssl": getattr(cfg, 'REDIS_USE_SSL', False),
                        "decode_responses": True,
                        "socket_timeout": 1,  # Fast timeout
                        "socket_connect_timeout": 1,
                    }
                #
                redis_config = redis_config.copy()
                #
                if redis_config.get("use_managed_identity", False):
                    redis_config.pop("use_managed_identity")
                    redis_config.pop("password", None)
                    #
                    from redis_entraid.cred_provider import create_from_default_azure_credential  # pylint: disable=C0415,E0401,W0401
                    #
                    credential_provider = create_from_default_azure_credential(  # pylint: disable=E0602
                        ("https://redis.azure.com/.default",),
                    )
                    #
                    redis_config["credential_provider"] = credential_provider
                #
                self._redis_client = redis.Redis(**redis_config)
                # Test connection
                self._redis_client.ping()
                log.info("[AUTH_CACHE] Redis client initialized for auth caching")
            except Exception as e:
                log.error(f"[AUTH_CACHE] Failed to init Redis: {e}")
                self._redis_client = False  # Mark as failed, don't retry
        #
        return self._redis_client if self._redis_client else None

    def _get_auth_cache_key(self, cookies: dict, headers: dict = None) -> Optional[str]:
        """ Generate cache key from session cookie or Authorization header """
        # First, check for Authorization header (token-based auth)
        if headers:
            auth_header = headers.get("Authorization") or headers.get("authorization")
            if auth_header:
                # Hash the token to avoid storing raw token values
                key_hash = hashlib.sha256(auth_header.encode()).hexdigest()[:32]
                return f"auth:token:{key_hash}"

        # Then, try to get the Flask session cookie name from app config
        session_cookie = None
        try:
            session_cookie_name = self.context.app.session_cookie_name
            if session_cookie_name:
                session_cookie = cookies.get(session_cookie_name)
        except:
            pass
        # Fallback: look for any session cookie (common patterns)
        if not session_cookie:
            for cookie_name, cookie_value in cookies.items():
                if '_session' in cookie_name.lower() or cookie_name.lower() == 'session':
                    session_cookie = cookie_value
                    break
        if not session_cookie:
            return None
        # Hash the session to avoid storing raw session values
        key_hash = hashlib.sha256(session_cookie.encode()).hexdigest()[:32]
        return f"auth:session:{key_hash}"

    def _get_cached_auth(self, cache_key: str) -> Optional[dict]:
        """ Get auth result from Redis cache """
        redis_client = self.get_cache_redis_client()
        if not redis_client:
            return None
        try:
            cached = redis_client.get(cache_key)
            if cached:
                log.debug(f"[AUTH_CACHE] Cache HIT: {cache_key[:20]}...")
                return json.loads(cached)
        except Exception as e:
            log.error(f"[AUTH_CACHE] Redis get failed: {e}")
        return None

    def _set_cached_auth(self, cache_key: str, auth_status: dict) -> None:
        """ Store auth result in Redis cache """
        redis_client = self.get_cache_redis_client()
        if not redis_client:
            return
        try:
            redis_client.setex(cache_key, self._auth_cache_ttl, json.dumps(auth_status))
            log.debug(f"[AUTH_CACHE] Cache SET: {cache_key[:20]}... (TTL={self._auth_cache_ttl}s)")
        except Exception as e:
            log.error(f"[AUTH_CACHE] Redis set failed: {e}")

    #
    # Module
    #

    def preload(self):
        """ Preload handler """
        self.descriptor.register_tool("auth", self)

    def init(self):
        """ Init module """
        log.info("Initializing module")
        # Config
        self.auth_mode = self.descriptor.config.get("auth_mode", self.auth_mode).lower()
        # Add decorators
        self.decorators.check = self._decorator_check
        self.decorators.check_api = self._decorator_check_api
        self.decorators.check_slot = self._decorator_check_slot
        #
        self.decorators.sio_connect = self._decorator_sio_connect
        self.decorators.sio_disconnect = self._decorator_sio_disconnect
        self.decorators.sio_check = self._decorator_sio_check
        # Register RPC proxies
        rpc_call = self.context.rpc_manager.timeout(15)
        #
        for proxy_name, rpc_name in self._rpcs:
            if hasattr(self, proxy_name):
                raise RuntimeError(f"Name '{proxy_name}' is already set")
            #
            setattr(self, proxy_name, getattr(rpc_call, rpc_name))
        #
        self.has_access = has_access  # pylint: disable=W0201
        # Register auth tool
        self.descriptor.register_tool("auth", self)
        # Add hooks
        self.context.app.before_request(self._before_request_hook)
        self.context.app.after_request(self._after_request_hook)
        # Register configured public rules
        for public_rule in self.descriptor.config.get("public_rules", []):
            self.add_public_rule(public_rule)
        #
        self.register_permissions = self._reg_permissions  # pylint: disable=W0201
        # Enable cache
        if self.descriptor.config.get("enable_cache", True):
            # FIXME: maybe this creates malfunctions
            self.get_user_permissions = cachetools.cached(  # pylint: disable=W0201
                cache=self.get_user_permissions_cache
            )(self.get_user_permissions)
            #
            self.get_token_permissions = cachetools.cached(  # pylint: disable=W0201
                cache=self.get_token_permissions_cache
            )(self.get_token_permissions)
            #
            self.get_user = cachetools.cached(  # pylint: disable=W0201
                cache=self.get_user_cache
            )(self.get_user)
            #
            self.get_token = cachetools.cached(  # pylint: disable=W0201
                cache=self.get_token_cache
            )(self.get_token)
        # Load GeoIP databases
        try:
            self.geoip = pygeoip.GeoIP("/usr/share/GeoIP/GeoIP.dat")  # pylint: disable=W0201
        except:  # pylint: disable=W0702
            self.geoip = None  # pylint: disable=W0201
        #
        # try:
        #     self.geoip6 = pygeoip.GeoIP("/usr/share/GeoIP/GeoIPv6.dat")  # pylint: disable=W0201
        # except:  # pylint: disable=W0702
        #     self.geoip6 = None  # pylint: disable=W0201
        # Register API endpoints (enable on pylon_main only, false by default)
        if self.descriptor.config.get("register_api", False):
            self.descriptor.init_api()
        self.descriptor.init_rpcs()
        #
        # log.info("Running DB migrations")
        # db_migrations.run_db_migrations(self, db.url)
        if self.descriptor.config.get("register_api", False):
            self._register_openapi()

    def _after_request_hook(self, response):
        additional_headers = self.descriptor.config.get(
            "additional_headers", {}
        )
        for key, value in additional_headers.items():
            response.headers[key] = value
        #
        if c.ALLOW_CORS or self.descriptor.config.get("allow_cors", False):
            if request.method == 'OPTIONS':
                response = make_response()
                response.status_code = 200
                response.headers.add('Access-Control-Allow-Headers', '*')
                response.headers.add('Access-Control-Allow-Methods', '*')
                response.headers.add('Access-Control-Allow-Credentials', 'true')
            response.headers.add('Access-Control-Allow-Origin', '*')
        #
        additional_default_headers = self.descriptor.config.get(
            "additional_default_headers", {}
        )
        for key, value in additional_default_headers.items():
            if key not in response.headers:
                response.headers[key] = value
        #
        return response

    def deinit(self):
        """ De-init module """
        log.info("De-initializing module")
        # Unregister auth tool
        self.descriptor.unregister_tool("auth")
        # Unregister RPC proxies
        for proxy_name, _ in self._rpcs:
            delattr(self, proxy_name)

    #
    # Ping: check if auth pylon is connected
    #

    def ping(self, retry_interval=5, rpc_timeout=1, max_retries=None):
        """ Check if auth pylon is connected """
        retries_done = 0
        #
        while True:
            try:
                self.context.rpc_manager.timeout(rpc_timeout).auth_ping()
                return True
            except:  # pylint: disable=W0702
                retries_done += 1
                #
                if max_retries is not None and retries_done >= max_retries:
                    return False
                #
                time.sleep(retry_interval)

    #
    # Hooks
    #

    def _before_request_hook(self):  # pylint: disable=R0912,R0915
        if self.descriptor.config.get("force_https_redirect", False) and \
                flask.request.host not in self.descriptor.config.get(
                    "https_redirect_excludes", []
                ):
            if flask.request.scheme == "http":
                log.info("HTTP -> HTTPS redirect for host: %s", flask.request.host)
                return flask.redirect(flask.request.url.replace("http://", "https://", 1))
        #
        flask.g.auth = Holder()
        #
        if self.auth_mode == "rpc":
            # Collect data
            source_uri = flask.request.full_path
            if not flask.request.query_string and source_uri.endswith("?"):
                source_uri = source_uri[:-1]
            source_uri = f'{self.context.url_prefix}{source_uri}'
            #
            source = {
                "method": flask.request.method,
                "proto": flask.request.scheme,
                "host": flask.request.host,
                "uri": source_uri,
                "ip": flask.request.remote_addr,
                "target": "rpc",
                "scope": None,
            }
            headers = dict(flask.request.headers.items())
            cookies = dict(flask.request.cookies.items())
            # Check public rules
            is_public_route = False
            for rule in self.public_rules:
                if self.public_rule_matches(rule, source):
                    is_public_route = True
            # Call authorize RPC (with Redis caching for performance)
            auth_status = None
            cache_key = self._get_auth_cache_key(cookies, headers)
            #
            # Try Redis cache first
            if cache_key:
                auth_status = self._get_cached_auth(cache_key)
            #
            # Cache miss - call RPC
            if auth_status is None:
                try:
                    auth_status = self.context.rpc_manager.timeout(15).auth_authorize(
                        source, headers, cookies
                    )
                    # Cache successful auth results
                    if cache_key and auth_status.get("auth_ok"):
                        self._set_cached_auth(cache_key, auth_status)
                except:  # pylint: disable=W0702
                    self._make_public_g_auth()
                    auth_status = None  # Mark as handled
            #
            if auth_status is not None:
                if auth_status["auth_ok"]:
                    flask.g.auth.type = auth_status["headers"].get("X-Auth-Type", "public")
                    flask.g.auth.id = auth_status["headers"].get("X-Auth-ID", "-")
                    flask.g.auth.reference = auth_status["headers"].get(
                        "X-Auth-Reference", "-"
                    )
                elif is_public_route:
                    # Keep session here
                    self._make_public_g_auth()
                elif auth_status["action"] == "redirect":
                    flask.session.destroy()  # Clear session
                    return flask.redirect(auth_status["target"])
                elif auth_status["action"] == "make_response":
                    flask.session.destroy()  # Clear session
                    return flask.make_response(auth_status["data"], auth_status["status_code"])
                else:
                    # Keep session here (for now)
                    return self.access_denied_reply()
            #
        #
        elif self.auth_mode == "traefik":
            flask.g.auth.type = flask.request.headers.get("X-Auth-Type", "public")
            flask.g.auth.id = flask.request.headers.get("X-Auth-ID", "-")
            flask.g.auth.reference = flask.request.headers.get(
                "X-Auth-Reference", "-"
            )
        #
        else:
            self._make_public_g_auth()
        #
        try:
            flask.g.auth.id = int(flask.g.auth.id)
        except:  # pylint: disable=W0702
            flask.g.auth.id = "-"
        #
        flask.g.visitor = Holder()
        #
        flask.g.visitor.ip = flask.request.remote_addr
        flask.g.visitor.masked_ip = ".".join(str(flask.g.visitor.ip).split(".")[:-1] + ["xx"])
        #
        try:
            flask.g.visitor.country_code = self.geoip.country_code_by_addr(flask.g.visitor.ip)
        except:  # pylint: disable=W0702
            flask.g.visitor.country_code = ""
        #
        try:
            flask.g.visitor.country_name = self.geoip.country_name_by_addr(flask.g.visitor.ip)
        except:  # pylint: disable=W0702
            flask.g.visitor.country_name = ""
        #
        visitor_event = {
            "type": flask.g.auth.type,
            "id": flask.g.auth.id,
            "reference": flask.g.auth.reference,
            "ip": flask.g.visitor.ip,
            "masked_ip": flask.g.visitor.masked_ip,
            "country_code": flask.g.visitor.country_code,
            "country_name": flask.g.visitor.country_name,
        }
        #
        self.context.event_manager.fire_event(
            "auth_visitor", visitor_event,
        )
        #
        log.debug("Visitor: %s", visitor_event)
        #
        return None

    @staticmethod
    def _make_public_g_auth():
        flask.g.auth.type = "public"
        flask.g.auth.id = "-"
        flask.g.auth.reference = "-"

    #
    # Decorators
    #

    #
    # Decorators: SIO
    #

    def _decorator_sio_connect(self):
        """ SIO: on connect save auth data for SID """

        #
        def _decorator(func):
            #
            @functools.wraps(func)
            def _decorated(*_args, **_kvargs):
                sid = _args[1]
                environ = _args[2]
                #
                self.sio_users[sid] = self.sio_make_auth_data(environ)
                #
                return func(*_args, **_kvargs)

            #
            return _decorated

        #
        return _decorator

    def _decorator_sio_disconnect(self):
        """ SIO: on disconnect remove auth data for SID """

        #
        def _decorator(func):
            #
            @functools.wraps(func)
            def _decorated(*_args, **_kvargs):
                sid = _args[1]
                #
                self.sio_users.pop(sid, None)
                #
                return func(*_args, **_kvargs)

            #
            return _decorated

        #
        return _decorator

    def _decorator_sio_check(self, permissions: list, scope_id: int = 1):
        """ SIO: on event """
        _ = scope_id
        #
        self.update_local_permissions(permissions)
        #
        def _decorator(func):
            #
            @functools.wraps(func)
            def _decorated(*_args, **_kvargs):
                sid = _args[1]
                #
                current_permissions = self.resolve_permissions(
                    mode='administration', auth_data=self.sio_users[sid]
                )
                #
                if has_access(current_permissions, permissions):
                    return func(*_args, **_kvargs)
                #
                return None

            #
            return _decorated
        #
        return _decorator

    def update_local_permissions(self, permissions: list | dict):
        """ Update local permissions """

        if not isinstance(permissions, dict):
            permissions = {"permissions": permissions}

        self._create_template_permissions(permissions)

    def _create_template_permissions(self, permissions: dict):
        result = []
        perm_obj = Permissions.parse_obj(permissions)
        if not perm_obj.permissions:
            return
        for perm in perm_obj.permissions:
            for mode, roles in perm_obj.recommended_roles.dict().items():
                for role, value in roles.items():
                    if value:
                        result.append((role, mode, perm))
            self.local_permissions.update(generate_permissions_from_string(perm))
            self.local_permissions.add(perm)

        if result:
            self.insert_permissions(result)

    #
    # Decorators
    #

    def _decorator_check(
            self, permissions: list | dict,
            access_denied_reply=...,
            mode="default",
            **kwargs
    ):
        """ Check access to route """
        _ = kwargs
        if access_denied_reply is ...:
            access_denied_reply = {"ok": False, "error": "access_denied"}
        #
        self.update_local_permissions(permissions)
        #
        def _decorator(func):
            @functools.wraps(func)
            def _decorated(*_args, **_kwargs):
                #
                # TBD: correct mode support
                current_permissions = self.resolve_permissions(mode=mode)
                #
                if has_access(current_permissions, permissions):
                    return func(*_args, **_kwargs)
                #
                return access_denied_reply, 403
            return _decorated
        #
        return _decorator

    def _reg_permissions(self, permissions: list | dict):
        self.update_local_permissions(permissions)

    def _decorator_check_api(
            self, permissions: list | dict,
            access_denied_reply: Optional[dict] = None,
            add_verbose_info: bool = True,
            **kwargs
    ):
        """ Check access to API """
        self.update_local_permissions(permissions)
        if access_denied_reply is None:
            access_denied_reply = {"ok": False, "error": "access_denied"}
        if add_verbose_info:
            if isinstance(permissions, dict):
                access_denied_reply['required'] = permissions.get('permissions', permissions)
            else:
                access_denied_reply['required'] = permissions

        def _decorator(func):
            @functools.wraps(func)
            def _decorated(*_args, **_kwargs):
                try:
                    mode = kwargs.get("mode") or _kwargs.get("mode") or _args[0].mode
                except (AttributeError, IndexError):
                    mode = "default"
                try:
                    project_id = \
                        kwargs.get("project_id") or _kwargs.get('project_id') or _args[0].project_id
                except (AttributeError, IndexError):
                    project_id = None

                if project_id is None and \
                        kwargs.get("project_id_in_request_json", False):
                    try:
                        project_id = flask.request.json.get('project_id')
                    except:  # pylint: disable=W0702
                        project_id = None  # no change

                # log.info('CHECK API %s', _args)
                # log.info('CHECK API %s', _kwargs)
                # log.info('CHECK API %s %s', mode, project_id)

                current_permissions = self.resolve_permissions(
                    mode=mode,
                    project_id=project_id
                )
                if has_access(current_permissions, permissions):
                    return func(*_args, **_kwargs)
                if add_verbose_info and isinstance(access_denied_reply, dict):
                    access_denied_reply['mode'] = mode
                    access_denied_reply['project_id'] = project_id
                    access_denied_reply['current_permissions'] = list(current_permissions)
                return access_denied_reply, 403
            return _decorated
        return _decorator

    def _decorator_check_slot(
            self, permissions: list | dict, access_denied_reply="",
    ):
        """ Check access to slot """
        self.update_local_permissions(permissions)

        #
        def _decorator(func):
            #
            @functools.wraps(func)
            def _decorated(*_args, **_kvargs):
                # log.info('check_slot State %s | %s', _args, _kvargs)
                context = _args[-1]  # need to get Context object
                if not isinstance(context, Holder):
                    return func(*_args, **_kvargs)
                #
                try:
                    mode = flask.g.theme.active_mode
                except AttributeError:
                    mode = c.DEFAULT_MODE

                current_permissions = self.resolve_permissions(
                    mode=mode, auth_data=context.auth
                )
                #
                if has_access(current_permissions, permissions):
                    return func(*_args, **_kvargs)
                #
                return access_denied_reply, 403

            #
            return _decorated

        #
        return _decorator

    #
    # Tools
    #

    #
    # Tools: public routes
    #

    def add_public_rule(self, rule):
        """ Public route: add """
        if self.auth_mode == "rpc":
            rule_obj = {}
            for key, regex in rule.items():
                rule_obj[key] = re.compile(regex)
            #
            if rule_obj not in self.public_rules:
                self.public_rules.append(rule_obj)
            #
            return None
        #
        return self.context.rpc_manager.timeout(15).auth_add_public_rule(rule)

    def remove_public_rule(self, rule):
        """ Public route: add """
        if self.auth_mode == "rpc":
            rule_obj = {}
            for key, regex in rule.items():
                rule_obj[key] = re.compile(regex)
            #
            while rule_obj in self.public_rules:
                self.public_rules.remove(rule_obj)
            #
            return None
        #
        return self.context.rpc_manager.timeout(15).auth_remove_public_rule(rule)

    @staticmethod
    def public_rule_matches(rule, source):
        """ Apply public rule """
        for key, obj in rule.items():
            if not obj.fullmatch(source[key]):
                return False
        #
        return True

    #
    # Tools: access denied
    #

    def access_denied_reply(self):
        """ Traefik/client: bad auth reply/redirect """
        if "auth_denied_url" in self.descriptor.config:
            return flask.redirect(self.descriptor.config.get("auth_denied_url"))
        return flask.make_response("Access Denied", 403)

    #
    # Tools: current
    #

    def resolve_permissions(self, mode: str = 'administration', auth_data=None,
                            project_id: Optional[int] = None) -> set:
        """ Resolve current permissions """
        if auth_data is None:
            auth_data = flask.g.auth

        if not project_id:
            try:
                project_id = self.context.rpc_manager.timeout(15).project_get_id()
            except:  # pylint: disable=W0702
                project_id = None

        # log.info(
        #     'resolve_permissions mode %s | auth_data %s | project_id %s',
        #     mode, auth_data.__dict__, project_id,
        # )

        try:
            if auth_data.type == "user":  # pylint: disable=R1705
                return self.get_user_permissions(auth_data.id, mode=mode, project_id=project_id)
            elif auth_data.type == "token":
                return self.get_token_permissions(auth_data.id, mode=mode, project_id=project_id)
            else:
                # Public: no permissions
                return set()
        except:  # pylint: disable=W0702
            log.exception("Failed to get permissions")
            return set()



    #
    # Tools: SIO
    #

    def sio_make_auth_data(self, environ):
        """ SIO: make auth data """
        auth_data = Holder()
        #
        if self.auth_mode == "rpc":
            # Construct request
            req = flask.Request(environ)
            # Collect data
            source_uri = req.full_path
            if not req.query_string and source_uri.endswith("?"):
                source_uri = source_uri[:-1]
            source_uri = f'{self.context.url_prefix}{source_uri}'
            #
            source = {
                "method": req.method,
                "proto": req.scheme,
                "host": req.host,
                "uri": source_uri,
                "ip": req.remote_addr,
                "target": "rpc",
                "scope": None,
            }
            headers = dict(req.headers.items())
            cookies = dict(req.cookies.items())
            # Call authorize RPC (with Redis caching for performance)
            auth_status = None
            cache_key = self._get_auth_cache_key(cookies, headers)
            #
            # Try Redis cache first
            if cache_key:
                auth_status = self._get_cached_auth(cache_key)
            #
            # Cache miss - call RPC
            if auth_status is None:
                try:
                    auth_status = self.context.rpc_manager.timeout(15).auth_authorize(
                        source, headers, cookies
                    )
                    # Cache successful auth results
                    if cache_key and auth_status.get("auth_ok"):
                        self._set_cached_auth(cache_key, auth_status)
                except:  # pylint: disable=W0702
                    auth_data.type = "public"
                    auth_data.id = "-"
                    auth_data.reference = "-"
                    auth_status = None  # Mark as handled
            #
            if auth_status is not None:
                if auth_status["auth_ok"]:
                    auth_data.type = auth_status["headers"].get("X-Auth-Type", "public")
                    auth_data.id = auth_status["headers"].get("X-Auth-ID", "-")
                    auth_data.reference = auth_status["headers"].get(
                        "X-Auth-Reference", "-"
                    )
                    #
                    try:
                        auth_data.id = int(auth_data.id)
                    except:  # pylint: disable=W0702
                        auth_data.id = "-"
                else:  # Note: may handle other cases (like 'redirect') later
                    auth_data.type = "public"
                    auth_data.id = "-"
                    auth_data.reference = "-"
        #
        elif self.auth_mode == "traefik":
            auth_data.type = environ.get("HTTP_X_AUTH_TYPE", "public")
            auth_data.id = environ.get("HTTP_X_AUTH_ID", "-")
            auth_data.reference = environ.get("HTTP_X_AUTH_REFERENCE", "-")
            #
            try:
                auth_data.id = int(auth_data.id)
            except:  # pylint: disable=W0702
                auth_data.id = "-"
        #
        else:
            auth_data.type = "public"
            auth_data.id = "-"
            auth_data.reference = "-"
        #
        return auth_data

    #
    # Tools: slot
    #

    def make_request_state(self):
        """ Make request state snapshot for slots """
        state = Holder()
        #
        state.auth = flask.g.auth
        #
        state.request = Holder()
        state.request.args = dict(flask.request.args)
        #
        state.theme = Holder()
        try:
            state.theme.active_mode = flask.g.theme.active_mode
            state.theme.active_parameter = flask.g.theme.active_parameter
            state.theme.active_section = flask.g.theme.active_section
            state.theme.active_subsection = flask.g.theme.active_subsection
        except AttributeError:
            state.theme.active_mode = c.DEFAULT_MODE
            state.theme.active_parameter = None
            state.theme.active_section = None
            state.theme.active_subsection = None
        #
        return state

    #
    # Tools: user in project
    #

    def is_user_in_project(self, project_id):
        """ Check if user in specific project """
        if not project_id:
            return False
        #
        current_user = self.current_user()
        user_id = current_user.get("id", None)
        #
        if not user_id:
            return False
        #
        return self.check_user_in_project(project_id, user_id)

    def is_sio_user_in_project(self, sid, project_id):
        """ Check if SIO user in specific project """
        if sid not in self.sio_users:
            return False
        #
        if not project_id:
            return False
        #
        current_user = self.current_user(
            auth_data=self.sio_users[sid]
        )
        #
        user_id = current_user.get("id", None)
        #
        if not user_id:
            return False
        #
        return self.check_user_in_project(project_id, user_id)
