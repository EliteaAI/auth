import functools
from queue import Empty
from flask import g, request, jsonify
from pylon.core.tools import log
from tools import auth

try:
    from tools import register_openapi, api_tools, config as c
except:  # pylint: disable=W0702
    from flask_restful import Resource
    from pylon.core.tools.context import Context as Holder  # pylint: disable=E0611,E0401
    #
    class APIBase(Resource):
        def __init__(self, module):
            self.module = module
    #
    def _dummy_register_openapi(*args, **kwargs):
        """Dummy decorator for standalone mode."""
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*fargs, **fkwargs):
                return func(*fargs, **fkwargs)
            return wrapper
        return decorator
    #
    register_openapi = _dummy_register_openapi
    #
    api_tools = Holder()
    api_tools.APIBase = APIBase
    api_tools.endpoint_metrics = lambda *args, **kwargs: lambda f: f
    #
    c = Holder()


class API(api_tools.APIBase):
    url_params = [
        '<string:mode>',
        '',
    ]

    # mode_handlers = {
    #     c.DEFAULT_MODE: ProjectAPI,
    # }

    @register_openapi(
        name="Get Current User",
        description="Get information about the currently authenticated user.",
        mcp_tool=True
    )
    @api_tools.endpoint_metrics
    def get(self, **kwargs):
        user = self.module.current_user()
        try:
            project_id = self.module.context.rpc_manager.timeout(15).projects_get_personal_project_id(user['id'])
            user['personal_project_id'] = project_id
        except Empty:
            ...
        try:
            auth_ctx = auth.get_referenced_auth_context(g.auth.reference)
            avatar = auth_ctx['provider_attr']['attributes']['picture']
        except (AttributeError, KeyError):
            avatar = None
        user['avatar'] = avatar
        return jsonify(user)
