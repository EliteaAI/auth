import functools
from flask import jsonify
from flask_restful import Resource

try:
    from tools import api_tools
except:
    from pylon.core.tools.context import Context as Holder
    api_tools = Holder()
    api_tools.endpoint_metrics = lambda *args, **kwargs: lambda f: f


class API(Resource):
    def __init__(self, module):
        self.module = module

    url_params = [
        '<string:mode>/<int:project_id>',
    ]

    @api_tools.endpoint_metrics
    def get(self, mode, project_id):
        current_permissions = self.module.resolve_permissions(
            mode=mode,
            project_id=project_id
        )
        return jsonify(list(current_permissions))
