from datetime import datetime, timedelta

from flask import jsonify, request
from pylon.core.tools import log

from tools import auth

from ...constants import SCOPED_TOKEN_MAX_PROJECTS, SCOPED_TOKEN_MAX_TTL_DAYS, SYSTEM_TOKEN_NAME
from ...utils.identity_verifier import TOKEN_OPERATIONS

try:
    from tools import api_tools
except:  # pylint: disable=W0702
    from flask_restful import Resource
    from pylon.core.tools.context import Context as Holder  # pylint: disable=E0611,E0401
    #
    class APIBase(Resource):
        def __init__(self, module):
            self.module = module
    #
    api_tools = Holder()
    api_tools.APIBase = APIBase


def _scope_error(user_id, expires, projects, operations):
    """ Why the scope of a new token (#7336) is refused, or None. Projects are checked against the creator's own
    memberships only: one answer whether a project exists or not """
    if projects is None and operations is None:
        return None
    if not isinstance(projects, list) or not projects or len(projects) > SCOPED_TOKEN_MAX_PROJECTS \
            or not all(isinstance(item, int) and not isinstance(item, bool) and item > 0 for item in projects):
        return f'scope_projects must list 1 to {SCOPED_TOKEN_MAX_PROJECTS} project ids'
    if not isinstance(operations, list) or not operations or not all(item in TOKEN_OPERATIONS for item in operations):
        return f'scope_operations must list operations among {list(TOKEN_OPERATIONS)}'
    if not isinstance(expires, datetime):
        return 'A scoped token needs an expiry'
    if expires <= datetime.now() or expires > datetime.now() + timedelta(days=SCOPED_TOKEN_MAX_TTL_DAYS):
        return f'A scoped token expires within {SCOPED_TOKEN_MAX_TTL_DAYS} days'
    if set(auth.check_user_in_projects(sorted(set(projects)), user_id)) != set(projects):
        return 'A token can be scoped only to projects you are a member of'
    return None


class API(api_tools.APIBase):
    url_params = [
        '',
        '<string:uid>',
    ]

    def get(self, uid: str | None = None, **kwargs):
        user = self.module.current_user()
        #
        if not user:
            return None, 403
        #
        if uid:
            try:
                token_data = auth.get_token(uuid=uid)
            except RuntimeError:
                return {'error': f'token with uid {uid} not found'}, 400
            #
            if token_data['user_id'] != user['id']:
                return None, 403
            #
            if token_data['name'] == SYSTEM_TOKEN_NAME:
                return {'error': f'token with uid {uid} not found'}, 404
            #
            token_data['token'] = f"...{str(auth.encode_token(token_data['id']))[-7:]}"
            #
            return jsonify(token_data)
        #
        all_tokens = auth.list_tokens(user['id'])
        #
        # log.warning('Token for user %s : %s', user, all_tokens)
        # # {
        # #     "expires": null,
        # #     "id": 1,
        # #     "name": "api",
        # #     "user_id": 1,
        # #     "uuid": "62b82885-6cd8-4b07-a0c2-5fc239c22ffa"
        # # }
        #
        for i in all_tokens:
            i['token'] = f"...{str(auth.encode_token(i['id']))[-7:]}"
        #
        return jsonify(all_tokens)

    def post(self, **kwargs):
        user = self.module.current_user()
        if not user:
            return None, 403
        try:
            name = request.json['name']
        except KeyError:
            return {'error': 'Name is required'}, 400

        # Matched exactly: the name is the only thing that marks a system
        # token, so letting a user claim it would let them forge one.
        if name == SYSTEM_TOKEN_NAME:
            return {'error': f'Name "{SYSTEM_TOKEN_NAME}" is reserved'}, 400

        expires = request.json.get('expires')
        if expires:
            allowed_measures = {'days', 'weeks', 'hours', 'minutes', 'seconds'}
            try:
                assert expires['measure'] in allowed_measures
            except AssertionError:
                return {'error': f'expires measure be in {allowed_measures}'}, 400
            except KeyError:
                return {'error': f'expires must have "measure" key'}, 400

            try:
                expire_value = int(expires['value'])
            except ValueError:
                return {'error': f'expires must be int, got {type(expires)}'}, 400
            except KeyError:
                return {'error': f'expires must have "value" key'}, 400
            expires = datetime.now() + timedelta(**{expires['measure']: expire_value})

        scope_projects = request.json.get('scope_projects')
        scope_operations = request.json.get('scope_operations')
        error = _scope_error(user['id'], expires, scope_projects, scope_operations)
        if error:
            return {'error': error}, 400
        scope = {} if scope_projects is None and scope_operations is None else {
            'scope_projects': scope_projects, 'scope_operations': scope_operations,
        }

        token_id = auth.add_token(
            user_id=user['id'],
            name=name,
            expires=expires,
            **scope,
        )
        token_data = auth.get_token(token_id=token_id)
        token_data['token'] = auth.encode_token(token_id)
        return jsonify(token_data)

    def delete(self, uid: str, **kwargs):
        user = self.module.current_user()
        if not user:
            return None, 403
        try:
            token_data = auth.get_token(uuid=uid)
        except RuntimeError:
            return {'error': f'token with uid {uid} not found'}, 400
        if token_data['user_id'] != user['id']:
            return None, 403

        if token_data['name'] == SYSTEM_TOKEN_NAME:
            return {'error': 'system token cannot be deleted'}, 403

        auth.delete_token(token_id=token_data['id'])
        return None, 204
