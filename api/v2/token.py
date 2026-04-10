from datetime import datetime, timedelta

from flask import jsonify, request
from pylon.core.tools import log

from tools import auth

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

        token_id = auth.add_token(
            user_id=user['id'],
            name=name,
            expires=expires,
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

        auth.delete_token(token_id=token_data['id'])
        return None, 204
