import flask
from pylon.core.tools import web, log


class RPC:
    @web.rpc('auth_main_current_user', 'current_user')
    def current_user(self, auth_data=None) -> dict:
        """ Get current user """
        if auth_data is None:
            auth_data = flask.g.auth

        if hasattr(auth_data, 'user'):
            return auth_data.user

        if auth_data.type == "user":
            user_data = self.get_user(auth_data.id)
            auth_data.user = user_data
            return user_data
        elif auth_data.type == "token":
            token = self.get_token(auth_data.id)
            user_data = self.get_user(token["user_id"])
            auth_data.user = user_data
            return user_data
        else:
            # Public
            return {
                "id": None, "email": "public@platform.user", "name": "Public"
            }
