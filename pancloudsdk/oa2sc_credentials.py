from pancloud import Credentials
from requests import get


class Oa2scCredential(Credentials):
    """ Extends PanCloud SDK Credentials class at https://github.com/PaloAltoNetworks/pancloud """
    _oa2url = None
    _headers = None

    def __init__(self, oa2url, oa2lttoken, **kwargs):
        self._accessUrl = oa2url+'token'
        self._refreshUrl = oa2url+'token/refresh'
        self._headers = {'Authorization': 'Bearer {}'.format(oa2lttoken)}
        super(Oa2scCredential, self).__init__(**kwargs)

    def refresh(self, **kwargs):
        if not self.token_lock.locked():
            with self.token_lock:
                r = get(self._refreshUrl, headers=self._headers)
                self.access_token = r.json().get('response').get('access_token')
                self.write_credentials()
                return self.access_token
