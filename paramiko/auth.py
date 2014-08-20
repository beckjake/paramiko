import copy
import threading
import weakref


from paramiko.message import Message
from paramiko.common import cMSG_SERVICE_REQUEST, cMSG_DISCONNECT, \
    DISCONNECT_SERVICE_NOT_AVAILABLE, DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE, \
    cMSG_USERAUTH_REQUEST, cMSG_SERVICE_ACCEPT, DEBUG, AUTH_SUCCESSFUL, INFO, \
    cMSG_USERAUTH_SUCCESS, cMSG_USERAUTH_FAILURE, AUTH_PARTIALLY_SUCCESSFUL, \
    cMSG_USERAUTH_INFO_REQUEST, WARNING, AUTH_FAILED, cMSG_USERAUTH_PK_OK, \
    cMSG_USERAUTH_INFO_RESPONSE, MSG_SERVICE_REQUEST, MSG_SERVICE_ACCEPT, \
    MSG_USERAUTH_REQUEST, MSG_USERAUTH_SUCCESS, MSG_USERAUTH_FAILURE, \
    MSG_USERAUTH_BANNER, MSG_USERAUTH_INFO_REQUEST, MSG_USERAUTH_INFO_RESPONSE
from paramiko.py3compat import bytestring
from paramiko.ssh_exception import SSHException, AuthenticationException, \
    BadAuthenticationType, PartialAuthentication
from paramiko.server import InteractiveQuery
from paramiko.util import get_logger


# base class, do not instantiate.
class Auth(object):
    def __init__(self):
        self.transport = None
        self.auth_event = None
        self.authenticated = False
        self.banner = None
        self.log = get_logger(__file__)

    def _request_auth(self):
        m = Message()
        m.add_byte(cMSG_SERVICE_REQUEST)
        m.add_string('ssh-userauth')
        self.log.debug('sending userauth request')
        self.transport._send_message(m)

    def _disconnect_service_not_available(self):
        m = Message()
        m.add_byte(cMSG_DISCONNECT)
        m.add_int(DISCONNECT_SERVICE_NOT_AVAILABLE)
        m.add_string('Service not available')
        m.add_string('en')
        self.log.debug('sending disconnect due to service not available')
        self.transport._send_message(m)
        self.transport.close()

    def _disconnect_no_more_auth(self):
        m = Message()
        m.add_byte(cMSG_DISCONNECT)
        m.add_int(DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE)
        m.add_string('No more auth methods available')
        m.add_string('en')
        self.log.debug('sending disconnect due to no more auth')
        self.transport._send_message(m)
        self.transport.close()

    def _get_session_blob(self, key, service, username):
        m = Message()
        m.add_string(self.transport.session_id)
        m.add_byte(cMSG_USERAUTH_REQUEST)
        m.add_string(username)
        m.add_string(service)
        m.add_string('publickey')
        m.add_boolean(True)
        m.add_string(key.get_name())
        m.add_string(key)
        return m.asbytes()

    def wait_for_response(self):
        """Wait for the transport to become active."""
        while True:
            self.auth_event.wait(0.1)
            if not self.transport.is_active():
                e = self.transport.get_exception()
                if (e is None) or isinstance(e, EOFError):
                    raise AuthenticationException('Authentication failed.')
                raise e
            if self.auth_event.isSet():
                break
        if not self.authenticated:
            e = self.transport.get_exception()
            if isinstance(e, PartialAuthentication):
                return e.allowed_types
            elif e is None:
                raise AuthenticationException('Authentication failed.')
            raise e
        return []

    def _parse_service_request(self, m):
        self._disconnect_service_not_available()

    def _auth_msg(self, m):
        raise SSHException('Unknown auth method "%s"' % self.METHOD)

    def _send_userauth_request(self):
        self.transport._log(DEBUG, 'userauth is OK')
        m = Message()
        m.add_byte(cMSG_USERAUTH_REQUEST)
        m.add_string(self.username)
        m.add_string('ssh-connection')
        m.add_string(self.METHOD)
        self._auth_msg(m)
        self.transport._send_message(m)

    def _parse_service_accept(self, m):
        service = m.get_text()
        if service == 'ssh-userauth':
            self._send_userauth_request()
        else:
            self.transport._log(DEBUG, 'Service request "%s" accepted (?)' % service)

    def _send_auth_result(self, username, method, result):
        # okay, send result
        m = Message()
        if result == AUTH_SUCCESSFUL:
            self.transport._log(INFO, 'Auth granted (%s).' % method)
            m.add_byte(cMSG_USERAUTH_SUCCESS)
            self.authenticated = True
        else:
            self.transport._log(INFO, 'Auth rejected (%s).' % method)
            m.add_byte(cMSG_USERAUTH_FAILURE)
            m.add_string(self.transport.server_object.get_allowed_auths(username))
            if result == AUTH_PARTIALLY_SUCCESSFUL:
                m.add_boolean(True)
            else:
                m.add_boolean(False)
                self.auth_fail_count += 1
        self.transport._send_message(m)
        if self.auth_fail_count >= 10:
            self._disconnect_no_more_auth()
        if result == AUTH_SUCCESSFUL:
            self.transport._auth_trigger()

    def _interactive_query(self, q):
        # make interactive query instead of response
        m = Message()
        m.add_byte(cMSG_USERAUTH_INFO_REQUEST)
        m.add_string(q.name)
        m.add_string(q.instructions)
        m.add_string(bytes())
        m.add_int(len(q.prompts))
        for p in q.prompts:
            m.add_string(p[0])
            m.add_boolean(p[1])
        self.transport._send_message(m)

    def _parse_userauth_request(self, m):
        # er, uh... what?
        m = Message()
        m.add_byte(cMSG_USERAUTH_FAILURE)
        m.add_string('none')
        m.add_boolean(False)
        self.transport._send_message(m)
        return
        
    def _parse_userauth_success(self, m):
        self.transport._log(INFO, 'Authentication (%s) successful!' % self.METHOD)
        self.authenticated = True
        self.transport._auth_trigger()
        if self.auth_event is not None:
            self.auth_event.set()

    def _parse_userauth_failure(self, m):
        authlist = m.get_list()
        partial = m.get_boolean()
        if partial:
            self.transport._log(INFO, 'Authentication continues...')
            self.transport._log(DEBUG, 'Methods: ' + str(authlist))
            self.transport.saved_exception = PartialAuthentication(authlist)
        elif self.METHOD not in authlist:
            self.transport._log(DEBUG, 'Authentication type (%s) not permitted.' % self.METHOD)
            self.transport._log(DEBUG, 'Allowed methods: ' + str(authlist))
            self.transport.saved_exception = BadAuthenticationType('Bad authentication type', authlist)
        else:
            self.transport._log(INFO, 'Authentication (%s) failed.' % self.METHOD)
        self.authenticated = False
        if self.auth_event is not None:
            self.auth_event.set()

    def _parse_userauth_banner(self, m):
        banner = m.get_string()
        self.banner = banner
        lang = m.get_string()
        self.transport._log(INFO, 'Auth banner: %s' % banner)
    
    def _parse_userauth_info_request(self, m):
        raise SSHException('Illegal info request from server')
    
    def _parse_userauth_info_response(self, m):
        raise SSHException('Illegal info response from server')


    def handler_lookup(self, message_type):
        if message_type == MSG_SERVICE_REQUEST:
            return self._parse_service_request
        elif message_type == MSG_SERVICE_ACCEPT: 
            return self._parse_service_accept
        elif message_type == MSG_USERAUTH_REQUEST: 
            return self._parse_userauth_request
        elif message_type == MSG_USERAUTH_SUCCESS:
            return self._parse_userauth_success
        elif message_type == MSG_USERAUTH_FAILURE:
            return self._parse_userauth_failure
        elif message_type == MSG_USERAUTH_BANNER: 
            return self._parse_userauth_banner
        elif message_type == MSG_USERAUTH_INFO_REQUEST: 
            return self._parse_userauth_info_request
        elif message_type == MSG_USERAUTH_INFO_RESPONSE: 
            return self._parse_userauth_info_response
        else:
            raise KeyError(message_type)

    def abort(self):
        if self.auth_event is not None:
            self.auth_event.set()

    def authorize(self, transport, event=None):
        self.transport = weakref.proxy(transport)
        self.transport.auth_handler = self
        if (not self.transport.active) or (not self.transport.initial_kex_done):
            # we should never try to authenticate unless we're on a secure link
            raise SSHException('No existing session')
        self.auth_event = threading.Event() if event is None else event
        
        with self.transport.lock:
            self._request_auth()
        
        if event is None:
            return self.wait_for_response()
        else:
            # caller will ask later when auth triggers the event
            return []



class PasswordAuth(Auth):
    METHOD = 'password'
    def __init__(self, username, password, fallback=False):
        super(PasswordAuth, self).__init__()
        self.username = username
        self.password = password
        self.fallback = False

    def _auth_msg(self, m):
        m.add_boolean(False)
        password = bytestring(self.password)
        m.add_string(password)


    def authorize(self, transport, event=None):
        try:
            return super(PasswordAuth, self).authorize(transport, event)
        except BadAuthenticationType as e:
            # if password auth isn't allowed, but keyboard-interactive *is*, try to fudge it
            if self.fallback or 'keyboard-interactive' not in e.allowed_types:
                raise
            try:
                auth = InteractiveAuth.from_password(self.username, self.password)
                return auth.authorize(transport, event)
            except SSHException:
                # attempt failed; just raise the original exception
                raise e


class PkeyAuth(Auth):
    METHOD = 'publickey'
    def __init__(self, username, pkey, password=None):
        super(PkeyAuth, self).__init__()
        self.username = username
        self.private_key = pkey
        self.password = password

    def _logmsg(self, log):
        log(DEBUG, 'Trying SSH key %s' % hexlify(self.pkey.get_fingerprint()))

    def _auth_msg(self, m):
        m.add_boolean(True)
        m.add_string(self.private_key.get_name())
        m.add_string(self.private_key)
        blob = self._get_session_blob(self.private_key, 'ssh-connection', self.username)
        sig = self.private_key.sign_ssh_data(blob)
        m.add_string(sig)


class NoAuth(Auth):
    METHOD = 'none'
    def __init__(self, username):
        super(NoAuth, self).__init__()
        self.username = username

    def _auth_msg(self, m):
        pass


class InteractiveAuth(Auth):
    METHOD = 'keyboard-interactive'
    def __init__(self, username, handler, submethods=''):
        super(InteractiveAuth, self).__init__()
        self.username = username
        self.handler = handler
        self.submethods = submethods

    def authorize(self, transport, event=None):
        return super(InteractiveAuth, self).authorize(transport, None)

    def _parse_userauth_info_request(self, m):
        title = m.get_text()
        instructions = m.get_text()
        m.get_binary()  # lang
        prompts = m.get_int()
        prompt_list = []
        for i in range(prompts):
            prompt_list.append((m.get_text(), m.get_boolean()))
        response_list = self.handler(title, instructions, prompt_list)
        
        m = Message()
        m.add_byte(cMSG_USERAUTH_INFO_RESPONSE)
        m.add_int(len(response_list))
        for r in response_list:
            m.add_string(r)
        self.transport._send_message(m)

    @classmethod
    def from_password(cls, username, password):
        def handler(title, instructions, fields):
                    if len(fields) > 1:
                        raise SSHException('Fallback authentication failed.')
                    if len(fields) == 0:
                        # for some reason, at least on os x, a 2nd request will
                        # be made with zero fields requested.  maybe it's just
                        # to try to fake out automated scripting of the exact
                        # type we're doing here.  *shrug* :)
                        return []
                    return [password]
        return cls(username, handler)

    def _auth_msg(self, m):
        m.add_string('')
        m.add_string(self.submethods)


class PasswordAuthList(PasswordAuth):
    def __init__(self, attempts):
        self.attempts = attempts
    


class ServerAuth(Auth):
    def __init__(self, transport):
        super(ServerAuth, self).__init__()
        self.transport = transport
        self.username = None
        self.auth_fail_count = 0

    def _parse_service_request(self, m):
        service = m.get_text()
        if service == 'ssh-userauth':
            # accepted
            m = Message()
            m.add_byte(cMSG_SERVICE_ACCEPT)
            m.add_string(service)
            self.transport._send_message(m)
            return
        else:
            self._disconnect_service_not_available()

    def _parse_auth_password(self, username, m):
        changereq = m.get_boolean()
        password = m.get_binary()
        try:
            password = password.decode('UTF-8')
        except UnicodeError:
            # some clients/servers expect non-utf-8 passwords!
            # in this case, just return the raw byte string.
            pass
        if changereq:
            # always treated as failure, since we don't support changing passwords, but collect
            # the list of valid auth types from the callback anyway
            self.transport._log(DEBUG, 'Auth request to change passwords (rejected)')
            newpassword = m.get_binary()
            try:
                newpassword = newpassword.decode('UTF-8', 'replace')
            except UnicodeError:
                pass
            return AUTH_FAILED
        else:
            return self.transport.server_object.check_auth_password(username, password)

    def _send_pkey_ok(self):
        m = Message()
        m.add_byte(cMSG_USERAUTH_PK_OK)
        m.add_string(keytype)
        m.add_string(keyblob)
        self.transport._send_message(m)

    def _key_check(self, username, key, service, m):
        sig = Message(m.get_binary())
        blob = self._get_session_blob(key, service, username)
        return key.verify_ssh_sig(blob, sig)

    def _parse_auth_pkey(self, username, service, m):
        sig_attached = m.get_boolean()
        keytype = m.get_text()
        keyblob = m.get_binary()
        try:
            key = self.transport._key_info[keytype](Message(keyblob))
        except SSHException as e:
            self.transport._log(INFO, 'Auth rejected: public key: %s' % str(e))
            key = None
        except:
            self.transport._log(INFO, 'Auth rejected: unsupported or mangled public key')
            key = None
        if key is None:
            self._disconnect_no_more_auth()
            return
        # first check if this key is okay... if not, we can skip the verify
        result = self.transport.server_object.check_auth_publickey(username, key)
        if result == AUTH_FAILED:
            return result

        # key is okay, verify it
        if not sig_attached:
            # client wants to know if this key is acceptable, before it
            # signs anything...  send special "ok" message
            self._send_pkey_ok()
            return
        if not self._key_check(username, key, service, m):
            self.transport._log(INFO, 'Auth rejected: invalid signature')
            return AUTH_FAILED
        return result

    def _parse_auth_interactive(self, username, m):
            lang = m.get_string()
            submethods = m.get_string()
            result = self.transport.server_object.check_auth_interactive(username, submethods)
            if isinstance(result, InteractiveQuery):
                # make interactive query instead of response
                self._interactive_query(result)
                return
            return result

    def _parse_userauth_info_response(self, m):
        n = m.get_int()
        responses = []
        for i in range(n):
            responses.append(m.get_text())
        result = self.transport.server_object.check_auth_interactive_response(responses)
        if isinstance(type(result), InteractiveQuery):
            # make interactive query instead of response
            self._interactive_query(result)
            return
        self._send_auth_result(self.username, 'keyboard-interactive', result)

    def _parse_userauth_request(self, m):
        if self.authenticated:
            # ignore
            return
        username = m.get_text()
        service = m.get_text()
        method = m.get_text()
        self.transport._log(DEBUG, 'Auth request (type=%s) service=%s, username=%s' % (method, service, username))
        
        if service != 'ssh-connection':
            self._disconnect_service_not_available()
            return
        if (self.username is not None) and (self.username != username):
            self.transport._log(WARNING, 'Auth rejected because the client attempted to change username in mid-flight')
            self._disconnect_no_more_auth()
            return
        self.username = username

        if method == 'none':
            result = self.transport.server_object.check_auth_none(username)
        elif method == 'password':
            result = self._parse_auth_password(username, m) 
        elif method == 'publickey':
            result = self._parse_auth_pkey(username, service, m)
        elif method == 'keyboard-interactive':
            result = self._parse_auth_interactive(username, m)
        else:
            result = self.transport.server_object.check_auth_none(username)
        # okay, send result
        if result is not None:
            self._send_auth_result(username, method, result)

