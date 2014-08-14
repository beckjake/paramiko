# Copyright (C) 2006-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
SSH client & key policies
"""

from binascii import hexlify
from contextlib import contextmanager
import getpass
import os
import socket
import warnings

from paramiko.agent import Agent
from paramiko.common import DEBUG
from paramiko.config import SSH_PORT
from paramiko.dsskey import DSSKey
from paramiko.hostkeys import HostKeys
from paramiko.py3compat import string_types, raise_saved
from paramiko.resource import ResourceManager
from paramiko.rsakey import RSAKey
from paramiko.ssh_exception import SSHException, BadHostKeyException
from paramiko.transport import Transport
from paramiko.util import retry_on_signal


def get_socket(hostname, port=SSH_PORT, timeout=None):
    """Get a connected object with the appropriate timeout.

    :param str hostname: the server to connect to
    :param int port: the server port to connect to
    :param float timeout: an optional timeout (in seconds) for the TCP connect
    :return: A socket connected to the host and port.

    :raises socket.error: if a socket error occurred while connecting
    """
    for (family, socktype, proto, canonname, sockaddr) in socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM):
        if socktype == socket.SOCK_STREAM:
            af = family
            addr = sockaddr
            break
    else:
        # some OS like AIX don't indicate SOCK_STREAM support, so just guess. :(
        af, _, _, _, addr = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    sock = socket.socket(af, socket.SOCK_STREAM)
    if timeout is not None:
        try:
            sock.settimeout(timeout)
        except:
            pass
    retry_on_signal(lambda: sock.connect(addr))
    return sock


class ExceptContext(object):
    """Context manager to grab exceptions."""
    def __init__(self, depth=0):
        self.saved_exc = None
        self.depth = depth

    def __enter__(self):
        self.depth += 1
        return self

    def __exit__(self, type, value, traceback):

        if type:
            self.saved_exc = (type, value, traceback)
        self.depth -= 1
        if self.depth > 0 or self.saved_exc is None:
            return True

        raise_saved(*self.saved_exc)




class SSHClient (object):
    """
    A high-level representation of a session with an SSH server.  This class
    wraps `.Transport`, `.Channel`, and `.SFTPClient` to take care of most
    aspects of authenticating and opening channels.  A typical use case is::

        client = SSHClient()
        client.load_system_host_keys()
        client.connect('ssh.example.com')
        stdin, stdout, stderr = client.exec_command('ls -l')

    You may pass in explicit overrides for authentication and server host key
    checking.  The default mechanism is to try to use local key files or an
    SSH agent (if one is running).

    .. versionadded:: 1.6
    """
    Transport = Transport
    KEY_CLASSES = (RSAKey, DSSKey)
    def __init__(self):
        """
        Create a new SSHClient.
        """
        self._system_host_keys = HostKeys()
        self._host_keys = HostKeys()
        self._host_keys_filename = None
        self._log_channel = None
        self._policy = RejectPolicy()
        self._transport = None
        self._agent = None

    def load_system_host_keys(self, filename=None):
        """
        Load host keys from a system (read-only) file.  Host keys read with
        this method will not be saved back by `save_host_keys`.

        This method can be called multiple times.  Each new set of host keys
        will be merged with the existing set (new replacing old if there are
        conflicts).

        If ``filename`` is left as ``None``, an attempt will be made to read
        keys from the user's local "known hosts" file, as used by OpenSSH,
        and no exception will be raised if the file can't be read.  This is
        probably only useful on posix.

        :param str filename: the filename to read, or ``None``

        :raises IOError:
            if a filename was provided and the file could not be read
        """
        if filename is None:
            # try the user's .ssh key file, and mask exceptions
            filename = os.path.expanduser('~/.ssh/known_hosts')
            try:
                self._system_host_keys.load(filename)
            except IOError:
                pass
            return
        self._system_host_keys.load(filename)

    def load_host_keys(self, filename):
        """
        Load host keys from a local host-key file.  Host keys read with this
        method will be checked after keys loaded via `load_system_host_keys`,
        but will be saved back by `save_host_keys` (so they can be modified).
        The missing host key policy `.AutoAddPolicy` adds keys to this set and
        saves them, when connecting to a previously-unknown server.

        This method can be called multiple times.  Each new set of host keys
        will be merged with the existing set (new replacing old if there are
        conflicts).  When automatically saving, the last hostname is used.

        :param str filename: the filename to read

        :raises IOError: if the filename could not be read
        """
        self._host_keys_filename = filename
        self._host_keys.load(filename)

    def save_host_keys(self, filename):
        """
        Save the host keys back to a file.  Only the host keys loaded with
        `load_host_keys` (plus any added directly) will be saved -- not any
        host keys loaded with `load_system_host_keys`.

        :param str filename: the filename to save to

        :raises IOError: if the file could not be written
        """

        # update local host keys from file (in case other SSH clients
        # have written to the known_hosts file meanwhile.
        if self._host_keys_filename is not None:
            self.load_host_keys(self._host_keys_filename)

        with open(filename, 'w') as f:
            for hostname, keys in self._host_keys.items():
                for keytype, key in keys.items():
                    f.write('%s %s %s\n' % (hostname, keytype, key.get_base64()))

    def get_host_keys(self):
        """
        Get the local `.HostKeys` object.  This can be used to examine the
        local host keys or change them.

        :return: the local host keys as a `.HostKeys` object.
        """
        return self._host_keys

    def set_log_channel(self, name):
        """
        Set the channel for logging.  The default is ``"paramiko.transport"``
        but it can be set to anything you want.

        :param str name: new channel name for logging
        """
        self._log_channel = name

    def set_missing_host_key_policy(self, policy):
        """
        Set the policy to use when connecting to a server that doesn't have a
        host key in either the system or local `.HostKeys` objects.  The
        default policy is to reject all unknown servers (using `.RejectPolicy`).
        You may substitute `.AutoAddPolicy` or write your own policy class.

        :param .MissingHostKeyPolicy policy:
            the policy to use when receiving a host key from a
            previously-unknown server
        """
        self._policy = policy

    def _attach_transport(self, sock, compress=False):
        """Attach a transport object via the socket, start it, and register it
        to the resource manager.

        :param socket.socket sock: The socket to use.
        :param bool compress: set to True to turn on compression
        :return: A started `.Transport` that is set to self._transport
        """
        t = self._transport = self.Transport(sock)
        t.use_compression(compress=compress)
        if self._log_channel is not None:
            t.set_log_channel(self._log_channel)
        t.start_client()
        ResourceManager.register(self, t)
        return t

    def _key_check(self, hostname, port):
        """
        The server's host key is checked against the system host keys
        (see `load_system_host_keys`) and any local host keys
        (`load_host_keys`).  If the server's hostname is not found in either
        set of host keys, the missing host key policy is used
        (see `set_missing_host_key_policy`).  The default policy is to reject
        the key and raise an `.SSHException`.

        :param str hostname: the server to connect to
        :param int port: the server port to connect to

        :raises BadHostKeyException: if the server's host key could not be
            verified
        :raises SSHException: if the missing_host_key policy is violated
        """
        if port == SSH_PORT:
            server_hostkey_name = hostname
        else:
            server_hostkey_name = "[%s]:%d" % (hostname, port)

        server_key = self._transport.get_remote_server_key()
        keytype = server_key.get_name()
        our_server_key = self._system_host_keys.get(server_hostkey_name, {}).get(keytype, None)
        if our_server_key is None:
            our_server_key = self._host_keys.get(server_hostkey_name, {}).get(keytype, None)
        if our_server_key is None:
            # will raise exception if the key is rejected; let that fall out
            self._policy.missing_host_key(self, server_hostkey_name, server_key)
            # if the callback returns, assume the key is ok
            our_server_key = server_key

        return server_key == our_server_key

        if server_key != our_server_key:
            raise BadHostKeyException(hostname, server_key, our_server_key)


    def connect(self, hostname, port=SSH_PORT, username=None, password=None, pkey=None,
                key_filename=None, timeout=None, allow_agent=True, look_for_keys=True,
                compress=False, sock=None):
        """
        Connect to an SSH server and authenticate to it.  The server's host key
        is checked against the system host keys (see `load_system_host_keys`)
        and any local host keys (`load_host_keys`).  If the server's hostname
        is not found in either set of host keys, the missing host key policy
        is used (see `set_missing_host_key_policy`).  The default policy is
        to reject the key and raise an `.SSHException`.

        Authentication is attempted in the following order of priority:

            - The ``pkey`` or ``key_filename`` passed in (if any)
            - Any key we can find through an SSH agent
            - Any "id_rsa" or "id_dsa" key discoverable in ``~/.ssh/``
            - Plain username/password auth, if a password was given

        If a private key requires a password to unlock it, and a password is
        passed in, that password will be used to attempt to unlock the key.

        :param str hostname: the server to connect to
        :param int port: the server port to connect to
        :param str username:
            the username to authenticate as (defaults to the current local
            username)
        :param str password:
            a password to use for authentication or for unlocking a private key
        :param .PKey pkey: an optional private key to use for authentication
        :param str key_filename:
            the filename, or list of filenames, of optional private key(s) to
            try for authentication
        :param float timeout: an optional timeout (in seconds) for the TCP connect
        :param bool allow_agent: set to False to disable connecting to the SSH agent
        :param bool look_for_keys:
            set to False to disable searching for discoverable private key
            files in ``~/.ssh/``
        :param bool compress: set to True to turn on compression
        :param socket sock:
            an open socket or socket-like object (such as a `.Channel`) to use
            for communication to the target host

        :raises BadHostKeyException: if the server's host key could not be
            verified
        :raises AuthenticationException: if authentication failed
        :raises SSHException: if there was any other error connecting or
            establishing an SSH session
        :raises socket.error: if a socket error occurred while connecting
        """
        if not sock:
            sock = get_socket(hostname, port, timeout)

        t = self._attach_transport(sock)
        self._key_check(hostname, port)

        if username is None:
            username = getpass.getuser()

        if key_filename is None:
            key_filenames = []
        elif isinstance(key_filename, string_types):
            key_filenames = [key_filename]
        else:
            key_filenames = key_filename
        self._auth(username, password, pkey, key_filenames, allow_agent, look_for_keys)

    def close(self):
        """
        Close this SSHClient and its underlying `.Transport`.
        """
        if self._transport is None:
            return
        self._transport.close()
        self._transport = None

        if self._agent is not None:
            self._agent.close()
            self._agent = None

    def exec_command(self, command, bufsize=-1, timeout=None, get_pty=False):
        """
        Execute a command on the SSH server.  A new `.Channel` is opened and
        the requested command is executed.  The command's input and output
        streams are returned as Python ``file``-like objects representing
        stdin, stdout, and stderr.

        :param str command: the command to execute
        :param int bufsize:
            interpreted the same way as by the built-in ``file()`` function in
            Python
        :param int timeout:
            set command's channel timeout. See `Channel.settimeout`.settimeout
        :return:
            the stdin, stdout, and stderr of the executing command, as a
            3-tuple

        :raises SSHException: if the server fails to execute the command
        """
        chan = self._transport.open_session()
        if get_pty:
            chan.get_pty()
        chan.settimeout(timeout)
        chan.exec_command(command)
        stdin = chan.makefile('wb', bufsize)
        stdout = chan.makefile('r', bufsize)
        stderr = chan.makefile_stderr('r', bufsize)
        return stdin, stdout, stderr

    def invoke_shell(self, term='vt100', width=80, height=24, width_pixels=0,
                     height_pixels=0):
        """
        Start an interactive shell session on the SSH server.  A new `.Channel`
        is opened and connected to a pseudo-terminal using the requested
        terminal type and size.

        :param str term:
            the terminal type to emulate (for example, ``"vt100"``)
        :param int width: the width (in characters) of the terminal window
        :param int height: the height (in characters) of the terminal window
        :param int width_pixels: the width (in pixels) of the terminal window
        :param int height_pixels: the height (in pixels) of the terminal window
        :return: a new `.Channel` connected to the remote shell

        :raises SSHException: if the server fails to invoke a shell
        """
        chan = self._transport.open_session()
        chan.get_pty(term, width, height, width_pixels, height_pixels)
        chan.invoke_shell()
        return chan

    def open_sftp(self):
        """
        Open an SFTP session on the SSH server.

        :return: a new `.SFTPClient` session object
        """
        return self._transport.open_sftp_client()

    def get_transport(self):
        """
        Return the underlying `.Transport` object for this SSH connection.
        This can be used to perform lower-level tasks, like opening specific
        kinds of channels.

        :return: the `.Transport` for this connection
        """
        return self._transport

    def _pkey_auth(self, username, password, pkey):
        """Try to authenticate with the public key.

        :param str username: the username to authenticate as
        :param str password: a password to use for two-factor authentication
        :param .PKey pkey: an optional private key to use for authentication
        :return bool: True if two-factor authenticatation is required
        :raises SSHException: If a password is required but not provided
        """
        self._log(DEBUG, 'Trying SSH key %s' % hexlify(pkey.get_fingerprint()))
        allowed_types = self._transport.auth_publickey(username, pkey)
        if (allowed_types == ['password']):
            self._transport.auth_password(username, password)
        else:
            raise SSHException('Two-factor authentication requires a password')

    def _keyfile_lookups(self, exc_context, password, key_filenames):
        """
        :param str password: The password to use for unlocking the private key
        :param list key_filenames: A list of filenames to look for keys in
        """
        with exc_context:
            for key_filename, pkey_class in itertools.product(key_filenames, self.KEY_CLASSES):
                with exc_context:
                    key = pkey_class.from_private_key_file(key_filename, password)
                    self._log(DEBUG, 'Trying key %s from %s' % (hexlify(key.get_fingerprint()), key_filename))
                    yield key

    def _agent_lookup(self, exc_context):
        if self._agent is None:
            self._agent = Agent()
        with exc_context:
            for pkey in self._agent.get_keys():
                with exc_context:
                    self._log(DEBUG, 'Trying SSH agent key %s' % hexlify(pkey.get_fingerprint()))
                    yield pkey

    def _local_ssh_keys(self, exc_context, username, password):
        rsa_key_posix = RSAKey, os.path.expanduser('~/.ssh/id_rsa')
        dsa_key_posix = DSSKey, os.path.expanduser('~/.ssh/id_dsa')
        rsa_key_win = RSAKey, os.path.expanduser('~/ssh/id_rsa')
        dsa_key_win = DSSKey, os.path.expanduser('~/ssh/id_dsa')
        for pkey_class, filename in (rsa_key_posix, dsa_key_posix, rsa_key_win, dsa_key_win):
            if not os.path.isfile(filename):
                continue
            with exc_context:
                key = pkey_class.from_private_key_file(filename, password)
                self._log(DEBUG, 'Trying discovered key %s in %s' % (hexlify(key.get_fingerprint()), filename))
                yield key

    def auth(self, authorizers):
        """Authorize through a variety of methods

        Each argument is a candidate Auth object.
        """
        with ExceptContext() as exc_context:
            for authorizer in authorizers:
                with exc_context:
                    authorizer.authorize(transport)


    def _auth(self, username, password, pkey, key_filenames, agent, look_for_keys):
        """
        Try, in order:

            - The key passed in, if one was passed in.
            - Any key we can find through an SSH agent (if allowed).
            - Any "id_rsa" or "id_dsa" key discoverable in ~/.ssh/ (if allowed).
            - Plain username/password auth, if a password was given.

        (The password might be needed to unlock a private key, or for
        two-factor authentication [for which it is required].)
        """
        #exc_context = ExceptContext(depth=1)
        with ExceptContext() as exc_context:
            if pkey:
                with exc_context:
                    self._pkey_auth(username, password, pkey)
                    return
            for pkey in self._keyfile_lookups(exc_context, password, key_filenames):
                with exc_context:
                    self._pkey_auth(username, password, pkey)
                    return
            if allow_agent:
                for pkey in self._agent_lookup(exc_context):
                    with exc_context:
                        self._pkey_auth(username, password, pkey)
                        return
            if look_for_keys:
                with exc_context:
                    for pkey in self._local_ssh_keys(exc_context, username, password):
                        self._pkey_auth(username, password, pkey)
                        return

            if password is not None:
                with exc_context:
                    self._transport.auth_password(username, password)
                    return

        raise SSHException('No authentication methods available')

    def _log(self, level, msg):
        self._transport._log(level, msg)


class MissingHostKeyPolicy (object):
    """
    Interface for defining the policy that `.SSHClient` should use when the
    SSH server's hostname is not in either the system host keys or the
    application's keys.  Pre-made classes implement policies for automatically
    adding the key to the application's `.HostKeys` object (`.AutoAddPolicy`),
    and for automatically rejecting the key (`.RejectPolicy`).

    This function may be used to ask the user to verify the key, for example.
    """

    def missing_host_key(self, client, hostname, key):
        """
        Called when an `.SSHClient` receives a server key for a server that
        isn't in either the system or local `.HostKeys` object.  To accept
        the key, simply return.  To reject, raised an exception (which will
        be passed to the calling application).
        """
        pass


class AutoAddPolicy (MissingHostKeyPolicy):
    """
    Policy for automatically adding the hostname and new host key to the
    local `.HostKeys` object, and saving it.  This is used by `.SSHClient`.
    """

    def missing_host_key(self, client, hostname, key):
        client._host_keys.add(hostname, key.get_name(), key)
        if client._host_keys_filename is not None:
            client.save_host_keys(client._host_keys_filename)
        client._log(DEBUG, 'Adding %s host key for %s: %s' %
                    (key.get_name(), hostname, hexlify(key.get_fingerprint())))


class RejectPolicy (MissingHostKeyPolicy):
    """
    Policy for automatically rejecting the unknown hostname & key.  This is
    used by `.SSHClient`.
    """

    def missing_host_key(self, client, hostname, key):
        client._log(DEBUG, 'Rejecting %s host key for %s: %s' %
                    (key.get_name(), hostname, hexlify(key.get_fingerprint())))
        raise SSHException('Server %r not found in known_hosts' % hostname)


class WarningPolicy (MissingHostKeyPolicy):
    """
    Policy for logging a Python-style warning for an unknown host key, but
    accepting it. This is used by `.SSHClient`.
    """
    def missing_host_key(self, client, hostname, key):
        warnings.warn('Unknown %s host key for %s: %s' %
                      (key.get_name(), hostname, hexlify(key.get_fingerprint())))
