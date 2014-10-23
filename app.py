#!/usr/bin/env python
"""
A self-service password change script for Samba 4 AD DC and Google Apps.

By: Nick Semenkovich <semenko@alum.mit.edu> http://nick.semenkovich.com

License: MIT

Google auth code derived from Flask-Oauthlib / Bruno Rocha / https://github.com/rochacbruno
"""

from flask import Flask, redirect, render_template, url_for, session, request, Response, jsonify
from flask_oauthlib.client import OAuth
import struct
import socket

app = Flask(__name__, static_url_path='')
app.config.from_pyfile('secrets.cfg') # Add your Google ID & Secret there.

RESTRICTED_DOMAIN = app.config.get('RESTRICTED_DOMAIN') # Require this domain for authentication
SITE_NAME = app.config.get('SITE_NAME')


app.secret_key = 'development'
oauth = OAuth(app)

google = oauth.remote_app(
    'google',
    consumer_key=app.config.get('GOOGLE_ID'),
    consumer_secret=app.config.get('GOOGLE_SECRET'),
    request_token_params={
        'scope': ['https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)


@app.route('/')
def index():
    if 'google_token' in session:
        me = google.get('userinfo')
        try:
            if me.data[u'hd'] != RESTRICTED_DOMAIN or me.data[u'verified_email'] != True:
                session.pop('google_token', None)
                return render_template('error.html', domain=RESTRICTED_DOMAIN, site_name=SITE_NAME)
        except KeyError:
            session.pop('google_token', None)
            return render_template('_base.html', site_name=SITE_NAME)
        # return jsonify({"data": me.data})
        # , computer_target=app.config.get('COMPUTER_MAP')[str(me.data[u'email'])]
        return render_template('authenticated.html', auth_data=me.data, site_name=SITE_NAME)
    return render_template('_base.html', site_name=SITE_NAME)

@app.route('/computer.rdp')
def getrdp():
    if 'google_token' in session:
        me = google.get('userinfo')
        try:
            if me.data[u'hd'] != RESTRICTED_DOMAIN or me.data[u'verified_email'] != True:
                session.pop('google_token', None)
                return redirect(url_for('logout'))
        except KeyError:
            session.pop('google_token', None)
            return render_template('_base.html', site_name=SITE_NAME)

        try:
            target = request.args.get('target')  # TODO: Sanitize this.
            target_hosts = {'hostname': app.config.get('DOMAIN_SECRET'), 'port': app.config.get('PORT_MAP')[target]}
        except KeyError:
            return redirect(url_for('logout'))

        return Response(RDP_FILE_TEMPLATE % target_hosts,
                        mimetype="application/rdp",
                        headers={"Content-Disposition":
                                     "attachment; filename=computer.rdp"})
    return redirect(url_for('logout'))

@app.route('/login')
def login():
    return google.authorize(callback=url_for('authorized', _external=True))


@app.route('/logout')
def logout():
    session.pop('google_token', None)
    return redirect(url_for('index'))


@app.route('/login/authorized')
@google.authorized_handler
def authorized(resp):
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    session['google_token'] = (resp['access_token'], '')
    #me = google.get('userinfo')
    return redirect(url_for('index'))
    #return jsonify({"data": me.data})


@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')


# Send a WOL packet
def wake_on_lan(macaddress):
    """ Switches on remote computers using WOL. """

    # Check macaddress format and try to compensate.
    if len(macaddress) == 12:
        pass
    elif len(macaddress) == 12 + 5:
        sep = macaddress[2]
        macaddress = macaddress.replace(sep, '')
    else:
        raise ValueError('Incorrect MAC address format')

    # Pad the synchronization stream.
    data = ''.join(['FFFFFFFFFFFF', macaddress * 20])
    send_data = ''

    # Split up the hex values and pack.
    for i in range(0, len(data), 2):
        send_data = ''.join([send_data,
                             struct.pack('B', int(data[i: i + 2], 16))])

    # Broadcast it to the LAN.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.sendto(send_data, ('<broadcast>', 7))


if __name__ == '__main__':
    app.debug = True
    app.run()
else:
    # Secure app in prod
    app.config['SESSION_COOKIE_SECURE'] = True
