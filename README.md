[DEPRECATED] Self-service Password Portal
============================================

Provide a simple self-service UI &amp; script to sync passwords on a Samba4 AD DC with Google Apps.

This solves the issue of syncing Samba AD DC passwords to Google Apps. Unfortunately, Google Directory Sync is challenging to configure with Samba, and the classic "unix password sync" and "passwd program" options in Samba 4 no longer work.


===
User workflow:

1. Sign-in to webapp with Google Apps domain credentials
2. Change password in web app
3. Web app updates Google (via Directory API) and Samba AD DC.


===

How to install:

1. `pip install Flask-OAuthlib`
2. Install the app! You can roughly do something like:
    adduser password-change-user
    chsh -s /bin/false password-change-user
    # Other security hardening here
    cd /home/password-change-user/
    git clone THIS_REPO
3. Configure apache. You can add something like this to a VirtualHost.

