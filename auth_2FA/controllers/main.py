# -*- coding: utf-8 -*-
import odoo
import logging
from odoo import http, _
from odoo.addons.web.controllers.main import ensure_db, Home
from passlib.context import CryptContext
from odoo.http import request

default_crypt_context = CryptContext(
    ['pbkdf2_sha512', 'md5_crypt'],
    deprecated=['md5_crypt'],
)

_logger = logging.getLogger(__name__)


class WebHome(odoo.addons.web.controllers.main.Home):
    # Override by misterling
    @http.route('/web/login', type='http', auth="none", sitemap=False)
    def web_login(self, redirect=None, **kw):
        ensure_db()
        request.params['login_success'] = False
        if request.httprequest.method == 'GET' and redirect and request.session.uid:
            return http.redirect_with_hash(redirect)

        if not request.uid:
            request.uid = odoo.SUPERUSER_ID

        values = request.params.copy()
        try:
            values['databases'] = http.db_list()
        except odoo.exceptions.AccessDenied:
            values['databases'] = None

        if request.httprequest.method == 'POST':
            old_uid = request.uid
            try:
                request.env.cr.execute(
                    "SELECT COALESCE(company_id, NULL), COALESCE(password, '') FROM res_users WHERE login=%s",
                    [request.params['login']]
                )
                res = request.env.cr.fetchone()
                if not res:
                    raise odoo.exceptions.AccessDenied(_('Wrong login account'))
                [company_id, hashed] = res
                if company_id and request.env['res.company'].browse(company_id).is_open_2fa:
                    # 验证密码正确性
                    valid, replacement = default_crypt_context.verify_and_update(request.params['password'], hashed)
                    if replacement is not None:
                        self._set_encrypted_password(self.env.user.id, replacement)
                    if valid:
                        response = request.render('auth_2FA.2fa_auth', values)
                        response.headers['X-Frame-Options'] = 'DENY'
                        return response
                    else:
                        raise odoo.exceptions.AccessDenied()
                # 没有打开双因子验证
                uid = request.session.authenticate(request.session.db, request.params['login'],
                                                   request.params['password'])
                request.params['login_success'] = True
                return http.redirect_with_hash(self._login_redirect(uid, redirect=redirect))
            except odoo.exceptions.AccessDenied as e:
                request.uid = old_uid
                if e.args == odoo.exceptions.AccessDenied().args:
                    values['error'] = _("Wrong login/password")
                else:
                    values['error'] = e.args[0]
        else:
            if 'error' in request.params and request.params.get('error') == 'access':
                values['error'] = _('Only employee can access this database. Please contact the administrator.')

        if 'login' not in values and request.session.get('auth_login'):
            values['login'] = request.session.get('auth_login')

        if not odoo.tools.config['list_db']:
            values['disable_database_manager'] = True

        # otherwise no real way to test debug mode in template as ?debug =>
        # values['debug'] = '' but that's also the fallback value when
        # missing variables in qweb
        if 'debug' in values:
            values['debug'] = True

        response = request.render('web.login', values)
        response.headers['X-Frame-Options'] = 'DENY'
        return response

    @http.route('/web/login/2fa_auth', type='http', auth="none")
    def web_login_2fa_auth(self, redirect=None, **kw):
        ensure_db()
        request.params['login_success'] = False
        if not request.uid:
            request.uid = odoo.SUPERUSER_ID

        values = request.params.copy()
        try:
            values['databases'] = http.db_list()
        except odoo.exceptions.AccessDenied:
            values['databases'] = None
        old_uid = request.uid
        try:
            uid = request.session.authenticate(request.session.db, request.params['login'],
                                               request.params['password'])
            request.params['login_success'] = True
            return http.redirect_with_hash(self._login_redirect(uid, redirect=redirect))
        except odoo.exceptions.AccessDenied as e:
            request.uid = old_uid
            if e.args == odoo.exceptions.AccessDenied().args:
                values['error'] = _("Wrong login/password")
            else:
                values['error'] = e.args[0]
        if not odoo.tools.config['list_db']:
            values['disable_database_manager'] = True

        if 'login' not in values and request.session.get('auth_login'):
            values['login'] = request.session.get('auth_login')

        if 'debug' in values:
            values['debug'] = True

        response = request.render('auth_2FA.2fa_auth', values)
        response.headers['X-Frame-Options'] = 'DENY'
        return response