# -*- coding: utf-8 -*-
# The MIT License
# copyright@misterling(26476395@qq.com)
import base64
import pyotp
import pyqrcode
import io

from odoo import models, fields, api, _, tools
from odoo.http import request
from odoo.exceptions import AccessDenied

import logging

_logger = logging.getLogger(__name__)


class ResUsers(models.Model):
    _inherit = 'res.users'

    otp_type = fields.Selection(selection=[('time', _('Time based')), ('count', _('Counter based'))], default='time',
                                string="Type",
                                help="Type of 2FA, time = new code for each period, counter = new code for each login")
    otp_secret = fields.Char(string="Secret", size=16, help='16 character base32 secret',
                             default=lambda self: pyotp.random_base32())
    otp_counter = fields.Integer(string="Counter", default=0)
    otp_digits = fields.Integer(string="Digits", default=6, help="Length of the code")
    otp_period = fields.Integer(string="Period", default=30, help="Seconds to update code")
    otp_qrcode = fields.Binary(compute="_compute_otp_qrcode")

    otp_uri = fields.Char(compute='_compute_otp_uri', string="URI")

    # 生成二维码
    @api.model
    def create_qr_code(self, uri):
        buffer = io.BytesIO()
        qr = pyqrcode.create(uri)
        qr.png(buffer, scale=3)
        return base64.b64encode(buffer.getvalue()).decode()

    # 将二维码的值赋给otp_qrcode变量
    @api.depends('otp_uri')
    def _compute_otp_qrcode(self):
        self.ensure_one()
        self.otp_qrcode = self.create_qr_code(self.otp_uri)

    # 计算otp_uri
    @api.depends('otp_type', 'otp_period', 'otp_digits', 'otp_secret', 'company_id', 'otp_counter')
    def _compute_otp_uri(self):
        self.ensure_one()
        if self.otp_type == 'time':
            self.otp_uri = pyotp.utils.build_uri(secret=self.otp_secret, name=self.login,
                                                 issuer_name=self.company_id.name, period=self.otp_period)
        else:
            self.otp_uri = pyotp.utils.build_uri(secret=self.otp_secret, name=self.login,
                                                 initial_count=self.otp_counter, issuer_name=self.company_id.name,
                                                 digits=self.otp_digits)

    # 验证otp验证码是否正确
    @api.model
    def check_otp(self, otp_code):
        res_user = self.env['res.users'].browse(self.env.uid)
        if res_user.otp_type == 'time':
            totp = pyotp.TOTP(res_user.otp_secret)
            return totp.verify(otp_code)
        elif res_user.otp_type == 'count':
            hotp = pyotp.HOTP(res_user.otp_secret)
            # 允许用户不小心多点20次，但是已经用过的码则无法再次使用
            for count in range(res_user.otp_counter, res_user.otp_counter + 20):
                if count > 0 and hotp.verify(otp_code, count):
                    res_user.otp_counter = count + 1
                    return True
        return False

    # 覆盖原生_check_credentials，增加双因子验证
    def _check_credentials(self, password):
        super(ResUsers, self)._check_credentials(password)
        # 判断是否打开双因子验证并校验验证码
        if self.company_id.is_open_2fa and not self.check_otp(request.params.get('tfa_code')):
            # pass
            raise AccessDenied(_('Validation Code Error!'))
