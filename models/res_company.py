# -*- coding: utf-8 -*-
# The MIT License
# copyright@misterling(26476395@qq.com)

from odoo import models, api, fields


class ResCompany(models.Model):
    _inherit = "res.company"

    is_open_2fa = fields.Boolean(string="Open 2FA", default=False)
