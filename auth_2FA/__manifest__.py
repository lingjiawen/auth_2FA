# -*- coding: utf-8 -*-
{
    'name': 'two factor authentication',
    'version': '1.0',
    'category': 'Tools',
    'description': """
        双因子验证
    """,
    'author': 'misterling',
    'license': 'LGPL-3',
    'depends': ['auth_signup'],
    'data': [
        'views/res_users.xml',
        'views/view_2FA_auth.xml',
        'views/res_config_settings_views.xml',
    ],
    'external_dependencies': {
        'python': ['pyotp','pyqrcode'],
    },
    'installable': True,
    'auto_install': False,
}
