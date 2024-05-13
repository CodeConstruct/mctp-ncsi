# SPDX-License-Identifier: GPL-2.0
#
project(
    'mctp-ncsi', 'c',
    meson_version: '>= 0.59.0',
    version: 'v1.1',
    license: 'GPLv2',
    default_options: [
        'warning_level=2',
    ],
)

cc = meson.get_compiler('c')

executable('mctp-ncsi',
    sources: ['src/mctp-ncsi.c'],
    install: true,
)
