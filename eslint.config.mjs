/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { recommended } from '@nextcloud/eslint-config'
import { defineConfig } from 'eslint/config'

export default defineConfig([
	{
		linterOptions: {
			reportUnusedDisableDirectives: 'error',
			reportUnusedInlineConfigs: 'error',
		},
	},

	...recommended,

	{
		name: 'intrusion_detection/ignored-files',
		ignores: [
			'composer/',
			'css/',
			'js/',
			'l10n/',
			'src/types/openapi/',
			'tests/',
			'vendor/',
		],
	},
])
