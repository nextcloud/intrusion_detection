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
		name: 'intrusion_detection/translate-as-text',
		ignores: ['src/utils/l10n.ts'],
		rules: {
			'no-restricted-imports': ['error', {
				paths: [{
					name: '@nextcloud/l10n',
					importNames: ['t', 'n', 'translate', 'translatePlural'],
					message: 'Import t and n from src/utils/l10n.ts: they translate for text output, without HTML escaping.',
				}],
			}],
		},
	},

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
