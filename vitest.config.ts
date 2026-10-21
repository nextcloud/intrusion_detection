/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import vue from '@vitejs/plugin-vue'
import { resolve } from 'node:path'
import { defineConfig } from 'vitest/config'

export default defineConfig({
	plugins: [vue()],
	define: {
		appName: '"intrusion_detection"',
		appVersion: '"1.0.0"',
	},
	test: {
		include: ['src/**/*.{test,spec}.ts'],
		env: {
			LANG: 'en_US',
			TZ: 'UTC',
		},
		environment: 'jsdom',
		environmentOptions: {
			jsdom: {
				url: 'http://nextcloud.local',
			},
		},
		setupFiles: [resolve(import.meta.dirname, 'src/tests/setup.ts')],
		server: {
			deps: {
				inline: [/@nextcloud\//],
			},
		},
	},
})
