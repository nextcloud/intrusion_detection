/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { createAppConfig } from '@nextcloud/vite-config'
import { resolve } from 'node:path'

// Without a prefix the entries are emitted as `js/<entry>.mjs` and
// `css/<entry>.css`, the files `Util::addScript()` and `Util::addStyle()` load.
export default createAppConfig({
	'settings-admin': resolve(import.meta.dirname, 'src', 'settings-admin.ts'),
	verify: resolve(import.meta.dirname, 'src', 'verify.ts'),
	'secure-account': resolve(import.meta.dirname, 'src', 'secure-account.ts'),
	'settings-personal': resolve(import.meta.dirname, 'src', 'settings-personal.ts'),
}, {
	assetsPrefix: '',
	createEmptyCSSEntryPoints: true,
	extractLicenseInformation: {
		includeSourceMaps: true,
	},
})
