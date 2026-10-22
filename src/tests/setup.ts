/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { afterEach, beforeEach } from 'vitest'

// The parts of the Nextcloud page and of a browser that jsdom does not provide.

window.OC = {
	...window.OC,
	config: {
		version: '36.0.0',
		...(window.OC?.config ?? {}),
	},
}
window.OCA = { ...window.OCA }
window.OCP = { ...window.OCP }

window._oc_webroot = ''

if (!('ResizeObserver' in window)) {
	window.ResizeObserver = class ResizeObserver {
		observe() {}
		unobserve() {}
		disconnect() {}
	}
}

// The specification lets `innerText` fall back to `textContent` for elements
// that are not rendered, see https://github.com/jsdom/jsdom/issues/1245
if (!('innerText' in HTMLElement.prototype)) {
	Object.defineProperty(HTMLElement.prototype, 'innerText', {
		configurable: true,
		get() {
			return this.textContent
		},
		set(value) {
			this.textContent = value
		},
	})
}

// There is no server: a request that a test did not mock fails at once.
// Imported late, so that a test file's mock of axios is respected.
beforeEach(async () => {
	const axios = (await import('@nextcloud/axios')).default
	if (axios.defaults !== undefined) {
		axios.defaults.adapter = () => Promise.reject(new Error('No server in tests'))
	}
})

// Every test starts without data loaded by an earlier one. Imported late, so
// that it is the module the test file uses, with its mocks.
afterEach(async () => (await import('../composables/useResource.ts')).clearResources())
