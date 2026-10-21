/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

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
