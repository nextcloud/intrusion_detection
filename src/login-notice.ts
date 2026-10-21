/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { loadState } from '@nextcloud/initial-state'

/** The notice's look, from the theme's variables only: an information card above the login box */
const STYLE = '.ids-login-notice{box-sizing:border-box;width:min(400px,calc(100vw - 32px));margin:0 auto 16px;padding:12px 16px;border-inline-start:4px solid var(--color-info-text,var(--color-info));text-align:start;line-height:1.5}'

/**
 * Show the lockdown notice above the login box. The page only loads this
 * script during a lockdown; the text comes from the server.
 *
 * @param text - The notice
 */
export function showNotice(text: string): HTMLElement | null {
	const content = document.querySelector('.guest-content')
	if (!text || !content || content.querySelector('.ids-login-notice')) {
		return null
	}
	const notice = document.createElement('div')
	notice.className = 'guest-box ids-login-notice'
	notice.setAttribute('role', 'note')
	notice.innerHTML = `<style>${STYLE}</style><span></span>`
	notice.querySelector('span')!.textContent = text
	content.prepend(notice)
	return notice
}

showNotice(loadState<string>('intrusion_detection', 'login-notice', ''))
