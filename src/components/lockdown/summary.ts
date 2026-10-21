/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { getCanonicalLocale, t } from '@nextcloud/l10n'
import { APP_ID } from '../../utils/format.ts'

/** Who started or ended a lockdown that no person started or ended */
export const AUTOMATIC = 'automatic'
export const OCC = 'occ'

/**
 * The end of a lockdown, short: "18:00" today, "Tue 08:00" on another day.
 *
 * @param timestamp - Seconds
 * @param now - Milliseconds, for tests
 */
export function formatUntil(timestamp: number, now = Date.now()): string {
	const date = new Date(timestamp * 1000)
	const sameDay = date.toDateString() === new Date(now).toDateString()
	return date.toLocaleString(getCanonicalLocale(), sameDay
		? { hour: '2-digit', minute: '2-digit' }
		: { weekday: 'short', hour: '2-digit', minute: '2-digit' })
}

/**
 * Who started or ended a lockdown, as part of a sentence.
 *
 * @param actor - An account, "occ" or "automatic"
 */
export function actorLabel(actor: string): string {
	if (actor === AUTOMATIC) {
		return t(APP_ID, 'Nextcloud, because of a distributed attack')
	}
	return actor === OCC ? t(APP_ID, 'a command on the server') : actor
}

const PHRASES: Record<string, () => string> = {
	login: () => t(APP_ID, 'every password login needs confirmation'),
	sensitive: () => t(APP_ID, 'sensitive actions need confirmation'),
	devices: () => t(APP_ID, 'new devices cannot be connected'),
	reset: () => t(APP_ID, 'password reset is paused'),
	limits: () => t(APP_ID, 'the limits of the checks are lower'),
	share_password: () => t(APP_ID, 'share passwords may be guessed wrong less often'),
}

/**
 * What a running lockdown does, as one sentence.
 *
 * @param effects - The effects that are on
 */
export function effectsSentence(effects: string[]): string {
	const phrases = effects.map((effect) => PHRASES[effect]?.()).filter((phrase): phrase is string => phrase !== undefined)
	if (phrases.length === 0) {
		return t(APP_ID, 'All of its effects are switched off.')
	}
	const sentence = phrases.join(', ')
	return sentence.charAt(0).toLocaleUpperCase() + sentence.slice(1) + '.'
}
