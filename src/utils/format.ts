/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { ParamType, ParamValue } from '../types.ts'

import { getCanonicalLocale, n, t } from '@nextcloud/l10n'

export const APP_ID = 'intrusion_detection'

/** A piece of a live sentence: plain text, or a filled-in setting */
export interface Segment {
	text: string
	/** The setting this segment shows, for filled-in values */
	name?: string
}

const DAY = 86400
const HOUR = 3600
const MINUTE = 60

/**
 * A duration in the largest whole unit, like the server's `TextRenderer::duration()`:
 * "90 seconds", "10 minutes", "4 hours", "7 days".
 *
 * @param seconds - The duration in seconds
 */
export function formatDuration(seconds: number): string {
	if (seconds >= DAY && seconds % DAY === 0) {
		return n(APP_ID, '%n day', '%n days', seconds / DAY)
	}
	if (seconds >= HOUR && seconds % HOUR === 0) {
		return n(APP_ID, '%n hour', '%n hours', seconds / HOUR)
	}
	if (seconds >= MINUTE && seconds % MINUTE === 0) {
		return n(APP_ID, '%n minute', '%n minutes', seconds / MINUTE)
	}
	return n(APP_ID, '%n second', '%n seconds', seconds)
}

const CHOICES: Record<string, () => string> = {
	off: () => t(APP_ID, 'Off'),
	observe: () => t(APP_ID, 'Observe'),
	protect: () => t(APP_ID, 'Protect'),
	low: () => t(APP_ID, 'Low'),
	medium: () => t(APP_ID, 'Medium'),
	high: () => t(APP_ID, 'High'),
	critical: () => t(APP_ID, 'Critical'),
	never: () => t(APP_ID, 'Never'),
	refuse: () => t(APP_ID, 'Refuse'),
	allow_notify: () => t(APP_ID, 'Allow and notify'),
}

/**
 * The value of a choice setting as people read it: "Observe" for "observe".
 *
 * @param choice - The stored value
 */
export function choiceLabel(choice: string): string {
	return CHOICES[choice]?.() ?? choice
}

/**
 * A setting's value as the explanation texts show it, like the server's `TextRenderer::format()`.
 *
 * @param value - The value
 * @param type - The type of the setting, if known
 */
export function formatValue(value: ParamValue, type?: ParamType): string {
	if (type === 'duration' && typeof value === 'number') {
		return formatDuration(value)
	}
	if (typeof value === 'boolean') {
		return value ? t(APP_ID, 'on') : t(APP_ID, 'off')
	}
	if (Array.isArray(value)) {
		return value.length === 0 ? t(APP_ID, 'none') : value.join(', ')
	}
	if (type === 'choice' && typeof value === 'string') {
		return choiceLabel(value)
	}
	if (type === 'float' && typeof value === 'number') {
		return String(Number(value.toFixed(2)))
	}
	return String(value)
}

/**
 * Fill the `{name}` placeholders of an explanation template. Placeholders
 * without a value stay as they are, as on the server.
 *
 * @param template - The translated template
 * @param values - Values by setting name
 * @param types - Types by setting name, for formatting
 */
export function fillTemplate(template: string, values: Record<string, ParamValue>, types: Record<string, ParamType> = {}): Segment[] {
	const segments: Segment[] = []
	const pattern = /\{([a-z][a-z0-9_]*)\}/g
	let last = 0
	for (const match of template.matchAll(pattern)) {
		const name = match[1]!
		const index = match.index
		if (!(name in values)) {
			continue
		}
		if (index > last) {
			segments.push({ text: template.slice(last, index) })
		}
		segments.push({ text: formatValue(values[name]!, types[name]), name })
		last = index + match[0].length
	}
	if (last < template.length) {
		segments.push({ text: template.slice(last) })
	}
	return mergeText(segments)
}

/**
 * The filled template as plain text.
 *
 * @param template - The translated template
 * @param values - Values by setting name
 * @param types - Types by setting name
 */
export function fillTemplateText(template: string, values: Record<string, ParamValue>, types: Record<string, ParamType> = {}): string {
	return fillTemplate(template, values, types).map((segment) => segment.text).join('')
}

/**
 * Join neighbouring plain segments, so unknown placeholders stay inside the text.
 *
 * @param segments - The segments
 */
function mergeText(segments: Segment[]): Segment[] {
	const merged: Segment[] = []
	for (const segment of segments) {
		const previous = merged.at(-1)
		if (previous && previous.name === undefined && segment.name === undefined) {
			previous.text += segment.text
		} else {
			merged.push({ ...segment })
		}
	}
	return merged
}

/**
 * A number with the reader's digit grouping.
 *
 * @param value - The number
 */
export function formatNumber(value: number): string {
	return new Intl.NumberFormat(getCanonicalLocale()).format(value)
}

/**
 * The measured guard cost in milliseconds, as people read it: "0.03 ms".
 *
 * @param microseconds - The cost in microseconds
 */
export function formatCost(microseconds: number): string {
	const format = new Intl.NumberFormat(getCanonicalLocale(), { maximumFractionDigits: microseconds >= 1000 ? 1 : 3 })
	return t(APP_ID, '{value} ms', { value: format.format(microseconds / 1000) })
}

/**
 * Split a duration into the largest whole unit, for the duration field.
 *
 * @param seconds - The duration in seconds
 */
export function splitDuration(seconds: number): { amount: number, unit: number } {
	for (const unit of [DAY, HOUR, MINUTE]) {
		if (seconds >= unit && seconds % unit === 0) {
			return { amount: seconds / unit, unit }
		}
	}
	return { amount: seconds, unit: 1 }
}

export const DURATION_UNITS = [
	{ seconds: 1, label: () => t(APP_ID, 'seconds') },
	{ seconds: MINUTE, label: () => t(APP_ID, 'minutes') },
	{ seconds: HOUR, label: () => t(APP_ID, 'hours') },
	{ seconds: DAY, label: () => t(APP_ID, 'days') },
]
