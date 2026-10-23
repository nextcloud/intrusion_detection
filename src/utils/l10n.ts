/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { t as translate, n as translatePlural } from '@nextcloud/l10n'

/** The placeholder names in a translation key, like `@nextcloud/l10n` derives them */
type Placeholders<T extends string> = T extends `${string}{${infer Name}}${infer Rest}` ? Name | Placeholders<Rest> : never

type Values<T extends string> = Record<Placeholders<T>, string | number>

/**
 * The app's texts are only ever rendered as text, which Vue escapes, so they
 * are translated without HTML escaping and sanitizing: a name like
 * `Tom's & Co` keeps its `'` and `&`.
 */
const AS_TEXT = { escape: false, sanitize: false }

/**
 * Translate a text for text output.
 *
 * @param app - The app id
 * @param text - The text to translate
 * @param vars - Values for the `{placeholders}`
 * @param count - Replaces `%n`
 */
export function t<T extends string>(app: string, text: T, vars?: Values<T>, count?: number): string {
	return translate(app, text, vars, count, AS_TEXT)
}

/**
 * Translate a text with a singular and a plural form for text output.
 *
 * @param app - The app id
 * @param singular - The text for exactly one
 * @param plural - The text for any other count
 * @param count - Picks the form and replaces `%n`
 * @param vars - Values for the `{placeholders}`
 */
export function n<S extends string, P extends string>(app: string, singular: S, plural: P, count: number, vars?: Values<S> & Values<P>): string {
	return translatePlural(app, singular, plural, count, vars, AS_TEXT)
}
