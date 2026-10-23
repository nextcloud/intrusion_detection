<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Mode, PayloadForm, PayloadTest, PayloadValue } from '../../types.ts'

import { mdiShieldAlertOutline, mdiShieldCheckOutline } from '@mdi/js'
import { computed } from 'vue'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import StateBadge from '../common/StateBadge.vue'
import { APP_ID } from '../../utils/format.ts'
import { n, t } from '../../utils/l10n.ts'

const props = defineProps<{
	result: PayloadTest
}>()

const inspected = computed(() => props.result.values.filter((v) => v.skipped === null && v.normalised !== undefined))
const skipped = computed(() => props.result.values.filter((v) => v.skipped !== null))
const strongest = computed(() => Math.max(0, ...inspected.value.map((v) => v.weight ?? 0)))

const verdict = computed(() => {
	const result = props.result
	if (result.fires) {
		return {
			fires: true,
			title: t(APP_ID, 'Would fire'),
			text: t(APP_ID, 'The strongest value reaches a weight of {weight}; {needed} is needed.', { weight: strongest.value, needed: result.minWeight }),
		}
	}
	let text: string
	if (result.pathExcluded && result.values.length === 0) {
		text = t(APP_ID, 'This is a file or folder name in WebDAV or a public share. File names are never inspected, because they can contain anything.')
	} else if (!result.prefilter) {
		text = t(APP_ID, 'Nothing suspicious: it contains none of the characters and words attacks need, so the check stops after its quick first scan.')
	} else if (inspected.value.length === 0) {
		text = t(APP_ID, 'No value was inspected: only fields that are never inspected, such as passwords or free text, contain anything suspicious.')
	} else {
		text = t(APP_ID, 'The strongest value reaches a weight of {weight}; {needed} is needed.', { weight: strongest.value, needed: result.minWeight })
	}
	return { fires: false, title: t(APP_ID, 'Would not fire'), text }
})

/**
 * @param mode - The effective mode
 * @param anonymous - For visitors who are not logged in
 */
function modeText(mode: Mode, anonymous: boolean): string {
	if (mode === 'protect') {
		return anonymous ? t(APP_ID, 'blocked') : t(APP_ID, 'blocked, and the session ended')
	}
	if (mode === 'observe') {
		return t(APP_ID, 'recorded only')
	}
	return t(APP_ID, 'not checked')
}

/**
 * @param value - An inspected value
 */
function locationLabel(value: PayloadValue): string {
	return {
		path: t(APP_ID, 'Path'),
		query: t(APP_ID, 'Web address parameter'),
		form: value.name === '' ? t(APP_ID, 'Value') : t(APP_ID, 'Form field'),
	}[value.location] ?? value.location
}

/**
 * @param reason - Why a value was not inspected
 */
function skippedText(reason: string): string {
	return {
		secret: t(APP_ID, 'Never inspected: a password, secret or token field can contain anything.'),
		free_text: t(APP_ID, 'Never inspected: a free-text field, on the list of excluded parameters.'),
		budget: t(APP_ID, 'Not inspected: the request is longer than the limit of what is inspected.'),
	}[reason] ?? reason
}

/**
 * @param form - A form of the value
 */
function formLabel(form: PayloadForm): string {
	return {
		none: t(APP_ID, 'As sent'),
		base64: t(APP_ID, 'After decoding base64'),
		base64_twice: t(APP_ID, 'After decoding base64 twice'),
	}[form.encoding] ?? form.encoding
}

</script>

<template>
	<div :class="$style.result" data-test="payload-result">
		<div :class="[$style.verdict, verdict.fires ? $style.verdict_fires : $style.verdict_quiet]">
			<span :class="$style.verdict__icon" aria-hidden="true">
				<NcIconSvgWrapper inline :path="verdict.fires ? mdiShieldAlertOutline : mdiShieldCheckOutline" :size="24" />
			</span>
			<div :class="$style.verdict__text">
				<p :class="$style.verdict__title" data-test="payload-verdict">
					{{ verdict.title }}
				</p>
				<p>{{ verdict.text }}</p>
				<p v-if="result.fires" :class="$style.verdict__modes">
					{{ t(APP_ID, 'Visitors who are not logged in: {anonymous}. Logged-in users: {authenticated}.', {
						anonymous: modeText(result.modes.anonymous, true),
						authenticated: modeText(result.modes.authenticated, false),
					}) }}
				</p>
			</div>
		</div>

		<ul v-if="inspected.length > 0" :class="$style.values">
			<li v-for="(value, index) in inspected" :key="index" :class="[$style.value, { [$style.value_fires]: value.fires }]">
				<div :class="$style.value__head">
					<span :class="$style.value__where">
						<StateBadge>{{ locationLabel(value) }}</StateBadge>
						<code v-if="value.name" :class="$style.value__name">{{ value.name }}</code>
					</span>
					<span :class="$style.meter" :title="t(APP_ID, 'Weight {weight} of {needed} needed', { weight: value.weight ?? 0, needed: result.minWeight })">
						<span :class="$style.meter__pips" aria-hidden="true">
							<span
								v-for="pip in result.minWeight"
								:key="pip"
								:class="[$style.meter__pip, { [$style.meter__pip_on]: pip <= (value.weight ?? 0), [$style.meter__pip_fires]: value.fires }]" />
						</span>
						<span :class="$style.meter__label">
							{{ t(APP_ID, 'weight {weight} / {needed}', { weight: value.weight ?? 0, needed: result.minWeight }) }}
						</span>
					</span>
				</div>

				<div :class="$style.step">
					<span :class="$style.step__label">{{ t(APP_ID, 'Normalised') }}</span>
					<code :class="$style.step__text" data-test="payload-normalised">{{ value.normalised || '—' }}</code>
				</div>
				<div v-for="(decoded, level) in value.decoded ?? []" :key="level" :class="$style.step">
					<span :class="$style.step__label">{{ level === 0 ? t(APP_ID, 'Decoded from base64') : t(APP_ID, 'Decoded again') }}</span>
					<code :class="$style.step__text" data-test="payload-decoded">{{ decoded }}</code>
				</div>

				<div v-for="form in (value.forms ?? []).filter((f) => f.matches.length > 0)" :key="form.encoding" :class="$style.matches">
					<p :class="$style.matches__head">
						<span>{{ formLabel(form) }}</span>
						<span :class="$style.matches__total">{{ t(APP_ID, 'total {weight}', { weight: form.weight }) }}</span>
					</p>
					<ul :class="$style.matches__list">
						<li
							v-for="match in form.matches"
							:key="match.id"
							:class="$style.match"
							data-test="payload-match">
							<span :class="$style.match__weight">+{{ match.weight }}</span>
							<span :class="$style.match__text">
								<span>{{ match.description }}</span>
								<code>{{ match.id }}</code>
							</span>
						</li>
					</ul>
				</div>
				<p v-if="(value.forms ?? []).every((f) => f.matches.length === 0)" :class="$style.value__none">
					{{ t(APP_ID, 'No signature matches this value.') }}
				</p>
				<p v-if="value.truncated" :class="$style.value__none">
					{{ n(APP_ID, 'Only the first %n byte was inspected.', 'Only the first %n bytes were inspected.', result.maxBytes) }}
				</p>
			</li>
		</ul>

		<ul v-if="skipped.length > 0" :class="$style.skipped">
			<li v-for="(value, index) in skipped" :key="index">
				<code>{{ value.name || locationLabel(value) }}</code>
				<span>{{ skippedText(value.skipped ?? '') }}</span>
			</li>
		</ul>
	</div>
</template>

<style module>
.result {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-3);
}

.verdict {
	--verdict-color: var(--color-success);
	--verdict-text: var(--color-success-text);
	display: flex;
	align-items: flex-start;
	gap: var(--ids-space-3);
	padding: var(--ids-space-3) var(--ids-space-4);
	border: 1px solid color-mix(in srgb, var(--verdict-color) 35%, var(--color-border));
	border-radius: var(--border-radius-large);
	background-color: color-mix(in srgb, var(--verdict-color) 10%, var(--color-main-background));
}

.verdict_fires {
	--verdict-color: var(--color-error);
	--verdict-text: var(--color-error-text);
}

.verdict__icon {
	display: inline-flex;
	flex: 0 0 auto;
	align-items: center;
	justify-content: center;
	width: 40px;
	height: 40px;
	border-radius: 50%;
	background-color: color-mix(in srgb, var(--verdict-color) 18%, var(--color-main-background));
	color: var(--verdict-text);
}

.verdict__text p {
	margin: 0;
	line-height: 1.5;
}

.verdict__title {
	color: var(--verdict-text);
	font-size: 1.1em;
	font-weight: 700;
}

.verdict__modes {
	composes: muted from '../../styles/shared.module.css';
	margin-top: var(--ids-space-1) !important;
	font-size: 0.92em;
}

.values {
	composes: plainList from '../../styles/shared.module.css';
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-3);
}

.value {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-2);
	padding: var(--ids-space-3);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
	background-color: var(--color-main-background);
}

.value_fires {
	border-color: color-mix(in srgb, var(--color-error) 40%, var(--color-border));
}

.value__head {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	justify-content: space-between;
	gap: var(--ids-space-2);
}

.value__where {
	display: inline-flex;
	flex-wrap: wrap;
	align-items: center;
	gap: var(--ids-space-2);
	min-width: 0;
}

.value__name {
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
	font-weight: 600;
	overflow-wrap: anywhere;
}

.meter {
	display: inline-flex;
	align-items: center;
	gap: var(--ids-space-2);
}

.meter__pips {
	display: inline-flex;
	gap: 3px;
}

.meter__pip {
	width: 10px;
	height: 12px;
	border: 1px solid var(--color-border-maxcontrast, var(--color-text-maxcontrast));
	border-radius: 3px;
}

.meter__pip_on {
	border-color: var(--color-text-maxcontrast);
	background-color: var(--color-text-maxcontrast);
}

.meter__pip_on.meter__pip_fires {
	border-color: var(--color-error);
	background-color: var(--color-error);
}

.meter__label {
	composes: muted from '../../styles/shared.module.css';
	font-size: 0.85em;
	font-variant-numeric: tabular-nums;
	white-space: nowrap;
}

.step {
	display: grid;
	grid-template-columns: minmax(0, 10em) minmax(0, 1fr);
	gap: var(--ids-space-3);
	align-items: baseline;
}

.step__label {
	composes: muted from '../../styles/shared.module.css';
	font-size: 0.85em;
}

.step__text {
	padding: var(--ids-space-1) var(--ids-space-2);
	border-radius: var(--border-radius-element);
	background-color: var(--color-background-hover);
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
	font-size: 0.88em;
	white-space: pre-wrap;
	overflow-wrap: anywhere;
}

.matches {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-1-5);
}

.matches__head {
	composes: eyebrow from '../../styles/shared.module.css';
	display: flex;
	justify-content: space-between;
	margin: 0;
}

.matches__total {
	font-variant-numeric: tabular-nums;
}

.matches__list {
	composes: plainList from '../../styles/shared.module.css';
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-1);
}

.match {
	display: flex;
	align-items: flex-start;
	gap: var(--ids-space-3);
}

.match__weight {
	flex: 0 0 auto;
	min-width: 32px;
	padding-inline: var(--ids-space-1-5);
	border-radius: var(--border-radius-pill, 100px);
	background-color: color-mix(in srgb, var(--color-error) 14%, var(--color-main-background));
	color: var(--color-error-text);
	font-size: 0.85em;
	font-weight: 700;
	font-variant-numeric: tabular-nums;
	line-height: 1.6;
	text-align: center;
}

.match__text {
	display: flex;
	flex-direction: column;
	min-width: 0;
	line-height: 1.45;
}

.match__text code {
	color: var(--color-text-maxcontrast);
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
	font-size: 0.8em;
}

.value__none {
	composes: muted from '../../styles/shared.module.css';
	margin: 0;
	font-size: 0.9em;
}

.skipped {
	composes: plainList muted from '../../styles/shared.module.css';
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-1);
	font-size: 0.9em;
}

.skipped li {
	display: flex;
	flex-wrap: wrap;
	gap: var(--ids-space-2);
}

.skipped code {
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
	color: var(--color-main-text);
}

@media (max-width: 600px) {
	.step {
		grid-template-columns: minmax(0, 1fr);
		gap: var(--ids-space-1);
	}
}
</style>
