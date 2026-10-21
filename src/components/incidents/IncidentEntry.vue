<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { IncidentEntry } from '../../types.ts'

import { mdiChevronDown } from '@mdi/js'
import { getCanonicalLocale, t } from '@nextcloud/l10n'
import { computed, useId } from 'vue'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import SeverityPill from '../common/SeverityPill.vue'
import TimeStamp from '../common/TimeStamp.vue'
import { APP_ID } from '../../utils/format.ts'
import { kindIcon } from './kinds.ts'

const expanded = defineModel<boolean>('expanded', { default: false })

const props = defineProps<{
	entry: IncidentEntry
	kindLabel: string
}>()

const id = useId()

const time = computed(() => new Intl.DateTimeFormat(getCanonicalLocale(), { timeStyle: 'short' }).format(props.entry.at * 1000))
const absolute = computed(() => new Intl.DateTimeFormat(getCanonicalLocale(), { dateStyle: 'full', timeStyle: 'medium' }).format(props.entry.at * 1000))
// Only a block's reference is quoted by people; the other references are internal ids.
const reference = computed(() => props.entry.ref?.type === 'block' ? props.entry.ref.id : null)
const hasDetail = computed(() => props.entry.details.length > 0 || props.entry.done.length > 0 || props.entry.note !== null || props.entry.address !== null || props.entry.accounts.length > 0 || reference.value !== null)
const tone = computed(() => props.entry.severity ?? 'neutral')
</script>

<template>
	<li :class="[$style.entry, $style[`entry_${tone}`]]" :data-test="`incident-entry-${entry.kind}`">
		<div :class="$style.entry__marker" aria-hidden="true">
			<NcIconSvgWrapper :path="kindIcon(entry.kind)" :size="18" />
		</div>
		<div :class="$style.entry__card">
			<div :class="$style.entry__head">
				<time :class="$style.entry__time" :datetime="new Date(entry.at * 1000).toISOString()" :title="absolute">
					{{ time }}
				</time>
				<span :class="$style.entry__kind">{{ kindLabel }}</span>
				<SeverityPill v-if="entry.severity" :severity="entry.severity" />
				<span
					v-if="entry.enforced !== null"
					:class="[$style.entry__outcome, entry.enforced ? $style.entry__outcome_enforced : $style.entry__outcome_observed]">
					{{ entry.enforced ? t(APP_ID, 'Acted on') : t(APP_ID, 'Observed') }}
				</span>
				<TimeStamp :class="$style.entry__relative" :timestamp="entry.at" short />
			</div>
			<button
				v-if="hasDetail"
				type="button"
				:class="$style.entry__toggle"
				:aria-expanded="expanded ? 'true' : 'false'"
				:aria-controls="`${id}-detail`"
				@click="expanded = !expanded">
				<span :class="$style.entry__title">{{ entry.title }}</span>
				<NcIconSvgWrapper :class="[$style.entry__chevron, { [$style.entry__chevron_open]: expanded }]" :path="mdiChevronDown" :size="20" />
			</button>
			<p v-else :class="$style.entry__title">
				{{ entry.title }}
			</p>

			<div v-if="hasDetail && expanded" :id="`${id}-detail`" :class="$style.entry__detail">
				<p v-for="(sentence, index) in entry.details" :key="`d${index}`" :class="$style.entry__text">
					{{ sentence }}
				</p>
				<template v-if="entry.done.length > 0">
					<h6 :class="$style.entry__subheading">
						{{ entry.enforced === false ? t(APP_ID, 'What Nextcloud would have done') : t(APP_ID, 'What Nextcloud did') }}
					</h6>
					<ul :class="$style.entry__done">
						<li v-for="(sentence, index) in entry.done" :key="`a${index}`">
							{{ sentence }}
						</li>
					</ul>
				</template>
				<p v-if="entry.note" :class="$style.entry__note">
					{{ entry.note }}
				</p>
				<dl :class="$style.entry__meta">
					<div v-if="entry.lastSeenAt">
						<dt>{{ t(APP_ID, 'Last seen') }}</dt>
						<dd><TimeStamp :timestamp="entry.lastSeenAt" /></dd>
					</div>
					<div v-if="entry.endsAt">
						<dt>{{ t(APP_ID, 'Until') }}</dt>
						<dd><TimeStamp :timestamp="entry.endsAt" /></dd>
					</div>
					<div v-if="entry.address">
						<dt>{{ t(APP_ID, 'Address') }}</dt>
						<dd><code>{{ entry.address }}</code></dd>
					</div>
					<div v-if="entry.accounts.length > 0">
						<dt>{{ t(APP_ID, 'Accounts') }}</dt>
						<dd>{{ entry.accounts.join(', ') }}</dd>
					</div>
					<div v-if="reference">
						<dt>{{ t(APP_ID, 'Reference') }}</dt>
						<dd><code>{{ reference }}</code></dd>
					</div>
				</dl>
			</div>
		</div>
	</li>
</template>

<style module>
.entry {
	--entry-tone: var(--color-primary-element);
	--entry-tint: var(--color-primary-element-light);
	--entry-tone-text: var(--color-primary-element-light-text);
	position: relative;
	display: grid;
	grid-template-columns: 36px minmax(0, 1fr);
	gap: calc(var(--default-grid-baseline) * 3);
	padding-block: calc(var(--default-grid-baseline) * 2);
}

.entry_low {
	--entry-tone: var(--color-text-maxcontrast);
	--entry-tint: var(--color-background-dark);
	--entry-tone-text: var(--color-main-text);
}

.entry_medium {
	--entry-tone: var(--color-info);
	--entry-tint: color-mix(in srgb, var(--color-info) 16%, var(--color-main-background));
	--entry-tone-text: var(--color-info-text);
}

.entry_high {
	--entry-tone: var(--color-warning);
	--entry-tint: color-mix(in srgb, var(--color-warning) 18%, var(--color-main-background));
	--entry-tone-text: var(--color-warning-text);
}

.entry_critical {
	--entry-tone: var(--color-error);
	--entry-tint: color-mix(in srgb, var(--color-error) 16%, var(--color-main-background));
	--entry-tone-text: var(--color-error-text);
}

.entry__marker {
	position: relative;
	z-index: 1;
	display: inline-flex;
	align-items: center;
	justify-content: center;
	width: 36px;
	height: 36px;
	margin-block-start: calc(var(--default-grid-baseline) * 1);
	border: 2px solid var(--color-main-background);
	border-radius: 50%;
	background-color: var(--entry-tint);
	color: var(--entry-tone-text);
	box-shadow: 0 0 0 1px color-mix(in srgb, var(--entry-tone) 35%, transparent);
}

.entry__card {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1);
	min-width: 0;
	padding-block: calc(var(--default-grid-baseline) * 1.5);
}

.entry__head {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 1.5) calc(var(--default-grid-baseline) * 2.5);
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}

.entry__time {
	color: var(--color-main-text);
	font-weight: 700;
	font-variant-numeric: tabular-nums;
}

.entry__kind {
	font-weight: 600;
}

.entry__outcome {
	padding-inline: calc(var(--default-grid-baseline) * 2);
	border-radius: var(--border-radius-element);
	font-size: 0.9em;
	font-weight: 600;
	line-height: 22px;
	white-space: nowrap;
}

.entry__outcome_enforced {
	background-color: var(--color-primary-element);
	color: var(--color-primary-element-text);
}

.entry__outcome_observed {
	border: 1px dashed var(--color-primary-element);
	background-color: var(--color-primary-element-light);
	color: var(--color-primary-element-light-text, var(--color-main-text));
}

.entry__relative {
	margin-inline-start: auto;
}

.entry .entry__toggle {
	display: flex;
	align-items: flex-start;
	justify-content: space-between;
	gap: calc(var(--default-grid-baseline) * 2);
	width: 100%;
	min-height: auto;
	margin: 0;
	padding: calc(var(--default-grid-baseline) * 1) 0;
	border: none;
	border-radius: var(--border-radius-element);
	background: transparent;
	color: var(--color-main-text);
	font-weight: normal;
	text-align: start;
	cursor: pointer;
}

.entry .entry__toggle:hover .entry__title {
	text-decoration: underline;
}

.entry .entry__toggle:focus-visible {
	outline: 2px solid var(--color-main-text);
	outline-offset: 2px;
}

.entry__title {
	margin: 0;
	font-weight: 600;
	line-height: 1.45;
	overflow-wrap: anywhere;
}

.entry__chevron {
	flex: 0 0 auto;
	color: var(--color-text-maxcontrast);
	transition: transform 180ms ease;
}

.entry__chevron_open {
	transform: rotate(180deg);
}

.entry__detail {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1.5);
	padding-block: calc(var(--default-grid-baseline) * 1) calc(var(--default-grid-baseline) * 1);
	animation: entry-reveal 180ms ease;
}

.entry__text {
	margin: 0;
	max-width: 80ch;
	line-height: 1.55;
	overflow-wrap: anywhere;
}

.entry__subheading {
	margin: calc(var(--default-grid-baseline) * 1.5) 0 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.8em;
	font-weight: 700;
	letter-spacing: 0.06em;
	text-transform: uppercase;
}

.entry__done {
	margin: 0;
	padding-inline-start: calc(var(--default-grid-baseline) * 5);
	list-style: disc;
	line-height: 1.55;
}

.entry__note {
	margin: 0;
	color: var(--color-text-maxcontrast);
	font-style: italic;
}

.entry__meta {
	display: flex;
	flex-wrap: wrap;
	gap: calc(var(--default-grid-baseline) * 1) calc(var(--default-grid-baseline) * 6);
	margin: calc(var(--default-grid-baseline) * 1) 0 0;
	font-size: 0.9em;
}

.entry__meta dt,
.entry__meta dd {
	height: auto;
	padding: 0;
	text-align: start;
}

.entry__meta dt {
	color: var(--color-text-maxcontrast);
}

.entry__meta dd {
	margin: 0;
	overflow-wrap: anywhere;
}

.entry__meta code {
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
}

@keyframes entry-reveal {
	from {
		opacity: 0;
		transform: translateY(-4px);
	}
}

@media (max-width: 600px) {
	.entry {
		grid-template-columns: 28px minmax(0, 1fr);
		gap: calc(var(--default-grid-baseline) * 2);
	}

	.entry__marker {
		width: 28px;
		height: 28px;
	}

	.entry__relative {
		margin-inline-start: 0;
	}
}

@media (prefers-reduced-motion: reduce) {
	.entry__chevron {
		transition: none;
	}

	.entry__detail {
		animation: none;
	}
}
</style>
