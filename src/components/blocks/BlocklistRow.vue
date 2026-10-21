<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Blocklist } from '../../types.ts'

import { mdiAlertCircleOutline, mdiAlertOutline, mdiCheckCircleOutline, mdiChevronDown, mdiCloudOutline, mdiDeleteOutline, mdiDownload, mdiIncognito, mdiOpenInNew, mdiShieldAlertOutline } from '@mdi/js'
import { showError, showSuccess } from '@nextcloud/dialogs'
import { n, t } from '@nextcloud/l10n'
import { computed, ref, useId, watch } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcCheckboxRadioSwitch from '@nextcloud/vue/components/NcCheckboxRadioSwitch'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcRadioGroup from '@nextcloud/vue/components/NcRadioGroup'
import NcRadioGroupButton from '@nextcloud/vue/components/NcRadioGroupButton'
import DurationInput from '../checks/DurationInput.vue'
import MatchSparkline from '../common/MatchSparkline.vue'
import ReferencePill from '../common/ReferencePill.vue'
import StateBadge from '../common/StateBadge.vue'
import TimeStamp from '../common/TimeStamp.vue'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { ApiError, errorMessage, isCancelled, removeBlocklist, syncBlocklist, updateBlocklist } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { APP_ID, formatDuration, formatNumber } from '../../utils/format.ts'

const props = defineProps<{
	list: Blocklist
	/** Days of matches to show */
	days: number
	countsMatches: boolean
	minInterval: number
	maxInterval: number
}>()

const emit = defineEmits<{
	updated: [list: Blocklist]
	removed: [id: string]
}>()

const id = useId()
const expanded = ref(false)
const busy = ref<string | null>(null)
const confirmRemove = ref(false)
const interval = ref<number | string>(props.list.interval)
const intervalError = ref<string | null>(null)
const { announce } = useAnnouncer()

watch(() => props.list.interval, (value) => {
	interval.value = value
})

const isDeny = computed(() => props.list.purpose === 'deny')

/** The publisher, as people recognise it */
const host = computed(() => {
	try {
		return new URL(props.list.url).hostname.replace(/^www\./, '')
	} catch {
		return props.list.url
	}
})

const purpose = computed(() => ({
	deny: { icon: mdiShieldAlertOutline, label: t(APP_ID, 'Blocklist') },
	hosting: { icon: mdiCloudOutline, label: t(APP_ID, 'Hosting networks') },
	tor: { icon: mdiIncognito, label: t(APP_ID, 'Tor network') },
})[props.list.purpose])

const sync = computed(() => {
	const list = props.list
	if (!list.enabled) {
		return null
	}
	const failedLast = list.lastFailureAt !== null && (list.lastSuccessAt === null || list.lastFailureAt > list.lastSuccessAt)
	if (failedLast) {
		return { type: 'error' as const, icon: mdiAlertCircleOutline, text: t(APP_ID, 'Download failed: {reason}', { reason: list.lastErrorText ?? '' }), at: list.lastFailureAt }
	}
	if (list.lastSuccessAt !== null) {
		return { type: list.stale ? 'warning' as const : 'success' as const, icon: list.stale ? mdiAlertOutline : mdiCheckCircleOutline, text: list.stale ? t(APP_ID, 'Out of date') : t(APP_ID, 'Up to date'), at: list.lastSuccessAt }
	}
	return { type: 'neutral' as const, icon: mdiDownload, text: t(APP_ID, 'Not downloaded yet'), at: null }
})

/** One value per day, oldest first, with days without matches as 0 */
const points = computed(() => {
	const byDay = new Map(props.list.matches.map((d) => [d.day, d.matches]))
	const today = Date.now()
	return Array.from({ length: props.days }, (_, i) => {
		const day = new Date(today - (props.days - 1 - i) * 86400000).toISOString().slice(0, 10)
		return { day, value: byDay.get(day) ?? 0 }
	})
})
const totalMatches = computed(() => points.value.reduce((sum, p) => sum + p.value, 0))
const latestSample = computed(() => [...props.list.matches].sort((a, b) => b.day.localeCompare(a.day)).find((d) => d.sample.length > 0)?.sample ?? [])

/**
 * Save a change of the list and tell the parent.
 *
 * @param key - What is saved, for the loading state
 * @param change - The change
 * @param change.enabled - Use the list
 * @param change.mode - Observe or protect
 * @param change.interval - Seconds, 0 for the default
 * @param done - What to announce when it worked
 */
async function save(key: string, change: { enabled?: boolean, mode?: string, interval?: number }, done: string) {
	busy.value = key
	try {
		emit('updated', await updateBlocklist(props.list.id, change))
		announce(done)
		return true
	} catch (error) {
		if (!isCancelled(error)) {
			logger.error('Could not change the list', { error })
			if (key === 'interval' && error instanceof ApiError) {
				intervalError.value = error.message
			} else {
				showError(errorMessage(error, t(APP_ID, 'The list could not be changed. Please try again.')))
			}
		}
		return false
	} finally {
		busy.value = null
	}
}

/**
 * @param on - Whether the list is used
 */
function setEnabled(on: boolean) {
	return save('enabled', { enabled: on }, on
		? t(APP_ID, '{list} is on. It is downloaded within the next minutes.', { list: props.list.name })
		: t(APP_ID, '{list} is off.', { list: props.list.name }))
}

/**
 * @param mode - observe or protect
 */
function setMode(mode: string) {
	if (mode === props.list.mode) {
		return
	}
	save('mode', { mode }, mode === 'protect'
		? t(APP_ID, '{list} now refuses matching addresses.', { list: props.list.name })
		: t(APP_ID, '{list} now only counts matching addresses.', { list: props.list.name }))
}

const intervalProblem = computed(() => {
	const value = interval.value
	if (typeof value !== 'number') {
		return t(APP_ID, 'Enter a whole number.')
	}
	if (value < props.minInterval || value > props.maxInterval) {
		return t(APP_ID, 'From {min} to {max}.', { min: formatDuration(props.minInterval), max: formatDuration(props.maxInterval) })
	}
	return null
})

/**
 * Save the interval, or go back to the default one.
 *
 * @param reset - Use the default interval instead
 */
async function saveInterval(reset: boolean) {
	intervalError.value = null
	if (!reset && intervalProblem.value !== null) {
		return
	}
	await save('interval', { interval: reset ? 0 : Number(interval.value) }, t(APP_ID, 'Saved'))
}

/**
 * Download the list now.
 */
async function syncNow() {
	busy.value = 'sync'
	try {
		const { result, list } = await syncBlocklist(props.list.id)
		emit('updated', list)
		const message = {
			updated: n(APP_ID, '{list} was downloaded: %n range.', '{list} was downloaded: %n ranges.', result.ranges, { list: props.list.name }),
			unchanged: t(APP_ID, '{list} has not changed since the last download.', { list: props.list.name }),
			skipped: t(APP_ID, 'Another download is running. Try again in a minute.'),
			failed: t(APP_ID, '{list} could not be downloaded: {reason}. The previous version stays in use.', { list: props.list.name, reason: result.errorText ?? '' }),
		}[result.outcome]
		if (result.outcome === 'failed') {
			showError(message)
		} else {
			showSuccess(message)
		}
		announce(message)
	} catch (error) {
		if (!isCancelled(error)) {
			logger.error('Could not download the list', { error })
			showError(errorMessage(error, t(APP_ID, 'The list could not be downloaded. Please try again.')))
		}
	} finally {
		busy.value = null
	}
}

/**
 * Remove the custom list, after the confirmation.
 */
async function remove() {
	busy.value = 'remove'
	try {
		await removeBlocklist(props.list.id)
		confirmRemove.value = false
		emit('removed', props.list.id)
		announce(t(APP_ID, '{list} was removed.', { list: props.list.name }))
	} catch (error) {
		if (!isCancelled(error)) {
			showError(errorMessage(error, t(APP_ID, 'The list could not be removed. Please try again.')))
		}
	} finally {
		busy.value = null
	}
}
</script>

<template>
	<li :class="[$style.row, { [$style.row_off]: !list.enabled, [$style.row_expanded]: expanded }]" :aria-labelledby="`${id}-name`">
		<div :class="$style.row__main">
			<span :class="[$style.row__icon, $style[`row__icon_${list.purpose}`]]" aria-hidden="true">
				<NcIconSvgWrapper inline :path="purpose.icon" :size="20" />
			</span>
			<div :class="$style.row__title">
				<div :class="$style.row__nameLine">
					<h5 :id="`${id}-name`" :class="$style.row__name">
						{{ list.name }}
					</h5>
					<StateBadge v-if="!list.builtin">
						{{ t(APP_ID, 'Your list') }}
					</StateBadge>
				</div>
				<p :class="$style.row__meta">
					<span>{{ host }}</span>
					<span v-if="list.enabled" aria-hidden="true">·</span>
					<span v-if="list.enabled">{{ t(APP_ID, 'every {interval}', { interval: formatDuration(list.interval) }) }}</span>
					<template v-if="list.ranges > 0">
						<span aria-hidden="true">·</span>
						<span>{{ n(APP_ID, '{count} range', '{count} ranges', list.ranges, { count: formatNumber(list.ranges) }) }}</span>
					</template>
				</p>
			</div>
			<div :class="$style.row__controls">
				<button
					type="button"
					:class="$style.row__toggle"
					:aria-expanded="expanded ? 'true' : 'false'"
					:aria-controls="`${id}-details`"
					:aria-label="expanded ? t(APP_ID, 'Hide the details of {list}', { list: list.name }) : t(APP_ID, 'Show the details of {list}', { list: list.name })"
					:title="expanded ? t(APP_ID, 'Hide details') : t(APP_ID, 'Details')"
					@click="expanded = !expanded">
					<NcIconSvgWrapper
						inline
						:class="$style.row__chevron"
						:path="mdiChevronDown"
						:size="20" />
				</button>
				<NcCheckboxRadioSwitch
					type="switch"
					:modelValue="list.enabled"
					:loading="busy === 'enabled'"
					:disabled="busy !== null"
					@update:modelValue="setEnabled">
					<span class="hidden-visually">{{ t(APP_ID, 'Use {list}', { list: list.name }) }}</span>
				</NcCheckboxRadioSwitch>
			</div>
		</div>

		<div v-if="list.enabled" :class="$style.row__body">
			<div :class="$style.row__line">
				<div v-if="sync" :class="$style.row__sync">
					<StateBadge :type="sync.type" :icon="sync.icon">
						{{ sync.text }}
					</StateBadge>
					<span v-if="sync.at" :class="$style.row__muted">
						<TimeStamp :timestamp="sync.at" short />
					</span>
				</div>
				<NcButton
					:class="$style.row__syncButton"
					variant="tertiary"
					size="small"
					:disabled="busy !== null"
					@click="syncNow">
					<template #icon>
						<NcLoadingIcon v-if="busy === 'sync'" :size="18" />
						<NcIconSvgWrapper v-else :path="mdiDownload" :size="18" />
					</template>
					{{ t(APP_ID, 'Sync now') }}
				</NcButton>
			</div>

			<div v-if="isDeny" :class="$style.row__line">
				<NcRadioGroup
					:modelValue="list.mode ?? 'observe'"
					:label="t(APP_ID, 'What a match does for {list}', { list: list.name })"
					hideLabel
					@update:modelValue="setMode">
					<NcRadioGroupButton value="observe" :label="t(APP_ID, 'Observe')" :disabled="busy !== null" />
					<NcRadioGroupButton value="protect" :label="t(APP_ID, 'Protect')" :disabled="busy !== null" />
				</NcRadioGroup>
				<div v-if="countsMatches || totalMatches > 0" :class="$style.row__matches">
					<MatchSparkline :points="points" :label="t(APP_ID, 'Matches of {list} per day', { list: list.name })" />
					<span :class="$style.row__muted">
						{{ n(APP_ID, '{count} match in {days} days', '{count} matches in {days} days', totalMatches, { count: formatNumber(totalMatches), days }) }}
					</span>
				</div>
			</div>
		</div>

		<div :id="`${id}-details`" :class="$style.row__collapse" :inert="!expanded">
			<div :class="$style.row__collapseInner">
				<dl :class="$style.details">
					<div>
						<dt>{{ t(APP_ID, 'Downloaded from') }}</dt>
						<dd><code :class="$style.url">{{ list.url }}</code></dd>
					</div>
					<div v-if="isDeny && list.reference">
						<dt>{{ t(APP_ID, 'Reference on the error page') }}</dt>
						<dd :class="$style.details__inline">
							<ReferencePill :reference="list.reference" />
							<span :class="$style.row__muted">{{ t(APP_ID, 'Visitors refused by this list see this reference, without the name of the list.') }}</span>
						</dd>
					</div>
					<div v-if="list.lastSuccessAt">
						<dt>{{ t(APP_ID, 'Last good version') }}</dt>
						<dd>
							<TimeStamp :timestamp="list.lastSuccessAt" />
							<span v-if="list.skipped > 0" :class="$style.row__muted">
								· {{ n(APP_ID, '%n line skipped as not an address range', '%n lines skipped as not address ranges', list.skipped) }}
							</span>
						</dd>
					</div>
					<div v-if="isDeny && latestSample.length > 0">
						<dt>{{ t(APP_ID, 'Last matched addresses') }}</dt>
						<dd :class="$style.sample">
							<code v-for="address in latestSample.slice(0, 8)" :key="address">{{ address }}</code>
							<span v-if="latestSample.length > 8" :class="$style.row__muted">{{ n(APP_ID, 'and %n more', 'and %n more', latestSample.length - 8) }}</span>
						</dd>
					</div>
				</dl>

				<form :class="$style.interval" @submit.prevent="saveInterval(false)">
					<DurationInput
						v-model="interval"
						:label="t(APP_ID, 'Download every')"
						:invalid="intervalProblem !== null || intervalError !== null"
						:disabled="busy !== null" />
					<NcButton
						type="submit"
						variant="secondary"
						:disabled="busy !== null || intervalProblem !== null || interval === list.interval">
						<template v-if="busy === 'interval'" #icon>
							<NcLoadingIcon />
						</template>
						{{ t(APP_ID, 'Save') }}
					</NcButton>
					<NcButton
						v-if="list.customInterval"
						variant="tertiary"
						:disabled="busy !== null"
						@click="saveInterval(true)">
						{{ t(APP_ID, 'Use the default') }}
					</NcButton>
					<p v-if="intervalProblem || intervalError" :class="$style.interval__error">
						{{ intervalError ?? intervalProblem }}
					</p>
				</form>

				<div :class="$style.row__footer">
					<NcButton
						v-if="list.termsUrl"
						variant="tertiary"
						:href="list.termsUrl"
						target="_blank"
						rel="noreferrer noopener">
						<template #icon>
							<NcIconSvgWrapper :path="mdiOpenInNew" />
						</template>
						{{ t(APP_ID, 'Terms of use of the publisher') }}
					</NcButton>
					<NcButton
						v-if="!list.builtin"
						variant="tertiary"
						:disabled="busy !== null"
						@click="confirmRemove = true">
						<template #icon>
							<NcIconSvgWrapper :path="mdiDeleteOutline" />
						</template>
						{{ t(APP_ID, 'Remove list') }}
					</NcButton>
				</div>
			</div>
		</div>

		<NcDialog
			v-model:open="confirmRemove"
			:name="t(APP_ID, 'Remove {list}?', { list: list.name })"
			:message="t(APP_ID, 'Its addresses are no longer checked, and its ranges and counters are deleted.')"
			:buttons="[
				{ label: t(APP_ID, 'Cancel'), callback: () => undefined },
				{ label: t(APP_ID, 'Remove list'), variant: 'error', callback: () => { remove(); return false } },
			]" />
	</li>
</template>

<style module>
.row {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
	padding: calc(var(--default-grid-baseline) * 4);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
	background-color: var(--color-main-background);
	transition: border-color 150ms ease;
}

.row:hover {
	border-color: var(--color-border-dark, var(--color-border));
}

.row__main {
	display: flex;
	align-items: flex-start;
	gap: calc(var(--default-grid-baseline) * 3);
}

.row__icon {
	display: inline-flex;
	flex: 0 0 auto;
	align-items: center;
	justify-content: center;
	width: 36px;
	height: 36px;
	border-radius: 50%;
	background-color: var(--color-background-dark);
	color: var(--color-text-maxcontrast);
}

.row__icon_deny {
	background-color: color-mix(in srgb, var(--color-error) 12%, var(--color-main-background));
	color: var(--color-error-text);
}

.row__icon_hosting,
.row__icon_tor {
	background-color: color-mix(in srgb, var(--color-info) 12%, var(--color-main-background));
	color: var(--color-info-text);
}

.row_off .row__icon {
	background-color: var(--color-background-dark);
	color: var(--color-text-maxcontrast);
}

.row__title {
	flex: 1 1 auto;
	min-width: 0;
}

.row__nameLine {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2);
}

.row__name {
	margin: 0;
	font-size: 1em;
	font-weight: 700;
	line-height: 1.4;
}

.row_off .row__name {
	color: var(--color-text-maxcontrast);
}

.row__meta {
	display: flex;
	flex-wrap: wrap;
	gap: calc(var(--default-grid-baseline) * 1.5);
	margin: calc(var(--default-grid-baseline) / 2) 0 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}

.row__controls {
	display: flex;
	flex: 0 0 auto;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 1);
}

.row__body {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
	padding-inline-start: calc(36px + var(--default-grid-baseline) * 3);
}

.row__line {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	justify-content: space-between;
	gap: calc(var(--default-grid-baseline) * 2) calc(var(--default-grid-baseline) * 4);
}

.row__sync,
.row__matches {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2);
	min-width: 0;
}

.row__sync > :first-child {
	white-space: normal;
}

.row__muted {
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}

.row button.row__toggle {
	display: inline-flex;
	align-items: center;
	justify-content: center;
	width: 34px;
	min-width: 34px;
	height: 34px;
	min-height: 34px;
	margin: 0;
	padding: 0;
	border: none;
	border-radius: 50%;
	background: transparent;
	color: var(--color-text-maxcontrast);
	cursor: pointer;
}

.row button.row__toggle:hover {
	background-color: var(--color-background-hover);
	color: var(--color-main-text);
}

.row button.row__toggle:focus-visible {
	outline: 2px solid var(--color-main-text);
	outline-offset: 2px;
}

.row__chevron {
	transition: transform 180ms ease;
}

.row_expanded .row__chevron {
	transform: rotate(180deg);
}

.row__collapse {
	display: grid;
	grid-template-rows: 0fr;
	margin-top: calc(var(--default-grid-baseline) * -3);
	opacity: 0;
	transition: grid-template-rows 180ms ease, opacity 180ms ease;
}

.row_expanded .row__collapse {
	grid-template-rows: 1fr;
	margin-top: 0;
	opacity: 1;
}

.row_expanded .row__collapseInner {
	padding-top: calc(var(--default-grid-baseline) * 3);
	border-top: 1px solid var(--color-border);
}

.row__collapseInner {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 4);
	min-height: 0;
	overflow: hidden;
	padding-inline-start: calc(36px + var(--default-grid-baseline) * 3);
}

.details {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(min(100%, 280px), 1fr));
	gap: calc(var(--default-grid-baseline) * 3) calc(var(--default-grid-baseline) * 5);
	margin: 0;
}

.details dt {
	margin-bottom: calc(var(--default-grid-baseline) * 1);
	color: var(--color-text-maxcontrast);
	font-size: 0.8em;
	font-weight: 700;
	letter-spacing: 0.06em;
	text-transform: uppercase;
}

.details dd {
	margin: 0;
}

.details__inline {
	display: flex;
	flex-direction: column;
	align-items: flex-start;
	gap: calc(var(--default-grid-baseline) * 1);
}

.url {
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
	font-size: 0.9em;
	overflow-wrap: anywhere;
}

.sample {
	display: flex;
	flex-wrap: wrap;
	gap: calc(var(--default-grid-baseline) * 1.5);
}

.sample code {
	padding-inline: calc(var(--default-grid-baseline) * 1.5);
	border-radius: var(--border-radius-element);
	background-color: var(--color-background-hover);
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
	font-size: 0.85em;
}

.interval {
	display: flex;
	flex-wrap: wrap;
	align-items: flex-end;
	gap: calc(var(--default-grid-baseline) * 2);
}

.interval__error {
	flex: 1 0 100%;
	margin: 0;
	color: var(--color-error-text);
	font-weight: 600;
}

.row__footer {
	display: flex;
	flex-wrap: wrap;
	gap: calc(var(--default-grid-baseline) * 2);
}

@media (max-width: 600px) {
	.row {
		padding: calc(var(--default-grid-baseline) * 3);
	}

	.row__body,
	.row__collapseInner {
		padding-inline-start: 0;
	}
}

@media (prefers-reduced-motion: reduce) {
	.row,
	.row__chevron,
	.row__collapse {
		transition: none;
	}
}
</style>
