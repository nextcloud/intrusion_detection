<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Status } from '../types.ts'

import { mdiShieldCheckOutline, mdiShieldOffOutline, mdiShieldSearch, mdiSpeedometer } from '@mdi/js'
import { showError, showSuccess } from '@nextcloud/dialogs'
import { getCanonicalLocale, n, t } from '@nextcloud/l10n'
import { computed, ref } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import ProblemList from './ProblemList.vue'
import { useAnnouncer } from '../composables/useAnnouncer.ts'
import { statusSections } from '../extensions.ts'
import { errorMessage, isCancelled, updateLearning, updateSettings } from '../services/api.ts'
import { logger } from '../services/logger.ts'
import { refreshChecks, refreshSettings, refreshStatus } from '../store.ts'
import { APP_ID, formatCost, formatNumber } from '../utils/format.ts'

const props = defineProps<{
	status: Status
}>()

const busy = ref<string | null>(null)
const { announce } = useAnnouncer()

const icon = computed(() => ({
	protecting: mdiShieldCheckOutline,
	learning: mdiShieldSearch,
	off: mdiShieldOffOutline,
})[props.status.state])

const title = computed(() => {
	switch (props.status.state) {
		case 'learning':
			return n(APP_ID, 'Learning: %n day left.', 'Learning: %n days left.', props.status.learning.daysLeft)
		case 'off':
			return t(APP_ID, 'Off.')
		default:
			return t(APP_ID, 'Protecting.')
	}
})

const sentence = computed(() => {
	const { checks, learning, state } = props.status
	if (state === 'off') {
		return t(APP_ID, 'No checks run, nothing is recorded and blocked addresses can reach the server again.')
	}
	if (state === 'learning') {
		const until = new Date(learning.until * 1000).toLocaleDateString(getCanonicalLocale(), { weekday: 'long', day: 'numeric', month: 'long' })
		return t(APP_ID, 'Nextcloud is watching, not acting: checks set to Protect only record what they would have done until {date}. Blocks you add by hand apply.', { date: until })
	}
	if (checks.protect + checks.observe + checks.off === 0) {
		return t(APP_ID, 'Blocks you add by hand are enforced. No checks are installed yet.')
	}
	return t(APP_ID, '{protecting}, {observing}, {off}.', {
		protecting: n(APP_ID, '%n check protects', '%n checks protect', checks.protect),
		observing: n(APP_ID, '%n observes', '%n observe', checks.observe),
		off: n(APP_ID, '%n is off', '%n are off', checks.off),
	})
})

const figures = computed(() => {
	const last = props.status.last24h
	const learning = props.status.state === 'learning'
	return [
		learning
			? { id: 'would', value: formatNumber(last.wouldHaveBlocked), label: t(APP_ID, 'addresses it would have blocked') }
			: { id: 'blocked', value: formatNumber(last.blockedAddresses), label: t(APP_ID, 'addresses blocked') },
		{
			id: 'detections',
			value: formatNumber(last.detections),
			label: n(APP_ID, 'detection', 'detections', last.detections),
			detail: last.detections > 0 ? t(APP_ID, '{enforced} acted on, {observed} observed', { enforced: formatNumber(last.enforced), observed: formatNumber(last.observed) }) : undefined,
		},
		{ id: 'accounts', value: formatNumber(last.accounts), label: n(APP_ID, 'account concerned', 'accounts concerned', last.accounts) },
		{ id: 'bans', value: formatNumber(props.status.activeBans), label: n(APP_ID, 'block active now', 'blocks active now', props.status.activeBans) },
	]
})

const costLine = computed(() => {
	const { cost, costSampleRate } = props.status
	if (cost === null) {
		return props.status.prerequisites.memoryCache === 'none'
			? t(APP_ID, 'Cost on every request: not measured. Measuring needs a memory cache; without one, every request asks the database whether its address is blocked.')
			: t(APP_ID, 'Cost on every request: not measured yet. It is measured on 1 in {rate} requests.', { rate: formatNumber(costSampleRate) })
	}
	return t(APP_ID, 'Cost on every request: {average} on average, {max} at most (measured on 1 in {rate} requests over the last 24 hours).', {
		average: formatCost(cost.averageMicroseconds),
		max: formatCost(cost.maxMicroseconds),
		rate: formatNumber(costSampleRate),
	})
})

/**
 * Run an action of the banner and reload what it changes.
 *
 * @param id - Which action, for the loading state
 * @param action - The request
 * @param done - The message when it worked
 */
async function run(id: string, action: () => Promise<unknown>, done: string) {
	busy.value = id
	try {
		await action()
		await Promise.all([refreshStatus(), refreshChecks(), refreshSettings()])
		showSuccess(done)
		announce(done)
	} catch (error) {
		if (isCancelled(error)) {
			return
		}
		logger.error('Intrusion detection action failed', { error })
		showError(errorMessage(error, t(APP_ID, 'That did not work. Please reload the page and try again.')))
	} finally {
		busy.value = null
	}
}

const startProtecting = () => run('protect', () => updateLearning('stop'), t(APP_ID, 'Protection is active. Checks set to Protect act from now on.'))
const observeLonger = () => run('extend', () => updateLearning('extend', 7), t(APP_ID, 'Learning mode was extended by 7 days.'))
const turnOn = () => run('on', () => updateSettings({ protection_enabled: true }), t(APP_ID, 'Intrusion detection is on.'))
</script>

<template>
	<section :class="[$style.banner, $style[`banner_${status.state}`]]" aria-labelledby="ids-status-title">
		<div :class="$style.banner__head">
			<span :class="$style.banner__icon" aria-hidden="true">
				<NcIconSvgWrapper :path="icon" :size="28" />
			</span>
			<div :class="$style.banner__text">
				<h3 id="ids-status-title" :class="$style.banner__title">
					{{ title }}
				</h3>
				<p :class="$style.banner__sentence">
					{{ sentence }}
				</p>
			</div>
			<div :class="$style.banner__actions">
				<template v-if="status.state === 'learning'">
					<NcButton variant="primary" :disabled="busy !== null" @click="startProtecting">
						<template v-if="busy === 'protect'" #icon>
							<NcLoadingIcon />
						</template>
						{{ t(APP_ID, 'Start protecting now') }}
					</NcButton>
					<NcButton variant="secondary" :disabled="busy !== null" @click="observeLonger">
						<template v-if="busy === 'extend'" #icon>
							<NcLoadingIcon />
						</template>
						{{ t(APP_ID, 'Observe 7 more days') }}
					</NcButton>
				</template>
				<NcButton
					v-else-if="status.state === 'off'"
					variant="primary"
					:disabled="busy !== null"
					@click="turnOn">
					<template v-if="busy === 'on'" #icon>
						<NcLoadingIcon />
					</template>
					{{ t(APP_ID, 'Turn on') }}
				</NcButton>
			</div>
		</div>

		<div>
			<p :class="$style.banner__period">
				{{ t(APP_ID, 'In the last 24 hours') }}
			</p>
			<dl :class="$style.figures">
				<div v-for="figure in figures" :key="figure.id" :class="$style.figure">
					<dt :class="$style.figure__label">
						{{ figure.label }}
					</dt>
					<dd :class="$style.figure__value">
						{{ figure.value }}
					</dd>
					<dd v-if="figure.detail" :class="$style.figure__detail">
						{{ figure.detail }}
					</dd>
				</div>
			</dl>
		</div>

		<p :class="$style.banner__cost">
			<NcIconSvgWrapper :path="mdiSpeedometer" :size="18" />
			<span>{{ costLine }}</span>
		</p>

		<component :is="section" v-for="(section, index) in statusSections" :key="index" />
	</section>

	<ProblemList v-if="status.problems.length > 0" :problems="status.problems" />
</template>

<style module>
.banner {
	--state-color: var(--color-success);
	--state-text: var(--color-success-text);
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 4);
	padding: calc(var(--default-grid-baseline) * 6);
	border: 1px solid color-mix(in srgb, var(--state-color) 30%, var(--color-border));
	border-radius: var(--border-radius-container, var(--border-radius-large));
	background-color: color-mix(in srgb, var(--state-color) 12%, var(--color-main-background));
}

.banner_learning {
	--state-color: var(--color-info);
	--state-text: var(--color-info-text);
}

.banner_off {
	--state-color: var(--color-warning);
	--state-text: var(--color-warning-text);
}

.banner__head {
	display: flex;
	flex-wrap: wrap;
	align-items: flex-start;
	gap: calc(var(--default-grid-baseline) * 4);
}

.banner__icon {
	display: inline-flex;
	flex: 0 0 auto;
	align-items: center;
	justify-content: center;
	width: 52px;
	height: 52px;
	border-radius: 50%;
	background-color: color-mix(in srgb, var(--state-color) 20%, var(--color-main-background));
	color: var(--state-text);
}

.banner__text {
	flex: 1 1 200px;
	min-width: 0;
}

.banner__title {
	margin: 0;
	color: var(--state-text);
	font-size: 1.45em;
	font-weight: 700;
	line-height: 1.3;
}

.banner__sentence {
	margin-block: calc(var(--default-grid-baseline) * 1) 0;
	max-width: 70ch;
	line-height: 1.5;
}

.banner__actions {
	display: flex;
	flex-wrap: wrap;
	gap: calc(var(--default-grid-baseline) * 2);
	margin-inline-start: auto;
}

.figures {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
	gap: calc(var(--default-grid-baseline) * 3);
	margin: 0;
}

.figure {
	display: flex;
	flex-direction: column;
	padding: calc(var(--default-grid-baseline) * 3) calc(var(--default-grid-baseline) * 4);
	border-radius: var(--border-radius-large);
	background-color: color-mix(in srgb, var(--color-main-background) 72%, transparent);
}

.figure dd,
.figure dt {
	margin: 0;
	padding: 0;
	text-align: start;
}

.figure__value {
	order: -1;
	margin: 0;
	font-size: 2em;
	font-weight: 700;
	line-height: 1.15;
	font-variant-numeric: tabular-nums;
}

.figure__label {
	color: var(--color-text-maxcontrast);
	font-size: 0.92em;
}

.figure__detail {
	margin: calc(var(--default-grid-baseline) / 2) 0 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.85em;
}

.banner__period {
	margin: 0 0 calc(var(--default-grid-baseline) * 2);
	color: var(--color-text-maxcontrast);
	font-size: 0.8em;
	font-weight: 600;
	letter-spacing: 0.06em;
	text-transform: uppercase;
}

.banner__cost {
	display: flex;
	align-items: flex-start;
	gap: calc(var(--default-grid-baseline) * 2);
	margin: 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.92em;
}

.banner__cost > :first-child {
	flex: 0 0 auto;
	margin-top: 1px;
}

@media (max-width: 600px) {
	.banner {
		padding: calc(var(--default-grid-baseline) * 4);
	}

	.banner__actions {
		margin-inline-start: 0;
		width: 100%;
	}

	.figures {
		grid-template-columns: repeat(2, minmax(0, 1fr));
	}
}
</style>
