<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Status } from '../types.ts'

import { showError, showSuccess } from '@nextcloud/dialogs'
import { n, t } from '@nextcloud/l10n'
import { computed, ref, useId } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import { useAnnouncer } from '../composables/useAnnouncer.ts'
import { statusSections } from '../extensions.ts'
import { errorMessage, isCancelled, updateLearning, updateSettings } from '../services/api.ts'
import { logger } from '../services/logger.ts'
import { refreshChecks, refreshSettings, refreshStatus } from '../store.ts'
import { APP_ID, formatNumber } from '../utils/format.ts'

const props = defineProps<{
	status: Status
}>()

const id = useId()
const busy = ref<string | null>(null)
const { announce } = useAnnouncer()

/** How many checks protect, observe or are off */
const checksLine = computed(() => {
	const { checks } = props.status
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
			detail: last.detections > 0 ? t(APP_ID, '{enforced} handled, {observed} only observed', { enforced: formatNumber(last.enforced), observed: formatNumber(last.observed) }) : undefined,
		},
		{ id: 'accounts', value: formatNumber(last.accounts), label: n(APP_ID, 'account targeted', 'accounts targeted', last.accounts) },
		{ id: 'bans', value: formatNumber(props.status.activeBans), label: n(APP_ID, 'block active now', 'blocks active now', props.status.activeBans) },
	]
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
	<section :class="$style.banner" :aria-labelledby="`${id}-heading`" data-test="status-summary">
		<div :class="$style.banner__head">
			<h3 :id="`${id}-heading`" :class="$style.banner__heading">
				{{ t(APP_ID, 'Last 24 hours') }}
			</h3>
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

		<dl :class="$style.figures" data-test="status-figures">
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
		<p :class="$style.banner__muted">
			{{ checksLine }}
		</p>

		<component :is="section" v-for="(section, index) in statusSections" :key="index" />
	</section>
</template>

<style module>
.banner {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 4);
	padding: calc(var(--default-grid-baseline) * 5);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
	background-color: var(--color-main-background);
}

.banner__head {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	justify-content: space-between;
	gap: calc(var(--default-grid-baseline) * 3);
}

.banner__heading {
	flex: 1 1 auto;
	margin: 0;
	font-size: 1.1em;
	font-weight: 700;
}

.banner__actions {
	display: flex;
	flex-wrap: wrap;
	gap: calc(var(--default-grid-baseline) * 2);
}

.banner__muted {
	margin: 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.92em;
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
	min-width: 0;
	padding: calc(var(--default-grid-baseline) * 3) calc(var(--default-grid-baseline) * 4);
	border-radius: var(--border-radius-large);
	background-color: var(--color-background-hover);
}

.figure dd,
.figure dt {
	margin: 0;
	padding: 0;
	text-align: start;
}

.figure__value {
	order: -1;
	font-size: 1.8em;
	font-weight: 700;
	line-height: 1.15;
	font-variant-numeric: tabular-nums;
}

.figure__label {
	color: var(--color-text-maxcontrast);
	font-size: 0.92em;
	overflow-wrap: anywhere;
}

.figure__detail {
	margin: calc(var(--default-grid-baseline) / 2) 0 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.85em;
}

@media (max-width: 600px) {
	.banner {
		padding: calc(var(--default-grid-baseline) * 4);
	}

	.figures {
		grid-template-columns: repeat(2, minmax(0, 1fr));
		gap: calc(var(--default-grid-baseline) * 2);
	}

	.figure__value {
		font-size: 1.5em;
	}
}
</style>
