<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { mdiDownload, mdiRestore } from '@mdi/js'
import { showError, showSuccess } from '@nextcloud/dialogs'
import { getCanonicalLocale, n, t } from '@nextcloud/l10n'
import { computed, ref } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcCheckboxRadioSwitch from '@nextcloud/vue/components/NcCheckboxRadioSwitch'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import SettingsGroup from '../components/common/SettingsGroup.vue'
import { useAnnouncer } from '../composables/useAnnouncer.ts'
import { errorMessage, exportSettings, isCancelled, resetSettings, updateLearning, updateSettings } from '../services/api.ts'
import { logger } from '../services/logger.ts'
import { refreshChecks, refreshStatus, state } from '../store.ts'
import { APP_ID } from '../utils/format.ts'

const busy = ref<string | null>(null)
const days = ref(7)
const confirmOff = ref(false)
const confirmReset = ref(false)
const { announce } = useAnnouncer()

const learning = computed(() => state.status?.learning ?? { active: false, until: 0, daysLeft: 0, minDays: 1, maxDays: 30 })
const enabled = computed(() => state.settings.find((s) => s.name === 'protection_enabled')?.value !== false)
const learningUntil = computed(() => new Date(learning.value.until * 1000).toLocaleString(getCanonicalLocale(), { dateStyle: 'full', timeStyle: 'short' }))
const daysValid = computed(() => Number.isInteger(days.value) && days.value >= learning.value.minDays && days.value <= learning.value.maxDays)

const learningSettings = computed(() => state.settings.filter((s) => s.group === 'learning'))
const otherSettings = computed(() => state.settings.filter((s) => s.group === 'notifications' || s.group === 'privacy' || s.group === 'other'))

/**
 * Run an action and reload what it changes.
 *
 * @param id - Which action, for the loading state
 * @param action - The request
 * @param done - What to say when it worked
 */
async function run(id: string, action: () => Promise<unknown>, done: string): Promise<boolean> {
	busy.value = id
	try {
		await action()
		await Promise.all([refreshStatus(), refreshChecks()])
		showSuccess(done)
		announce(done)
		return true
	} catch (error) {
		if (!isCancelled(error)) {
			logger.error('Intrusion detection action failed', { error })
			showError(errorMessage(error, t(APP_ID, 'That did not work. Please try again.')))
		}
		return false
	} finally {
		busy.value = null
	}
}

const startLearning = () => run('start', () => updateLearning('start', days.value), n(APP_ID, 'Learning mode is on for %n day.', 'Learning mode is on for %n days.', days.value))
const extendLearning = () => run('extend', () => updateLearning('extend', days.value), n(APP_ID, 'Learning mode was extended by %n day.', 'Learning mode was extended by %n days.', days.value))
const stopLearning = () => run('stop', () => updateLearning('stop'), t(APP_ID, 'Learning mode ended. Checks set to Protect act from now on.'))

/**
 * @param on - The new state of the master switch
 */
async function setEnabled(on: boolean) {
	if (!on) {
		confirmOff.value = true
		return
	}
	await switchTo(true)
}

/**
 * @param on - The new state
 */
async function switchTo(on: boolean) {
	await run(on ? 'on' : 'off', async () => {
		const payload = await updateSettings({ protection_enabled: on })
		state.settings = payload.settings
	}, on ? t(APP_ID, 'Intrusion detection is on.') : t(APP_ID, 'Intrusion detection is off.'))
	confirmOff.value = false
}

/**
 * Reset everything, after the confirmation.
 */
async function resetAll() {
	await run('reset', async () => {
		const payload = await resetSettings()
		state.settings = payload.settings
		state.templates = payload.templates
	}, t(APP_ID, 'All settings are back to their defaults.'))
	confirmReset.value = false
}

/**
 * Download the settings as a JSON file.
 */
async function download() {
	busy.value = 'export'
	try {
		const data = await exportSettings()
		const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
		const link = document.createElement('a')
		link.href = URL.createObjectURL(blob)
		link.download = `intrusion-detection-settings-${new Date().toISOString().slice(0, 10)}.json`
		link.click()
		URL.revokeObjectURL(link.href)
		announce(t(APP_ID, 'The settings were downloaded.'))
	} catch (error) {
		logger.error('Could not export the settings', { error })
		showError(errorMessage(error, t(APP_ID, 'The settings could not be exported.')))
	} finally {
		busy.value = null
	}
}
</script>

<template>
	<div :class="$style.advanced">
		<section :class="$style.card" aria-labelledby="ids-learning-heading">
			<h3 id="ids-learning-heading" :class="$style.card__heading">
				{{ t(APP_ID, 'Learning mode') }}
			</h3>
			<p :class="$style.card__text">
				{{ t(APP_ID, 'While Nextcloud is learning, every check set to Protect only observes: it records what it would have done, so you can see whether your settings fit before anything is blocked. It starts for 7 days when the app is installed.') }}
			</p>
			<p :class="[$style.card__state, { [$style.card__state_on]: learning.active }]">
				{{ learning.active ? t(APP_ID, 'Learning until {date}.', { date: learningUntil }) : t(APP_ID, 'Learning mode is off; checks set to Protect act.') }}
			</p>
			<div :class="$style.card__row">
				<label :class="$style.days">
					<span :class="$style.days__label">{{ t(APP_ID, 'Days') }}</span>
					<input
						v-model.number="days"
						type="number"
						:min="learning.minDays"
						:max="learning.maxDays"
						step="1"
						:aria-invalid="daysValid ? undefined : 'true'"
						aria-describedby="ids-days-hint">
				</label>
				<NcButton
					v-if="!learning.active"
					variant="secondary"
					:disabled="!daysValid || busy !== null"
					@click="startLearning">
					<template v-if="busy === 'start'" #icon>
						<NcLoadingIcon />
					</template>
					{{ t(APP_ID, 'Start learning') }}
				</NcButton>
				<template v-else>
					<NcButton variant="secondary" :disabled="!daysValid || busy !== null" @click="extendLearning">
						<template v-if="busy === 'extend'" #icon>
							<NcLoadingIcon />
						</template>
						{{ t(APP_ID, 'Extend') }}
					</NcButton>
					<NcButton variant="primary" :disabled="busy !== null" @click="stopLearning">
						<template v-if="busy === 'stop'" #icon>
							<NcLoadingIcon />
						</template>
						{{ t(APP_ID, 'Stop learning and protect') }}
					</NcButton>
				</template>
			</div>
			<p id="ids-days-hint" :class="[$style.card__hint, { [$style.card__hint_error]: !daysValid }]">
				{{ t(APP_ID, 'From {min} to {max} days.', { min: learning.minDays, max: learning.maxDays }) }}
			</p>
			<SettingsGroup v-if="learningSettings.length > 0" :settings="learningSettings" />
		</section>

		<section :class="$style.card" aria-labelledby="ids-master-heading">
			<h3 id="ids-master-heading" :class="$style.card__heading">
				{{ t(APP_ID, 'Master switch') }}
			</h3>
			<NcCheckboxRadioSwitch
				:modelValue="enabled"
				type="switch"
				:loading="busy === 'on' || busy === 'off'"
				:disabled="busy !== null"
				:description="t(APP_ID, 'When it is off, no check runs, nothing is recorded and existing blocks are not enforced.')"
				@update:modelValue="setEnabled">
				{{ t(APP_ID, 'Intrusion detection is on') }}
			</NcCheckboxRadioSwitch>
		</section>

		<section v-if="otherSettings.length > 0" :class="$style.card" aria-labelledby="ids-other-heading">
			<h3 id="ids-other-heading" :class="$style.card__heading">
				{{ t(APP_ID, 'Other settings') }}
			</h3>
			<SettingsGroup :settings="otherSettings" />
		</section>

		<section :class="$style.card" aria-labelledby="ids-maintenance-heading">
			<h3 id="ids-maintenance-heading" :class="$style.card__heading">
				{{ t(APP_ID, 'Support and reset') }}
			</h3>
			<p :class="$style.card__text">
				{{ t(APP_ID, 'The export contains every setting of every check, without detections, blocks or any personal data. Attach it when you ask for support.') }}
			</p>
			<div :class="$style.card__row">
				<NcButton variant="secondary" :disabled="busy !== null" @click="download">
					<template #icon>
						<NcLoadingIcon v-if="busy === 'export'" />
						<NcIconSvgWrapper v-else :path="mdiDownload" />
					</template>
					{{ t(APP_ID, 'Export settings as JSON') }}
				</NcButton>
				<NcButton variant="error" :disabled="busy !== null" @click="confirmReset = true">
					<template #icon>
						<NcIconSvgWrapper :path="mdiRestore" />
					</template>
					{{ t(APP_ID, 'Reset all settings to defaults') }}
				</NcButton>
			</div>
		</section>

		<NcDialog
			v-model:open="confirmOff"
			:name="t(APP_ID, 'Turn off intrusion detection?')"
			:message="t(APP_ID, 'No check runs and nothing is recorded while it is off. Existing blocks are not enforced, so blocked addresses can reach the server again at once.')"
			:buttons="[
				{ label: t(APP_ID, 'Cancel'), callback: () => undefined },
				{ label: t(APP_ID, 'Turn off'), variant: 'error', callback: () => { switchTo(false); return false } },
			]" />

		<NcDialog
			v-model:open="confirmReset"
			:name="t(APP_ID, 'Reset all settings?')"
			:message="t(APP_ID, 'Every check goes back to its default mode, responses and thresholds, and every setting on this page to its default. Detections, blocks and learning mode stay as they are.')"
			:buttons="[
				{ label: t(APP_ID, 'Cancel'), callback: () => undefined },
				{ label: t(APP_ID, 'Reset all settings'), variant: 'error', callback: () => { resetAll(); return false } },
			]" />
	</div>
</template>

<style module>
.advanced {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(min(100%, 420px), 1fr));
	gap: calc(var(--default-grid-baseline) * 5);
	align-items: start;
}

.card {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
	min-width: 0;
	padding: calc(var(--default-grid-baseline) * 5);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
	background-color: var(--color-main-background);
}

.card__heading {
	margin: 0;
	font-size: 1.15em;
	font-weight: 700;
}

.card__text {
	margin: 0;
	line-height: 1.6;
}

.card__state {
	margin: 0;
	padding: calc(var(--default-grid-baseline) * 2) calc(var(--default-grid-baseline) * 3);
	border-radius: var(--border-radius-element);
	background-color: var(--color-background-hover);
	font-weight: 600;
}

.card__state_on {
	background-color: color-mix(in srgb, var(--color-info) 12%, var(--color-main-background));
	color: var(--color-info-text);
}

.card__row {
	display: flex;
	flex-wrap: wrap;
	align-items: flex-end;
	gap: calc(var(--default-grid-baseline) * 2);
}

.card__hint {
	margin: 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}

.card__hint_error {
	color: var(--color-error-text);
	font-weight: 600;
}

.days {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1);
}

.days input {
	width: 6em;
	margin: 0;
}

.days__label {
	font-weight: 600;
}

@media (max-width: 600px) {
	.card {
		padding: calc(var(--default-grid-baseline) * 3);
	}
}
</style>
