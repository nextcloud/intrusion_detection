<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { mdiDownload, mdiRestore } from '@mdi/js'
import { computed, ref } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcTextField from '@nextcloud/vue/components/NcTextField'
import SettingsGroup from '../common/SettingsGroup.vue'
import TimeStamp from '../common/TimeStamp.vue'
import { useAction } from '../../composables/useAction.ts'
import { exportSettings } from '../../services/api.ts'
import { changeLearning, resetAllSettings, state } from '../../store.ts'
import { APP_ID } from '../../utils/format.ts'
import { n, t } from '../../utils/l10n.ts'

const { busy, run } = useAction()
const days = ref(7)
const confirmReset = ref(false)

const learning = computed(() => state.status?.learning ?? { active: false, until: 0, daysLeft: 0, minDays: 1, maxDays: 30 })
const daysValid = computed(() => Number.isInteger(days.value) && days.value >= learning.value.minDays && days.value <= learning.value.maxDays)

/** Notification, privacy and confirmation settings have their own sections */
const otherSettings = computed(() => state.settings.filter((s) => s.group === 'approvals' || s.group === 'other'))

/**
 * Run an action.
 *
 * @param id - Which action, for the loading state
 * @param action - The change
 * @param done - What to say when it worked
 */
function act(id: string, action: () => Promise<void>, done: string): Promise<boolean> {
	return run(id, action, { done, toast: true, fallback: t(APP_ID, 'That did not work. Please try again.') })
}

const startLearning = () => act('start', () => changeLearning('start', days.value), n(APP_ID, 'Learning mode is on for %n day.', 'Learning mode is on for %n days.', days.value))
const extendLearning = () => act('extend', () => changeLearning('extend', days.value), n(APP_ID, 'Learning mode was extended by %n day.', 'Learning mode was extended by %n days.', days.value))
const stopLearning = () => act('stop', () => changeLearning('stop'), t(APP_ID, 'Learning mode ended. Checks set to Protect act from now on.'))

/**
 * Reset everything, after the confirmation.
 */
async function resetAll() {
	await act('reset', resetAllSettings, t(APP_ID, 'All settings are back to their defaults.'))
	confirmReset.value = false
}

/**
 * Download the settings as a JSON file.
 */
function download() {
	run('export', async () => {
		const data = await exportSettings()
		const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
		const link = document.createElement('a')
		link.href = URL.createObjectURL(blob)
		link.download = `intrusion-detection-settings-${new Date().toISOString().slice(0, 10)}.json`
		link.click()
		URL.revokeObjectURL(link.href)
	}, {
		done: t(APP_ID, 'The settings were downloaded.'),
		fallback: t(APP_ID, 'The settings could not be exported.'),
	})
}
</script>

<template>
	<div :class="$style.grid">
		<section :class="$style.card" aria-labelledby="ids-learning-heading">
			<h4 id="ids-learning-heading" :class="$style.card__heading">
				{{ t(APP_ID, 'Learning mode') }}
			</h4>
			<p :class="$style.card__text">
				{{ t(APP_ID, 'Checks set to Protect only record what they would block; earlier blocks, blocks you add by hand, a user\'s "No, it was not me", decoys and reserved names still block.') }}
				{{ t(APP_ID, 'Alerts are still sent.') }}
			</p>
			<p :class="[$style.card__state, { [$style.card__state_on]: learning.active }]">
				<template v-if="learning.active">
					{{ t(APP_ID, 'Learning ends') }} <TimeStamp :timestamp="learning.until" />.
				</template>
				<template v-else>
					{{ t(APP_ID, 'Learning mode is off; checks set to Protect act.') }}
				</template>
			</p>
			<div :class="$style.card__row">
				<NcTextField
					v-model.number="days"
					:class="$style.days"
					:label="t(APP_ID, 'Days')"
					type="number"
					:min="learning.minDays"
					:max="learning.maxDays"
					step="1"
					:error="!daysValid"
					aria-describedby="ids-days-hint" />
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
						{{ t(APP_ID, 'Start protecting now') }}
					</NcButton>
				</template>
			</div>
			<p id="ids-days-hint" :class="[$style.card__hint, { [$style.card__hint_error]: !daysValid }]">
				{{ t(APP_ID, 'From {min} to {max} days.', { min: learning.minDays, max: learning.maxDays }) }}
			</p>
		</section>

		<section
			v-if="otherSettings.length > 0"
			id="settings-other"
			:class="$style.card"
			aria-labelledby="ids-other-heading">
			<h4 id="ids-other-heading" :class="$style.card__heading">
				{{ t(APP_ID, 'Other settings') }}
			</h4>
			<SettingsGroup :settings="otherSettings" />
		</section>

		<section
			id="settings-support"
			:class="$style.card"
			aria-labelledby="ids-maintenance-heading">
			<h4 id="ids-maintenance-heading" :class="$style.card__heading">
				{{ t(APP_ID, 'Support and reset') }}
			</h4>
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
.grid {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(min(100%, 420px), 1fr));
	gap: var(--ids-space-5);
	align-items: start;
}

.card {
	composes: card from '../../styles/shared.module.css';
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-3);
	min-width: 0;
	padding: var(--ids-space-5);
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
	padding: var(--ids-space-2) var(--ids-space-3);
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
	gap: var(--ids-space-2);
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

.card__row .days {
	flex: 0 0 120px;
	margin: 0;
}

@media (max-width: 600px) {
	.card {
		padding: var(--ids-space-3);
	}
}
</style>
