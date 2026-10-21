<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { ProtectionLevel } from '../../types.ts'

import { showError } from '@nextcloud/dialogs'
import { t } from '@nextcloud/l10n'
import { computed, ref, useId } from 'vue'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcRadioGroup from '@nextcloud/vue/components/NcRadioGroup'
import NcRadioGroupButton from '@nextcloud/vue/components/NcRadioGroupButton'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { errorMessage, isCancelled, updateProtectionLevel } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { refreshSettings, state } from '../../store.ts'
import { APP_ID } from '../../utils/format.ts'
import { vRadioGroupName } from '../../utils/radioGroupName.ts'

type Choosable = Exclude<ProtectionLevel, 'custom'>

const id = useId()
const saving = ref(false)
const { announce } = useAnnouncer()

const LEVELS: { value: ProtectionLevel, label: () => string, text: () => string }[] = [
	{ value: 'recommended', label: () => t(APP_ID, 'Recommended'), text: () => t(APP_ID, 'Balanced limits that suit most servers.') },
	{ value: 'strict', label: () => t(APP_ID, 'Strict'), text: () => t(APP_ID, 'Checks fire at half the usual counts, and blocks last twice as long. More false alarms are possible.') },
	{ value: 'relaxed', label: () => t(APP_ID, 'Relaxed'), text: () => t(APP_ID, 'Checks fire at twice the usual counts, and blocks last half as long. For servers with many people behind one address.') },
	{ value: 'custom', label: () => t(APP_ID, 'Custom'), text: () => t(APP_ID, 'Some limits were changed by hand. Choose a level to set them all again.') },
]

const current = computed(() => LEVELS.find((level) => level.value === state.protectionLevel) ?? LEVELS[0]!)
const shown = computed(() => LEVELS.filter((level) => level.value !== 'custom' || state.protectionLevel === 'custom'))

/**
 * Set every limit to a level: it applies at once, after the password confirmation.
 *
 * @param value - The chosen level
 */
async function choose(value: ProtectionLevel) {
	if (value === state.protectionLevel || value === 'custom' || saving.value) {
		return
	}
	const previous = state.protectionLevel
	state.protectionLevel = value
	saving.value = true
	try {
		const result = await updateProtectionLevel(value as Choosable)
		state.protectionLevel = result.level
		state.checks = result.checks.checks
		state.categories = result.checks.categories
		await refreshSettings()
		announce(t(APP_ID, 'Saved: the protection level is {level}.', { level: current.value.label() }))
	} catch (error) {
		state.protectionLevel = previous
		if (!isCancelled(error)) {
			logger.error('Could not set the protection level', { error })
			const message = errorMessage(error, t(APP_ID, 'The protection level could not be changed. Please try again.'))
			showError(message)
			announce(message)
		}
	} finally {
		saving.value = false
	}
}
</script>

<template>
	<section :class="$style.level" :aria-labelledby="`${id}-heading`" data-test="protection-level">
		<div :class="$style.level__head">
			<h3 :id="`${id}-heading`" :class="$style.level__heading">
				{{ t(APP_ID, 'Protection level') }}
			</h3>
			<NcLoadingIcon v-if="saving" :size="20" :name="t(APP_ID, 'Saving')" />
		</div>
		<NcRadioGroup
			v-radio-group-name
			:modelValue="state.protectionLevel"
			:label="t(APP_ID, 'Protection level')"
			hideLabel
			@update:modelValue="choose">
			<NcRadioGroupButton
				v-for="level in shown"
				:key="level.value"
				:value="level.value"
				:label="level.label()"
				:disabled="saving || level.value === 'custom'" />
		</NcRadioGroup>
		<p :class="$style.level__text" aria-live="polite">
			{{ current.text() }}
			<span :class="$style.level__note">{{ t(APP_ID, 'Modes and responses stay as they are.') }}</span>
		</p>
	</section>
</template>

<style module>
.level {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
}

.level__head {
	display: flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2);
}

.level__heading {
	margin: 0;
	font-size: 1.15em;
	font-weight: 700;
}

.level__text {
	margin: 0;
	max-width: 80ch;
	line-height: 1.5;
}

.level__note {
	color: var(--color-text-maxcontrast);
}
</style>
