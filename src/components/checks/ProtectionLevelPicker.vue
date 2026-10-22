<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { ProtectionLevel } from '../../types.ts'

import { t } from '@nextcloud/l10n'
import { computed, useId } from 'vue'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcRadioGroup from '@nextcloud/vue/components/NcRadioGroup'
import NcRadioGroupButton from '@nextcloud/vue/components/NcRadioGroupButton'
import { useAction } from '../../composables/useAction.ts'
import { chooseProtectionLevel, state } from '../../store.ts'
import { APP_ID } from '../../utils/format.ts'
import { vRadioGroupName } from '../../utils/radioGroupName.ts'

type Choosable = Exclude<ProtectionLevel, 'custom'>

const id = useId()
const { busy, run } = useAction()
const saving = computed(() => busy.value !== null)

/** From the loosest to the tightest limits */
const LEVELS: { value: ProtectionLevel, label: () => string, text: () => string }[] = [
	{ value: 'relaxed', label: () => t(APP_ID, 'Relaxed'), text: () => t(APP_ID, 'Checks fire at twice the usual counts, and blocks last half as long. For servers with many people behind one address.') },
	{ value: 'recommended', label: () => t(APP_ID, 'Recommended'), text: () => t(APP_ID, 'Balanced limits that suit most servers.') },
	{ value: 'strict', label: () => t(APP_ID, 'Strict'), text: () => t(APP_ID, 'Checks fire at half the usual counts, and blocks last twice as long. More false alarms are possible.') },
	{ value: 'custom', label: () => t(APP_ID, 'Custom'), text: () => t(APP_ID, 'Some limits were changed by hand. Choose a level to set them all again.') },
]

const current = computed(() => LEVELS.find((level) => level.value === state.protectionLevel) ?? LEVELS[1]!)
const shown = computed(() => LEVELS.filter((level) => level.value !== 'custom' || state.protectionLevel === 'custom'))

/**
 * Set every limit to a level: it applies at once, after the password confirmation.
 *
 * @param value - The chosen level
 */
function choose(value: ProtectionLevel) {
	if (value === state.protectionLevel || value === 'custom' || saving.value) {
		return
	}
	run('level', () => chooseProtectionLevel(value as Choosable), {
		done: () => t(APP_ID, 'Saved: the protection level is {level}.', { level: current.value.label() }),
		fallback: t(APP_ID, 'The protection level could not be changed. Please try again.'),
	})
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
