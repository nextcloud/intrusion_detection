<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Mode } from '../../types.ts'

import { t } from '@nextcloud/l10n'
import NcRadioGroup from '@nextcloud/vue/components/NcRadioGroup'
import NcRadioGroupButton from '@nextcloud/vue/components/NcRadioGroupButton'
import { APP_ID } from '../../utils/format.ts'

const mode = defineModel<Mode>({ required: true })

defineProps<{
	/** The accessible name, e.g. "Mode of Credential stuffing" */
	label: string
	/** Only Off can be chosen, e.g. while a requirement is missing */
	onlyOff?: boolean
	disabled?: boolean
}>()

const modes: { value: Mode, label: () => string }[] = [
	{ value: 'off', label: () => t(APP_ID, 'Off') },
	{ value: 'observe', label: () => t(APP_ID, 'Observe') },
	{ value: 'protect', label: () => t(APP_ID, 'Protect') },
]
</script>

<template>
	<NcRadioGroup
		v-model="mode"
		:class="$style.modeSwitch"
		:label="label"
		hideLabel>
		<NcRadioGroupButton
			v-for="option in modes"
			:key="option.value"
			:value="option.value"
			:label="option.label()"
			:disabled="disabled || (onlyOff && option.value !== 'off')" />
	</NcRadioGroup>
</template>

<style module>
.modeSwitch {
	flex: 0 0 auto;
	min-width: 0;
}
</style>
