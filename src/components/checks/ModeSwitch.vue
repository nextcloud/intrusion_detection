<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Mode } from '../../types.ts'

import NcRadioGroup from '@nextcloud/vue/components/NcRadioGroup'
import NcRadioGroupButton from '@nextcloud/vue/components/NcRadioGroupButton'
import { modeLabel } from '../../store.ts'
import { vRadioGroupName } from '../../utils/radioGroupName.ts'

const mode = defineModel<Mode>({ required: true })

defineProps<{
	/** The accessible name, e.g. "Mode of Credential stuffing" */
	label: string
	/** Only Off can be chosen, e.g. while a requirement is missing */
	onlyOff?: boolean
	disabled?: boolean
}>()

const modes: Mode[] = ['off', 'observe', 'protect']
</script>

<template>
	<NcRadioGroup
		v-model="mode"
		v-radio-group-name
		:class="$style.modeSwitch"
		:label="label"
		hideLabel>
		<NcRadioGroupButton
			v-for="option in modes"
			:key="option"
			:value="option"
			:label="modeLabel(option)"
			:disabled="disabled || (onlyOff && option !== 'off')" />
	</NcRadioGroup>
</template>

<style module>
.modeSwitch {
	flex: 0 0 auto;
	min-width: 0;
}
</style>
