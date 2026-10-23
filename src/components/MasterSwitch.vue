<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, ref } from 'vue'
import NcCheckboxRadioSwitch from '@nextcloud/vue/components/NcCheckboxRadioSwitch'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import { useAction } from '../composables/useAction.ts'
import { saveSettings, state } from '../store.ts'
import { APP_ID } from '../utils/format.ts'
import { t } from '../utils/l10n.ts'

const { busy, run } = useAction()
const confirmOff = ref(false)

const setting = computed(() => state.settings.find((s) => s.name === 'protection_enabled'))
const enabled = computed(() => setting.value?.value !== false)
/** config.php keeps it on */
const locked = computed(() => setting.value?.locked === true)

/**
 * @param on - The new state of the switch; turning it off asks first
 */
async function toggle(on: boolean) {
	if (on) {
		await switchTo(true)
	} else {
		confirmOff.value = true
	}
}

/**
 * @param on - The new state
 */
async function switchTo(on: boolean) {
	confirmOff.value = false
	await run('switch', () => saveSettings({ protection_enabled: on }), {
		done: on ? t(APP_ID, 'Intrusion detection is on.') : t(APP_ID, 'Intrusion detection is off.'),
		toast: true,
		fallback: t(APP_ID, 'That did not work. Please try again.'),
	})
}
</script>

<template>
	<div :class="$style.switch" data-test="master-switch">
		<NcCheckboxRadioSwitch
			:modelValue="enabled"
			type="switch"
			:loading="busy !== null"
			:disabled="busy !== null || locked"
			@update:modelValue="toggle">
			{{ t(APP_ID, 'Intrusion detection is on') }}
		</NcCheckboxRadioSwitch>
		<p v-if="locked" :class="$style.switch__note" data-test="master-switch-locked">
			{{ t(APP_ID, 'Locked in config.php') }}
		</p>

		<NcDialog
			v-model:open="confirmOff"
			:name="t(APP_ID, 'Turn off intrusion detection?')"
			:message="t(APP_ID, 'No check runs and nothing is recorded while it is off. Existing blocks are not enforced, so blocked addresses can reach the server again at once.')"
			:buttons="[
				{ label: t(APP_ID, 'Cancel'), callback: () => undefined },
				{ label: t(APP_ID, 'Turn off'), variant: 'error', callback: () => { switchTo(false); return false } },
			]" />
	</div>
</template>

<style module>
.switch {
	flex: 0 0 auto;
}

.switch__note {
	color: var(--color-text-maxcontrast);
}
</style>
