<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { showError, showSuccess } from '@nextcloud/dialogs'
import { t } from '@nextcloud/l10n'
import { computed, ref } from 'vue'
import NcCheckboxRadioSwitch from '@nextcloud/vue/components/NcCheckboxRadioSwitch'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import { useAnnouncer } from '../composables/useAnnouncer.ts'
import { errorMessage, isCancelled, updateSettings } from '../services/api.ts'
import { logger } from '../services/logger.ts'
import { refreshChecks, refreshStatus, state } from '../store.ts'
import { APP_ID } from '../utils/format.ts'

const busy = ref(false)
const confirmOff = ref(false)
const { announce } = useAnnouncer()

const enabled = computed(() => state.settings.find((s) => s.name === 'protection_enabled')?.value !== false)

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
	busy.value = true
	try {
		const payload = await updateSettings({ protection_enabled: on })
		state.settings = payload.settings
		await Promise.all([refreshStatus(), refreshChecks()])
		const done = on ? t(APP_ID, 'Intrusion detection is on.') : t(APP_ID, 'Intrusion detection is off.')
		showSuccess(done)
		announce(done)
	} catch (error) {
		if (!isCancelled(error)) {
			logger.error('Could not switch intrusion detection', { error })
			showError(errorMessage(error, t(APP_ID, 'That did not work. Please try again.')))
		}
	} finally {
		busy.value = false
	}
}
</script>

<template>
	<div :class="$style.switch" data-test="master-switch">
		<NcCheckboxRadioSwitch
			:modelValue="enabled"
			type="switch"
			:loading="busy"
			:disabled="busy"
			@update:modelValue="toggle">
			{{ t(APP_ID, 'Intrusion detection is on') }}
		</NcCheckboxRadioSwitch>

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
</style>
