<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { mdiLogoutVariant } from '@mdi/js'
import { showError, showSuccess } from '@nextcloud/dialogs'
import { n, t } from '@nextcloud/l10n'
import { computed, ref } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import SectionCard from '../../components/common/SectionCard.vue'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { errorMessage, isCancelled } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { APP_ID } from '../../utils/format.ts'
import { logOutElsewhere } from '../api.ts'
import { personal } from '../store.ts'

const dialog = ref(false)
const busy = ref(false)
const { announce } = useAnnouncer()

/**
 * End the other sessions, after the password.
 */
async function run() {
	dialog.value = false
	busy.value = true
	try {
		const result = await logOutElsewhere()
		const message = result.sessions === 0
			? t(APP_ID, 'No other browser was logged in.')
			: n(APP_ID, 'Logged out of %n other browser.', 'Logged out of %n other browsers.', result.sessions)
		const devices = result.devices > 0
			? ' ' + n(APP_ID, '%n remembered device was forgotten.', '%n remembered devices were forgotten.', result.devices)
			: ''
		showSuccess(message + devices)
		announce(message + devices)
		personal.devicesVersion++
	} catch (error) {
		if (isCancelled(error)) {
			return
		}
		logger.error('Could not log out everywhere else', { error })
		const message = errorMessage(error, t(APP_ID, 'The other sessions could not be ended. Please try again.'))
		showError(message)
		announce(message)
	} finally {
		busy.value = false
	}
}

const buttons = computed(() => [
	{ label: t(APP_ID, 'Cancel'), callback: () => undefined },
	{ label: t(APP_ID, 'Log out everywhere else'), variant: 'error' as const, callback: () => { run() } },
])
</script>

<template>
	<SectionCard :heading="t(APP_ID, 'Log out everywhere else')" :icon="mdiLogoutVariant" data-test="log-out-elsewhere">
		<template #description>
			{{ t(APP_ID, 'Ends every other browser session of your account and forgets the other remembered devices. You stay logged in here.') }}
		</template>

		<p :class="$style.note">
			{{ t(APP_ID, 'Apps and devices connected with app passwords keep working. To disconnect them, revoke their app passwords in "Devices & sessions" above.') }}
		</p>
		<div>
			<NcButton
				variant="error"
				:disabled="busy"
				data-test="log-out-elsewhere-button"
				@click="dialog = true">
				<template #icon>
					<NcLoadingIcon v-if="busy" :size="20" />
					<NcIconSvgWrapper v-else :path="mdiLogoutVariant" />
				</template>
				{{ t(APP_ID, 'Log out everywhere else') }}
			</NcButton>
		</div>

		<NcDialog
			v-model:open="dialog"
			:name="t(APP_ID, 'Log out everywhere else?')"
			:buttons="buttons"
			size="normal">
			<p :class="$style.dialog">
				{{ t(APP_ID, 'Every other browser logged in to your account is logged out at once, and the other remembered devices must confirm their next login again. Nextcloud asks for your password first.') }}
			</p>
		</NcDialog>
	</SectionCard>
</template>

<style module>
.note {
	margin: 0;
	max-width: 75ch;
	color: var(--color-text-maxcontrast);
	line-height: 1.5;
}

.dialog {
	margin: 0 0 calc(var(--default-grid-baseline) * 2);
	line-height: 1.5;
}
</style>
