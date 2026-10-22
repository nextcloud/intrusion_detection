<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { mdiLogoutVariant } from '@mdi/js'
import { n, t } from '@nextcloud/l10n'
import { computed, ref } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import SectionCard from '../../components/common/SectionCard.vue'
import { useAction } from '../../composables/useAction.ts'
import { APP_ID } from '../../utils/format.ts'
import { logOutOtherBrowsers } from '../store.ts'

const dialog = ref(false)
const { busy, run } = useAction()

/**
 * End the other sessions, after the password.
 */
function logOut() {
	dialog.value = false
	run('log-out', logOutOtherBrowsers, {
		done: (result) => {
			const message = result.sessions === 0
				? t(APP_ID, 'No other browser was logged in.')
				: n(APP_ID, 'Logged out of %n other browser.', 'Logged out of %n other browsers.', result.sessions)
			const devices = result.devices > 0
				? ' ' + n(APP_ID, '%n remembered device was forgotten.', '%n remembered devices were forgotten.', result.devices)
				: ''
			return message + devices
		},
		toast: true,
		fallback: t(APP_ID, 'The other sessions could not be ended. Please try again.'),
	})
}

const buttons = computed(() => [
	{ label: t(APP_ID, 'Cancel'), callback: () => undefined },
	{ label: t(APP_ID, 'Log out other browsers'), variant: 'error' as const, callback: () => { logOut() } },
])
</script>

<template>
	<SectionCard
		:heading="t(APP_ID, 'Log out other browsers')"
		:icon="mdiLogoutVariant"
		level="h4"
		data-test="log-out-elsewhere">
		<template #description>
			{{ t(APP_ID, 'Logs out every other browser and forgets the other remembered devices. Unlike "Revoke all other sessions" above, your apps and app passwords stay connected.') }}
		</template>
		<div>
			<NcButton
				variant="error"
				:disabled="busy !== null"
				data-test="log-out-elsewhere-button"
				@click="dialog = true">
				<template #icon>
					<NcLoadingIcon v-if="busy !== null" :size="20" />
					<NcIconSvgWrapper v-else :path="mdiLogoutVariant" />
				</template>
				{{ t(APP_ID, 'Log out other browsers') }}
			</NcButton>
		</div>

		<NcDialog
			v-model:open="dialog"
			:name="t(APP_ID, 'Log out other browsers?')"
			:buttons="buttons"
			size="normal">
			<p :class="$style.dialog">
				{{ t(APP_ID, 'Every other browser logged in to your account is logged out at once, and the other remembered devices must confirm their next login again. Nextcloud asks for your password first.') }}
			</p>
		</NcDialog>
	</SectionCard>
</template>

<style module>
.dialog {
	margin: 0 0 calc(var(--default-grid-baseline) * 2);
	line-height: 1.5;
}
</style>
