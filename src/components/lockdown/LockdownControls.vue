<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { LockdownStatus } from '../../types.ts'

import { mdiLockOutline, mdiShieldLockOpenOutline, mdiTimerPlusOutline } from '@mdi/js'
import { showError, showSuccess } from '@nextcloud/dialogs'
import { t } from '@nextcloud/l10n'
import { computed, ref } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcSelect from '@nextcloud/vue/components/NcSelect'
import StartLockdownDialog from './StartLockdownDialog.vue'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { endLockdown, errorMessage, extendLockdown, isCancelled } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { refreshStatus } from '../../store.ts'
import { APP_ID, formatDuration } from '../../utils/format.ts'
import { formatUntil } from './summary.ts'

const props = defineProps<{
	/** The running lockdown, or null */
	lockdown: LockdownStatus | null
	/** Another action of the banner is running */
	disabled?: boolean
}>()

const HOUR = 3600
const MAX = 24 * HOUR

const starting = ref(false)
const extending = ref(false)
const ending = ref(false)
const busy = ref<string | null>(null)
const extendBy = ref(2)
const { announce } = useAnnouncer()

/** Extensions that keep the lockdown within 24 hours from now */
const extensions = computed(() => {
	const left = Math.max(0, (props.lockdown?.until ?? 0) - Date.now() / 1000)
	const max = Math.max(1, Math.floor((MAX - left) / HOUR))
	return Array.from({ length: max }, (_, i) => ({ id: i + 1, label: formatDuration((i + 1) * HOUR) }))
})

const extension = computed({
	get: () => extensions.value.find((option) => option.id === extendBy.value) ?? extensions.value[extensions.value.length - 1] ?? null,
	set: (option) => {
		if (option) {
			extendBy.value = option.id
		}
	},
})

/**
 * Run an action and reload the status.
 *
 * @param id - Which action, for the loading state
 * @param action - The request
 * @param done - The message when it worked
 */
async function run(id: string, action: () => Promise<unknown>, done: () => string) {
	busy.value = id
	try {
		await action()
		await refreshStatus()
		showSuccess(done())
		announce(done())
	} catch (error) {
		if (isCancelled(error)) {
			return
		}
		logger.error('Lockdown action failed', { error })
		showError(errorMessage(error, t(APP_ID, 'That did not work. Please reload the page and try again.')))
	} finally {
		busy.value = null
	}
}

const extend = () => run('extend', () => extendLockdown((extension.value?.id ?? 1) * HOUR), () => t(APP_ID, 'The lockdown was extended until {time}.', { time: formatUntil(props.lockdown?.until ?? 0) }))
const end = () => run('end', endLockdown, () => t(APP_ID, 'The lockdown has ended.'))

const extendButtons = computed(() => [
	{ label: t(APP_ID, 'Cancel'), callback: () => undefined },
	{ label: t(APP_ID, 'Extend lockdown'), variant: 'primary' as const, callback: () => { void extend() } },
])

const endButtons = computed(() => [
	{ label: t(APP_ID, 'Keep it'), callback: () => undefined },
	{ label: t(APP_ID, 'End lockdown'), variant: 'primary' as const, callback: () => { void end() } },
])

/**
 * The start dialog started one.
 */
async function started() {
	await refreshStatus()
	const done = t(APP_ID, 'Lockdown started. Every administrator was notified.')
	showSuccess(done)
	announce(done)
}
</script>

<template>
	<template v-if="lockdown">
		<NcButton :disabled="disabled || busy !== null" @click="extending = true">
			<template #icon>
				<NcLoadingIcon v-if="busy === 'extend'" :size="20" />
				<NcIconSvgWrapper v-else :path="mdiTimerPlusOutline" />
			</template>
			{{ t(APP_ID, 'Extend') }}
		</NcButton>
		<NcButton variant="primary" :disabled="disabled || busy !== null" @click="ending = true">
			<template #icon>
				<NcLoadingIcon v-if="busy === 'end'" :size="20" />
				<NcIconSvgWrapper v-else :path="mdiShieldLockOpenOutline" />
			</template>
			{{ t(APP_ID, 'End lockdown') }}
		</NcButton>
	</template>
	<NcButton v-else :disabled="disabled" @click="starting = true">
		<template #icon>
			<NcIconSvgWrapper :path="mdiLockOutline" />
		</template>
		{{ t(APP_ID, 'Start lockdown') }}
	</NcButton>

	<StartLockdownDialog v-if="starting" v-model:open="starting" @started="started" />

	<NcDialog
		v-if="extending"
		v-model:open="extending"
		:name="t(APP_ID, 'Extend the lockdown')"
		:buttons="extendButtons"
		size="small">
		<div :class="$style.dialog">
			<p>{{ t(APP_ID, 'The lockdown lasts until {time} now. A lockdown ends at most 24 hours from now.', { time: formatUntil(lockdown?.until ?? 0) }) }}</p>
			<NcSelect
				v-model="extension"
				:inputLabel="t(APP_ID, 'Extend by')"
				:options="extensions"
				:clearable="false"
				:searchable="false"
				label="label" />
		</div>
	</NcDialog>

	<NcDialog
		v-if="ending"
		v-model:open="ending"
		:name="t(APP_ID, 'End the lockdown?')"
		:message="t(APP_ID, 'Logins, sensitive actions, new devices and password reset work as usual again at once. Every administrator is notified.')"
		:buttons="endButtons"
		size="small" />
</template>

<style module>
.dialog {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 4);
	padding-bottom: calc(var(--default-grid-baseline) * 2);
}

.dialog p {
	margin: 0;
	line-height: 1.5;
}
</style>
