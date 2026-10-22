<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { StaleCredential } from '../types.ts'

import { mdiDeleteOutline, mdiKeyOutline, mdiWeb } from '@mdi/js'
import { showError, showSuccess } from '@nextcloud/dialogs'
import { n, t } from '@nextcloud/l10n'
import { computed, ref } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import SectionCard from '../../components/common/SectionCard.vue'
import TimeStamp from '../../components/common/TimeStamp.vue'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { errorMessage, isCancelled } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { APP_ID } from '../../utils/format.ts'
import { removeAllStaleCredentials, removeStaleCredential } from '../api.ts'
import { personal } from '../store.ts'

/** The credential being removed, or 'all' */
const removing = ref<number | 'all' | null>(null)
const confirmAll = ref(false)
const { announce } = useAnnouncer()
const credentials = computed(() => personal.staleCredentials)
const timeZone = computed(() => personal.overview?.timezone)

/**
 * @param credential - The credential
 */
function kindLabel(credential: StaleCredential): string {
	return credential.kind === 'app_password' ? t(APP_ID, 'App password') : t(APP_ID, 'Browser')
}

/**
 * Remove one credential, after the password.
 *
 * @param credential - The credential
 */
async function remove(credential: StaleCredential) {
	removing.value = credential.id
	try {
		await removeStaleCredential(credential.id)
		personal.staleCredentials = personal.staleCredentials.filter((c) => c.id !== credential.id)
		const message = t(APP_ID, '{name} was removed.', { name: credential.name })
		showSuccess(message)
		announce(message)
	} catch (error) {
		if (isCancelled(error)) {
			return
		}
		logger.error('Could not remove an unused app password or device', { error })
		showError(errorMessage(error, t(APP_ID, 'It could not be removed. Please try again.')))
	} finally {
		removing.value = null
	}
}

/**
 * Remove them all, after the confirmation and the password.
 */
async function removeAll() {
	confirmAll.value = false
	removing.value = 'all'
	try {
		const { removed } = await removeAllStaleCredentials()
		personal.staleCredentials = []
		const message = n(APP_ID, '%n unused app password or device was removed.', '%n unused app passwords and devices were removed.', removed)
		showSuccess(message)
		announce(message)
	} catch (error) {
		if (isCancelled(error)) {
			return
		}
		logger.error('Could not remove the unused app passwords and devices', { error })
		showError(errorMessage(error, t(APP_ID, 'They could not be removed. Please try again.')))
	} finally {
		removing.value = null
	}
}

const buttons = computed(() => [
	{ label: t(APP_ID, 'Cancel'), callback: () => undefined },
	{ label: t(APP_ID, 'Remove all'), variant: 'error' as const, callback: () => { removeAll() } },
])
</script>

<template>
	<SectionCard
		v-if="credentials.length > 0"
		:heading="t(APP_ID, 'App passwords and devices you have not used for 3 months')"
		:icon="mdiKeyOutline"
		level="h4"
		data-test="stale-credentials">
		<template #description>
			{{ t(APP_ID, 'If someone else had one of these, it would be easy to miss. Remove the ones you no longer need; an app you still use asks you to log in again.') }}
		</template>
		<template v-if="credentials.length > 1" #actions>
			<NcButton
				variant="secondary"
				:disabled="removing !== null"
				data-test="remove-all-stale"
				@click="confirmAll = true">
				<template #icon>
					<NcLoadingIcon v-if="removing === 'all'" :size="20" />
					<NcIconSvgWrapper v-else :path="mdiDeleteOutline" />
				</template>
				{{ t(APP_ID, 'Remove all') }}
			</NcButton>
		</template>

		<ul :class="$style.list">
			<li
				v-for="credential in credentials"
				:key="credential.id"
				:class="$style.item"
				:data-test="`stale-${credential.id}`">
				<span :class="$style.item__icon" aria-hidden="true">
					<NcIconSvgWrapper :path="credential.kind === 'app_password' ? mdiKeyOutline : mdiWeb" :size="20" />
				</span>
				<div :class="$style.item__main">
					<p :class="$style.item__name">
						{{ credential.name }}
					</p>
					<p :class="$style.item__meta">
						{{ kindLabel(credential) }} · {{ t(APP_ID, 'Last used') }}
						<TimeStamp :timestamp="credential.lastUsed" :timeZone="timeZone" />
					</p>
				</div>
				<NcButton
					:class="$style.item__remove"
					variant="tertiary"
					:aria-label="t(APP_ID, 'Remove {name}', { name: credential.name })"
					:disabled="removing !== null"
					data-test="remove-stale"
					@click="remove(credential)">
					<template #icon>
						<NcLoadingIcon v-if="removing === credential.id" :size="20" />
						<NcIconSvgWrapper v-else :path="mdiDeleteOutline" />
					</template>
					{{ t(APP_ID, 'Remove') }}
				</NcButton>
			</li>
		</ul>

		<NcDialog
			v-model:open="confirmAll"
			:name="t(APP_ID, 'Remove all unused app passwords and devices?')"
			:buttons="buttons"
			size="normal">
			<p :class="$style.dialog">
				{{ n(APP_ID, 'The %n app password or device in this list stops working at once. Nextcloud asks for your password first.', 'The %n app passwords and devices in this list stop working at once. Nextcloud asks for your password first.', credentials.length) }}
			</p>
		</NcDialog>
	</SectionCard>
</template>

<style module>
.list {
	display: flex;
	flex-direction: column;
	margin: 0;
	padding: 0;
	list-style: none;
}

.item {
	display: flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 3);
	padding-block: calc(var(--default-grid-baseline) * 3);
	border-block-start: 1px solid var(--color-border);
}

.item:first-child {
	padding-block-start: 0;
	border-block-start: none;
}

.item__icon {
	display: inline-flex;
	flex: 0 0 auto;
	align-items: center;
	justify-content: center;
	width: 36px;
	height: 36px;
	border-radius: 50%;
	background-color: var(--color-background-dark);
	color: var(--color-text-maxcontrast);
}

.item__main {
	display: flex;
	flex: 1 1 auto;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 0.5);
	min-width: 0;
}

.item__name {
	margin: 0;
	font-weight: 600;
	overflow-wrap: anywhere;
}

.item__remove {
	flex: 0 0 auto;
}

.item__meta {
	margin: 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.92em;
	line-height: 1.5;
}

.dialog {
	margin: 0 0 calc(var(--default-grid-baseline) * 2);
	line-height: 1.5;
}
</style>
