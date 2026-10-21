<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { KnownDevice } from '../types.ts'

import { mdiCellphone, mdiCheckCircleOutline, mdiDeleteOutline, mdiDevices, mdiLaptop, mdiMonitor } from '@mdi/js'
import { showError, showSuccess } from '@nextcloud/dialogs'
import { t } from '@nextcloud/l10n'
import { computed, onMounted, ref, watch } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcDateTime from '@nextcloud/vue/components/NcDateTime'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import SectionCard from '../../components/common/SectionCard.vue'
import StateBadge from '../../components/common/StateBadge.vue'
import EmptyLine from './EmptyLine.vue'
import LoadError from './LoadError.vue'
import SkeletonRows from './SkeletonRows.vue'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { errorMessage } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { APP_ID } from '../../utils/format.ts'
import { fetchKnownDevices, removeKnownDevice } from '../api.ts'
import { personal } from '../store.ts'
import { date } from '../time.ts'
import { useRemoteList } from '../useRemoteList.ts'

const { items: devices, error, load } = useRemoteList<KnownDevice>(
	fetchKnownDevices,
	() => t(APP_ID, 'Your remembered devices could not be loaded. Please try again.'),
)
const removing = ref<number | null>(null)
const { announce } = useAnnouncer()
const timeZone = computed(() => personal.overview?.timezone)
/** Without the feature and without devices, there is nothing to show */
const shown = computed(() => personal.knownDevicesEnabled || (devices.value?.length ?? 0) > 0 || error.value !== null)

/**
 * @param device - The device
 */
function iconOf(device: KnownDevice): string {
	if (device.platform === 'android' || device.platform === 'ios') {
		return mdiCellphone
	}
	return device.platform === 'other' ? mdiMonitor : mdiLaptop
}

/**
 * Forget one device.
 *
 * @param device - The device
 */
async function remove(device: KnownDevice) {
	removing.value = device.id
	try {
		await removeKnownDevice(device.id)
		devices.value = (devices.value ?? []).filter((d) => d.id !== device.id)
		const message = t(APP_ID, '{device} is no longer remembered.', { device: device.label })
		showSuccess(message)
		announce(message)
	} catch (e) {
		logger.error('Could not forget a remembered device', { error: e })
		showError(errorMessage(e, t(APP_ID, 'The device could not be removed. Please try again.')))
	} finally {
		removing.value = null
	}
}

watch(() => personal.devicesVersion, load)
onMounted(load)
</script>

<template>
	<SectionCard
		v-if="shown"
		:heading="t(APP_ID, 'Remembered devices')"
		:icon="mdiDevices"
		data-test="known-devices">
		<template #description>
			{{ t(APP_ID, 'Browsers you chose to remember after confirming a login. Logins from them are not asked again, unless your password itself is at risk.') }}
		</template>

		<LoadError v-if="error" :text="error" @retry="load" />
		<SkeletonRows v-else-if="devices === null" :rows="2" />
		<EmptyLine
			v-else-if="devices.length === 0"
			:icon="mdiDevices"
			:text="t(APP_ID, 'No remembered devices. When Nextcloud asks you to confirm a login, you can choose to remember the browser.')" />
		<ul v-else :class="$style.list">
			<li
				v-for="device in devices"
				:key="device.id"
				:class="$style.device"
				:data-test="`device-${device.id}`">
				<span :class="$style.device__icon" aria-hidden="true">
					<NcIconSvgWrapper :path="iconOf(device)" :size="20" />
				</span>
				<div :class="$style.device__main">
					<p :class="$style.device__title">
						<span :class="$style.device__label">{{ device.label }}</span>
						<StateBadge v-if="device.current" type="active" :icon="mdiCheckCircleOutline">
							{{ t(APP_ID, 'This browser') }}
						</StateBadge>
					</p>
					<p :class="$style.device__meta">
						{{ t(APP_ID, 'First used {date}', { date: date(device.createdAt, timeZone) }) }}
					</p>
					<p :class="$style.device__meta">
						{{ t(APP_ID, 'Last used') }}
						<NcDateTime :timestamp="device.lastSeenAt * 1000" relativeTime="long" :format="{ dateStyle: 'long', timeStyle: 'short', timeZone }" />
					</p>
				</div>
				<NcButton
					variant="tertiary"
					:aria-label="t(APP_ID, 'Remove {device}', { device: device.label })"
					:title="t(APP_ID, 'Remove')"
					:disabled="removing !== null"
					data-test="remove-device"
					@click="remove(device)">
					<template #icon>
						<NcLoadingIcon v-if="removing === device.id" :size="20" />
						<NcIconSvgWrapper v-else :path="mdiDeleteOutline" />
					</template>
				</NcButton>
			</li>
		</ul>
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

.device {
	display: flex;
	align-items: flex-start;
	gap: calc(var(--default-grid-baseline) * 3);
	padding-block: calc(var(--default-grid-baseline) * 3);
	border-block-start: 1px solid var(--color-border);
}

.device:first-child {
	padding-block-start: 0;
	border-block-start: none;
}

.device__icon {
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

.device__main {
	display: flex;
	flex: 1 1 auto;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 0.5);
	min-width: 0;
}

.device__title {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2);
	margin: 0;
}

.device__label {
	font-weight: 600;
}

.device__meta {
	margin: 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.92em;
	line-height: 1.5;
}
</style>
