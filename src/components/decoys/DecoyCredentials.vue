<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { CheckRef, Decoy, NewDecoy } from '../../types.ts'

import { mdiAlertCircleOutline, mdiDeleteOutline, mdiKeyChainVariant, mdiKeyVariant, mdiPlus } from '@mdi/js'
import { showError } from '@nextcloud/dialogs'
import { n, t } from '@nextcloud/l10n'
import { computed, ref } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcDateTime from '@nextcloud/vue/components/NcDateTime'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import CheckStateNote from '../common/CheckStateNote.vue'
import EmptyNote from '../common/EmptyNote.vue'
import SectionCard from '../common/SectionCard.vue'
import StateBadge from '../common/StateBadge.vue'
import CreateDecoyDialog from './CreateDecoyDialog.vue'
import DecoySecretDialog from './DecoySecretDialog.vue'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { deleteDecoy, errorMessage, isCancelled } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { globalValues } from '../../store.ts'
import { APP_ID, formatDuration } from '../../utils/format.ts'

const props = defineProps<{
	decoys: Decoy[]
	check: CheckRef
	/** Login names of decoys that are accounts by now */
	collisions: string[]
}>()

const emit = defineEmits<{
	changed: [decoys: Decoy[]]
}>()

const creating = ref(false)
/** The decoy just created, with its secret, until the secret dialog closes */
const created = ref<NewDecoy | null>(null)
const deleting = ref<Decoy | null>(null)
const busy = ref(false)
const { announce } = useAnnouncer()

/** A used decoy secret blocks like a repeat offender */
const repeatBlock = computed(() => formatDuration(Number(globalValues.value.ban_duration_3 ?? 604800)))

/**
 * @param value - The new decoy and its secret
 */
function onCreated(value: NewDecoy) {
	emit('changed', [value.decoy, ...props.decoys])
	created.value = value
	announce(t(APP_ID, 'The decoy was created. Copy its secret now; it is shown only once.'))
}

/**
 * Delete the decoy, after the confirmation.
 */
async function remove() {
	const decoy = deleting.value
	if (decoy === null) {
		return
	}
	busy.value = true
	try {
		await deleteDecoy(decoy.id)
		emit('changed', props.decoys.filter((d) => d.id !== decoy.id))
		deleting.value = null
		announce(t(APP_ID, 'The decoy "{label}" was deleted.', { label: decoy.label }, undefined, { escape: false, sanitize: false }))
	} catch (error) {
		if (!isCancelled(error)) {
			logger.error('Could not delete the decoy', { error })
			showError(errorMessage(error, t(APP_ID, 'The decoy could not be deleted. Please try again.')))
		}
	} finally {
		busy.value = false
	}
}
</script>

<template>
	<SectionCard :heading="t(APP_ID, 'Decoy credentials')" :icon="mdiKeyChainVariant">
		<template #description>
			{{ t(APP_ID, 'Fake app passwords or tokens that you plant where an intruder would look. Whoever uses one is blocked for {duration} at once, and you get an alert with the place you planted it.', { duration: repeatBlock }) }}
		</template>
		<template #actions>
			<CheckStateNote :check="check" />
			<NcButton variant="primary" @click="creating = true">
				<template #icon>
					<NcIconSvgWrapper :path="mdiPlus" />
				</template>
				{{ t(APP_ID, 'Create decoy') }}
			</NcButton>
		</template>

		<EmptyNote
			v-if="decoys.length === 0"
			:name="t(APP_ID, 'No decoys yet')"
			:description="t(APP_ID, 'Create one and plant it somewhere only an intruder would find it. It costs nothing until someone uses it.')"
			:icon="mdiKeyVariant" />

		<ul v-else :class="$style.list" data-test="decoy-list">
			<li v-for="decoy in decoys" :key="decoy.id" :class="[$style.decoy, { [$style.decoy_used]: decoy.triggerCount > 0 }]">
				<span :class="$style.decoy__icon" aria-hidden="true">
					<NcIconSvgWrapper inline :path="mdiKeyVariant" :size="20" />
				</span>
				<div :class="$style.decoy__text">
					<span :class="$style.decoy__label">{{ decoy.label }}</span>
					<span :class="$style.decoy__meta">
						<span>{{ decoy.format === 'token' ? t(APP_ID, 'Looks like a token') : t(APP_ID, 'Looks like an app password') }}</span>
						<template v-if="decoy.loginName">
							<span aria-hidden="true">·</span>
							<span>{{ t(APP_ID, 'login name') }} <code>{{ decoy.loginName }}</code></span>
						</template>
						<span aria-hidden="true">·</span>
						<span :class="$style.decoy__created">
							<span>{{ t(APP_ID, 'created') }}</span>
							<NcDateTime :timestamp="decoy.createdAt * 1000" relativeTime="short" />
							<span v-if="decoy.createdBy">{{ t(APP_ID, 'by {admin}', { admin: decoy.createdBy }, undefined, { escape: false, sanitize: false }) }}</span>
						</span>
					</span>
					<span v-if="decoy.loginName && collisions.includes(decoy.loginName)" :class="$style.decoy__problem">
						<NcIconSvgWrapper inline :path="mdiAlertCircleOutline" :size="16" />
						{{ t(APP_ID, 'An account with this login name exists now, so the login name no longer works as a trap.') }}
					</span>
				</div>
				<div :class="$style.decoy__state">
					<StateBadge v-if="decoy.triggerCount > 0" type="error" :icon="mdiAlertCircleOutline">
						{{ n(APP_ID, 'Used %n time', 'Used %n times', decoy.triggerCount) }}
					</StateBadge>
					<StateBadge v-else>
						{{ t(APP_ID, 'Never used') }}
					</StateBadge>
					<span v-if="decoy.lastTriggeredAt" :class="[$style.decoy__last, $style.decoy__created]">
						<span>{{ t(APP_ID, 'last') }}</span>
						<NcDateTime :timestamp="decoy.lastTriggeredAt * 1000" />
					</span>
				</div>
				<NcButton
					variant="tertiary"
					:aria-label="t(APP_ID, 'Delete the decoy {label}', { label: decoy.label }, undefined, { escape: false, sanitize: false })"
					:title="t(APP_ID, 'Delete')"
					@click="deleting = decoy">
					<template #icon>
						<NcIconSvgWrapper :path="mdiDeleteOutline" />
					</template>
				</NcButton>
			</li>
		</ul>

		<CreateDecoyDialog v-model:open="creating" @created="onCreated" />
		<DecoySecretDialog v-model:created="created" />
		<NcDialog
			:open="deleting !== null"
			:name="t(APP_ID, 'Delete this decoy?')"
			:message="t(APP_ID, 'Anyone who uses it afterwards is treated like any other failed login. Remove it from where you planted it too.')"
			:buttons="[
				{ label: t(APP_ID, 'Cancel'), callback: () => { deleting = null } },
				{ label: t(APP_ID, 'Delete decoy'), variant: 'error', disabled: busy, callback: () => { remove(); return false } },
			]"
			@update:open="!$event && (deleting = null)" />
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

.decoy {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 3);
	padding-block: calc(var(--default-grid-baseline) * 3);
	border-top: 1px solid var(--color-border);
}

.decoy:first-child {
	border-top: none;
	padding-top: 0;
}

.decoy__icon {
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

.decoy_used .decoy__icon {
	background-color: color-mix(in srgb, var(--color-error) 14%, var(--color-main-background));
	color: var(--color-error-text);
}

.decoy__text {
	display: flex;
	flex: 1 1 280px;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) / 2);
	min-width: 0;
}

.decoy__label {
	font-weight: 700;
	overflow-wrap: anywhere;
}

.decoy__meta {
	display: flex;
	flex-wrap: wrap;
	gap: calc(var(--default-grid-baseline) * 1.5);
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}

.decoy__created {
	display: inline-flex;
	flex-wrap: wrap;
	gap: 0.3em;
}

.decoy__meta code {
	color: var(--color-main-text);
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
}

.decoy__problem {
	display: inline-flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 1);
	color: var(--color-error-text);
	font-size: 0.9em;
	font-weight: 600;
}

.decoy__state {
	display: flex;
	flex-direction: column;
	align-items: flex-end;
	gap: calc(var(--default-grid-baseline) / 2);
}

.decoy__last {
	color: var(--color-text-maxcontrast);
	font-size: 0.85em;
}

@media (max-width: 600px) {
	.decoy__state {
		align-items: flex-start;
		margin-inline-start: calc(36px + var(--default-grid-baseline) * 3);
	}
}
</style>
