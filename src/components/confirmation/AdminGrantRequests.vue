<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { AdminGrantRequest } from '../../types.ts'

import { mdiCheck, mdiClose } from '@mdi/js'
import { showError, showSuccess } from '@nextcloud/dialogs'
import { t } from '@nextcloud/l10n'
import { computed, ref } from 'vue'
import NcAvatar from '@nextcloud/vue/components/NcAvatar'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import TimeStamp from '../common/TimeStamp.vue'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { approveRequest, errorMessage, isCancelled, rejectRequest } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { APP_ID } from '../../utils/format.ts'

const props = defineProps<{
	requests: AdminGrantRequest[]
}>()

const emit = defineEmits<{
	/** A request was decided; the list should be loaded again */
	decided: []
}>()

const busy = ref<number | null>(null)
/** Whether the busy request is being approved, for the spinner on the right button */
const approving = ref(false)
/** The request the approve dialog is about */
const confirming = ref<AdminGrantRequest | null>(null)
const { announce } = useAnnouncer()

const open = computed({
	get: () => confirming.value !== null,
	set: (value: boolean) => {
		if (!value) {
			confirming.value = null
		}
	},
})

const opts = { escape: false, sanitize: false }

const buttons = computed(() => [
	{ label: t(APP_ID, 'Cancel'), callback: () => undefined },
	{ label: t(APP_ID, 'Approve'), variant: 'primary' as const, callback: () => { void decide(confirming.value!, true) } },
])

/**
 * Approving asks for the password first; rejecting does not.
 *
 * @param request - The request
 * @param approve - Approve, or reject
 */
async function decide(request: AdminGrantRequest, approve: boolean) {
	busy.value = request.id
	approving.value = approve
	try {
		await (approve ? approveRequest(request.id) : rejectRequest(request.id))
		const done = approve
			? t(APP_ID, '{user} is now an administrator.', { user: request.displayName }, undefined, opts)
			: t(APP_ID, 'The request to make {user} an administrator was rejected. Nothing was changed.', { user: request.displayName }, undefined, opts)
		showSuccess(done)
		announce(done)
		emit('decided')
	} catch (error) {
		if (!isCancelled(error)) {
			logger.error('Could not decide on a new administrator', { error })
			showError(errorMessage(error, t(APP_ID, 'That did not work. Please try again.')))
			emit('decided')
		}
	} finally {
		busy.value = null
	}
}
</script>

<template>
	<div data-test="admin-grants">
		<ul :class="$style.list">
			<li
				v-for="request in props.requests"
				:id="`approval-${request.id}`"
				:key="request.id"
				:class="$style.item">
				<NcAvatar
					:user="request.uid"
					:displayName="request.displayName"
					:size="40"
					disableMenu />
				<div :class="$style.item__text">
					<span :class="$style.item__name">
						{{ t(APP_ID, '{requester} asks to make {user} an administrator', { requester: request.requesterName, user: request.displayName }, undefined, opts) }}
					</span>
					<span :class="$style.item__meta">
						{{ t(APP_ID, 'Group {group}', { group: request.group }, undefined, opts) }} ·
						{{ t(APP_ID, 'asked') }} <TimeStamp :timestamp="request.createdAt" /> ·
						{{ t(APP_ID, 'expires') }} <TimeStamp :timestamp="request.expiresAt" />
					</span>
				</div>
				<div :class="$style.item__actions">
					<span v-if="!request.canApprove" :class="$style.item__own">
						{{ t(APP_ID, 'Your request: another administrator approves') }}
					</span>
					<NcButton
						:disabled="busy !== null"
						:aria-label="request.canApprove
							? t(APP_ID, 'Reject the request to make {user} an administrator', { user: request.displayName }, undefined, opts)
							: t(APP_ID, 'Withdraw the request to make {user} an administrator', { user: request.displayName }, undefined, opts)"
						@click="decide(request, false)">
						<template #icon>
							<NcLoadingIcon v-if="busy === request.id" :size="20" />
							<NcIconSvgWrapper v-else :path="mdiClose" />
						</template>
						{{ request.canApprove ? t(APP_ID, 'Reject') : t(APP_ID, 'Withdraw') }}
					</NcButton>
					<NcButton
						v-if="request.canApprove"
						variant="primary"
						:disabled="busy !== null"
						:aria-label="t(APP_ID, 'Approve the request to make {user} an administrator', { user: request.displayName }, undefined, opts)"
						@click="confirming = request">
						<template #icon>
							<NcLoadingIcon v-if="busy === request.id && approving" :size="20" />
							<NcIconSvgWrapper v-else :path="mdiCheck" />
						</template>
						{{ t(APP_ID, 'Approve') }}
					</NcButton>
				</div>
			</li>
		</ul>

		<NcDialog
			v-model:open="open"
			:name="t(APP_ID, 'Make {user} an administrator?', { user: confirming?.displayName ?? '' }, undefined, opts)"
			:buttons="buttons"
			size="normal">
			<div :class="$style.dialog">
				<p>{{ t(APP_ID, '{requester} asked to add {user} to the group {group}. Approving gives the account its administration rights at once.', { requester: confirming?.requesterName ?? '', user: confirming?.uid ?? '', group: confirming?.group ?? '' }, undefined, opts) }}</p>
				<p><strong>{{ t(APP_ID, 'Approve only if you know about this change. If you did not expect it, reject it and check the account of the one who asked: it may have been taken over.') }}</strong></p>
				<p>{{ t(APP_ID, 'Approving needs your password.') }}</p>
			</div>
		</NcDialog>
	</div>
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
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 3);
	padding-block: calc(var(--default-grid-baseline) * 3);
	border-bottom: 1px solid var(--color-border);
}

.item:last-child {
	border-bottom: none;
}

.item__text {
	display: flex;
	flex: 1 1 240px;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 0.5);
	min-width: 0;
}

.item__name {
	font-weight: 700;
	overflow-wrap: anywhere;
}

.item__meta,
.item__own {
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}

.item__actions {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2);
}

.dialog {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
	padding-bottom: calc(var(--default-grid-baseline) * 2);
}

.dialog p {
	margin: 0;
	line-height: 1.5;
}
</style>
