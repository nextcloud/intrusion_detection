<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { AdminGrantRequest } from '../../types.ts'

import { mdiCheck, mdiClose } from '@mdi/js'
import { computed, ref } from 'vue'
import NcAvatar from '@nextcloud/vue/components/NcAvatar'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import TimeStamp from '../common/TimeStamp.vue'
import { useAction } from '../../composables/useAction.ts'
import { decideAdminGrant } from '../../store.ts'
import { APP_ID } from '../../utils/format.ts'
import { t } from '../../utils/l10n.ts'

const props = defineProps<{
	requests: AdminGrantRequest[]
}>()

const { busy, run } = useAction()
/** Whether the busy request is being approved, for the spinner on the right button */
const approving = ref(false)
/** The request the approve dialog is about */
const confirming = ref<AdminGrantRequest | null>(null)

const open = computed({
	get: () => confirming.value !== null,
	set: (value: boolean) => {
		if (!value) {
			confirming.value = null
		}
	},
})

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
function decide(request: AdminGrantRequest, approve: boolean) {
	approving.value = approve
	const settings = request.kind === 'settings'
	run('decide:' + request.id, () => decideAdminGrant(request.id, approve), {
		done: approve
			? (settings ? t(APP_ID, 'The change was made.') : t(APP_ID, '{user} is now an administrator.', { user: request.displayName }))
			: (settings ? t(APP_ID, 'The change was rejected. Nothing was changed.') : t(APP_ID, 'The request to make {user} an administrator was rejected. Nothing was changed.', { user: request.displayName })),
		toast: true,
		fallback: t(APP_ID, 'That did not work. Please try again.'),
	})
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
					<span v-if="request.kind === 'settings'" :class="$style.item__name">
						{{ t(APP_ID, '{requester} asks for a change: {change}', { requester: request.requesterName, change: request.change ?? '' }) }}
					</span>
					<span v-else :class="$style.item__name">
						{{ t(APP_ID, '{requester} asks to make {user} an administrator', { requester: request.requesterName, user: request.displayName }) }}
					</span>
					<span :class="$style.item__meta">
						<template v-if="request.kind !== 'settings'">
							{{ t(APP_ID, 'Group {group}', { group: request.group }) }} ·
						</template>
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
						:aria-label="request.kind === 'settings'
							? (request.canApprove
								? t(APP_ID, 'Reject the change {requester} asks for', { requester: request.requesterName })
								: t(APP_ID, 'Withdraw your change'))
							: (request.canApprove
								? t(APP_ID, 'Reject the request to make {user} an administrator', { user: request.displayName })
								: t(APP_ID, 'Withdraw the request to make {user} an administrator', { user: request.displayName }))"
						@click="decide(request, false)">
						<template #icon>
							<NcLoadingIcon v-if="busy === 'decide:' + request.id" :size="20" />
							<NcIconSvgWrapper v-else :path="mdiClose" />
						</template>
						{{ request.canApprove ? t(APP_ID, 'Reject') : t(APP_ID, 'Withdraw') }}
					</NcButton>
					<NcButton
						v-if="request.canApprove"
						variant="primary"
						:disabled="busy !== null"
						:aria-label="request.kind === 'settings'
							? t(APP_ID, 'Approve the change {requester} asks for', { requester: request.requesterName })
							: t(APP_ID, 'Approve the request to make {user} an administrator', { user: request.displayName })"
						@click="confirming = request">
						<template #icon>
							<NcLoadingIcon v-if="busy === 'decide:' + request.id && approving" :size="20" />
							<NcIconSvgWrapper v-else :path="mdiCheck" />
						</template>
						{{ t(APP_ID, 'Approve') }}
					</NcButton>
				</div>
			</li>
		</ul>

		<NcDialog
			v-model:open="open"
			:name="confirming?.kind === 'settings'
				? t(APP_ID, 'Make this change?')
				: t(APP_ID, 'Make {user} an administrator?', { user: confirming?.displayName ?? '' })"
			:buttons="buttons"
			size="normal">
			<div :class="$style.dialog">
				<p v-if="confirming?.kind === 'settings'">
					{{ t(APP_ID, '{requester} asked for this change: {change} Approving makes it at once.', { requester: confirming?.requesterName ?? '', change: confirming?.change ?? '' }) }}
				</p>
				<p v-else>
					{{ t(APP_ID, '{requester} asked to add {user} to the group {group}. Approving gives the account its administration rights at once.', { requester: confirming?.requesterName ?? '', user: confirming?.uid ?? '', group: confirming?.group ?? '' }) }}
				</p>
				<p><strong>{{ t(APP_ID, 'Approve only if you know about this change. If you did not expect it, reject it and check the account of the one who asked: it may have been taken over.') }}</strong></p>
				<p>{{ t(APP_ID, 'Approving needs your password.') }}</p>
			</div>
		</NcDialog>
	</div>
</template>

<style module>
.list {
	composes: plainList from '../../styles/shared.module.css';
	display: flex;
	flex-direction: column;
}

.item {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: var(--ids-space-3);
	padding-block: var(--ids-space-3);
	border-bottom: 1px solid var(--color-border);
}

.item:last-child {
	border-bottom: none;
}

.item__text {
	display: flex;
	flex: 1 1 240px;
	flex-direction: column;
	gap: var(--ids-space-half);
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
	gap: var(--ids-space-2);
}

.dialog {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-3);
	padding-bottom: var(--ids-space-2);
}

.dialog p {
	margin: 0;
	line-height: 1.5;
}
</style>
