<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { LoginApproval } from '../../types.ts'

import { mdiAccountClockOutline, mdiCheck, mdiClose } from '@mdi/js'
import { showError, showSuccess } from '@nextcloud/dialogs'
import { t } from '@nextcloud/l10n'
import { computed, ref } from 'vue'
import NcAvatar from '@nextcloud/vue/components/NcAvatar'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import EmptyNote from '../common/EmptyNote.vue'
import TimeStamp from '../common/TimeStamp.vue'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { approveRequest, errorMessage, isCancelled, rejectRequest } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { APP_ID } from '../../utils/format.ts'

const props = defineProps<{
	approvals: LoginApproval[]
}>()

const emit = defineEmits<{
	/** A request was decided; the list should be loaded again */
	decided: []
}>()

const busy = ref<number | null>(null)
/** The request the approve dialog is about */
const confirming = ref<LoginApproval | null>(null)
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
	{ label: t(APP_ID, 'Approve login'), variant: 'primary' as const, callback: () => { void decide(confirming.value!, true) } },
])

/**
 * @param approval - The waiting login
 * @param approve - Approve, or reject
 */
async function decide(approval: LoginApproval, approve: boolean) {
	busy.value = approval.id
	try {
		await (approve ? approveRequest(approval.id) : rejectRequest(approval.id))
		const done = approve
			? t(APP_ID, 'The login of {user} was approved. It continues by itself.', { user: approval.displayName }, undefined, opts)
			: t(APP_ID, 'The login of {user} was rejected and is ended.', { user: approval.displayName }, undefined, opts)
		showSuccess(done)
		announce(done)
		emit('decided')
	} catch (error) {
		if (!isCancelled(error)) {
			logger.error('Could not decide on a login', { error })
			showError(errorMessage(error, t(APP_ID, 'That did not work. Please try again.')))
			emit('decided')
		}
	} finally {
		busy.value = null
	}
}

/**
 * @param approval - The waiting login
 */
function address(approval: LoginApproval): string {
	return approval.ip ?? t(APP_ID, 'an unknown address')
}
</script>

<template>
	<div :class="$style.approvals">
		<EmptyNote
			v-if="props.approvals.length === 0"
			:name="t(APP_ID, 'No login is waiting')"
			:description="t(APP_ID, 'Logins that wait for an administrator appear here, and as a notification to every administrator who may decide.')"
			:icon="mdiAccountClockOutline" />

		<ul v-else :class="$style.list" data-test="approvals">
			<li
				v-for="approval in props.approvals"
				:key="approval.id"
				:class="$style.item"
				:data-approval="approval.id">
				<NcAvatar
					:user="approval.uid"
					:displayName="approval.displayName"
					:size="40"
					disableMenu />
				<div :class="$style.item__text">
					<span :class="$style.item__name">{{ approval.displayName }} <span :class="$style.item__uid">{{ approval.uid }}</span></span>
					<span :class="$style.item__meta">
						{{ t(APP_ID, 'From {address}', { address: address(approval) }, undefined, opts) }} ·
						{{ t(APP_ID, 'asked') }} <TimeStamp :timestamp="approval.createdAt" /> ·
						{{ t(APP_ID, 'expires') }} <TimeStamp :timestamp="approval.expiresAt" />
					</span>
				</div>
				<div :class="$style.item__actions">
					<span v-if="!approval.canDecide" :class="$style.item__own">
						{{ t(APP_ID, 'Your own login: another administrator decides') }}
					</span>
					<template v-else>
						<NcButton
							:disabled="busy !== null"
							:aria-label="t(APP_ID, 'Reject the login of {user}', { user: approval.displayName }, undefined, opts)"
							@click="decide(approval, false)">
							<template #icon>
								<NcLoadingIcon v-if="busy === approval.id" :size="20" />
								<NcIconSvgWrapper v-else :path="mdiClose" />
							</template>
							{{ t(APP_ID, 'Reject') }}
						</NcButton>
						<NcButton
							variant="primary"
							:disabled="busy !== null"
							:aria-label="t(APP_ID, 'Approve the login of {user}', { user: approval.displayName }, undefined, opts)"
							@click="confirming = approval">
							<template #icon>
								<NcIconSvgWrapper :path="mdiCheck" />
							</template>
							{{ t(APP_ID, 'Approve') }}
						</NcButton>
					</template>
				</div>
			</li>
		</ul>

		<NcDialog
			v-model:open="open"
			:name="t(APP_ID, 'Approve the login of {user}?', { user: confirming?.displayName ?? '' }, undefined, opts)"
			:buttons="buttons"
			size="normal">
			<div :class="$style.dialog">
				<p>{{ t(APP_ID, 'Someone logged in as {user} from {address} with the correct password. Approving lets this login in without any other confirmation.', { user: confirming?.uid ?? '', address: confirming ? address(confirming) : '' }, undefined, opts) }}</p>
				<p><strong>{{ t(APP_ID, 'Approve only if you know it is really them, for example because they asked you. If you did not expect it, reject it: someone else may know the password.') }}</strong></p>
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

.item__uid,
.item__meta,
.item__own {
	color: var(--color-text-maxcontrast);
	font-weight: normal;
}

.item__meta,
.item__own {
	font-size: 0.9em;
}

.item__actions {
	display: flex;
	flex-wrap: wrap;
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
