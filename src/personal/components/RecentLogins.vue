<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Login } from '../types.ts'

import { mdiApplicationOutline, mdiCellphone, mdiCheckCircleOutline, mdiLaptop, mdiLogin } from '@mdi/js'
import { n, t } from '@nextcloud/l10n'
import { computed, onMounted, ref } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import SectionCard from '../../components/common/SectionCard.vue'
import StateBadge from '../../components/common/StateBadge.vue'
import TimeStamp from '../../components/common/TimeStamp.vue'
import EmptyLine from './EmptyLine.vue'
import LoadError from './LoadError.vue'
import SkeletonRows from './SkeletonRows.vue'
import { APP_ID } from '../../utils/format.ts'
import { fetchLogins } from '../api.ts'
import { personal } from '../store.ts'
import { shortDateTime } from '../time.ts'
import { useRemoteList } from '../useRemoteList.ts'

/** Shown before "Show all" */
const FIRST = 6

const { items: logins, error, load } = useRemoteList<Login>(
	() => fetchLogins(30),
	() => t(APP_ID, 'Your recent logins could not be loaded. Please try again.'),
)
const showAll = ref(false)
const visible = computed(() => showAll.value ? (logins.value ?? []) : (logins.value ?? []).slice(0, FIRST))
const timeZone = computed(() => personal.overview?.timezone)

/**
 * How the account logged in, in plain words.
 *
 * @param login - The login
 */
function methodLabel(login: Login): string {
	switch (login.method) {
		case 'password':
			return t(APP_ID, 'Password')
		case 'client_password':
			return t(APP_ID, 'Password in an app')
		case 'app_password':
			return t(APP_ID, 'App password')
		case 'token':
			return t(APP_ID, 'Access token')
		case 'cookie':
			return t(APP_ID, 'Stayed logged in')
		case 'sso':
			return t(APP_ID, 'Single sign-on')
		default:
			return login.method
	}
}

/**
 * How the login was confirmed, or why it needed nothing.
 *
 * @param login - The login
 */
function confirmationLabel(login: Login): string {
	switch (login.stepUp) {
		case 'pending':
			return t(APP_ID, 'Waiting for confirmation')
		case 'refused':
			return t(APP_ID, 'Refused')
		case 'failed':
			return t(APP_ID, 'Confirmation failed')
		case 'allowed':
			return t(APP_ID, 'Allowed without confirmation')
	}
	switch (login.confirmedBy) {
		case 'second_factor':
			return t(APP_ID, 'Confirmed with your second factor')
		case 'email_code':
			return t(APP_ID, 'Confirmed with an email code')
		case 'known_device':
			return t(APP_ID, 'Confirmed by a remembered device')
		case 'admin_approval':
			return t(APP_ID, 'Approved by an administrator')
		default:
			return t(APP_ID, 'No extra confirmation needed')
	}
}

/**
 * @param login - The login
 */
function iconOf(login: Login): string {
	if (/android|iphone|ipad|ios/i.test(login.userAgent ?? '')) {
		return mdiCellphone
	}
	return login.method === 'app_password' || login.method === 'client_password' || login.method === 'token' ? mdiApplicationOutline : mdiLaptop
}

onMounted(load)
</script>

<template>
	<SectionCard :heading="t(APP_ID, 'Recent logins')" :icon="mdiLogin" data-test="logins">
		<template #description>
			{{ t(APP_ID, 'Every login to your account in the last 30 days. Apps that log in all the time are listed once an hour.') }}
		</template>

		<LoadError v-if="error" :text="error" @retry="load" />
		<SkeletonRows v-else-if="logins === null" />
		<EmptyLine
			v-else-if="logins.length === 0"
			:icon="mdiLogin"
			:text="t(APP_ID, 'No logins in the last 30 days.')" />
		<template v-else>
			<ul :class="$style.list">
				<li
					v-for="login in visible"
					:key="login.id"
					:class="$style.login"
					:data-test="`login-${login.id}`">
					<span :class="$style.login__icon" aria-hidden="true">
						<NcIconSvgWrapper :path="iconOf(login)" :size="20" />
					</span>
					<div :class="$style.login__main">
						<p :class="$style.login__title">
							<span :class="$style.login__device">{{ login.device }}</span>
							<StateBadge v-if="login.current" type="active" :icon="mdiCheckCircleOutline">
								{{ t(APP_ID, 'This session') }}
							</StateBadge>
							<StateBadge v-else-if="login.knownDevice" type="neutral">
								{{ t(APP_ID, 'Remembered device') }}
							</StateBadge>
						</p>
						<p :class="$style.login__meta">
							<TimeStamp :timestamp="login.createdAt" short :timeZone="timeZone" />
							<span :class="$style.login__sep">{{ shortDateTime(login.createdAt, timeZone) }}</span>
							<span v-if="login.ip" :class="[$style.login__sep, $style.login__address]">{{ login.ip }}</span>
						</p>
						<p :class="$style.login__meta">
							<span>{{ methodLabel(login) }}</span>
							<span :class="$style.login__sep">{{ confirmationLabel(login) }}</span>
						</p>
					</div>
				</li>
			</ul>
			<NcButton
				v-if="logins.length > FIRST"
				variant="tertiary"
				:class="$style.more"
				:aria-expanded="showAll ? 'true' : 'false'"
				@click="showAll = !showAll">
				{{ showAll ? t(APP_ID, 'Show fewer logins') : n(APP_ID, 'Show all %n logins', 'Show all %n logins', logins.length) }}
			</NcButton>
		</template>
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

.login {
	display: flex;
	align-items: flex-start;
	gap: calc(var(--default-grid-baseline) * 3);
	padding-block: calc(var(--default-grid-baseline) * 3);
	border-block-start: 1px solid var(--color-border);
}

.login:first-child {
	padding-block-start: 0;
	border-block-start: none;
}

.login__icon {
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

.login__main {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 0.5);
	min-width: 0;
}

.login__title {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2);
	margin: 0;
}

.login__device {
	font-weight: 600;
}

.login__meta {
	display: flex;
	flex-wrap: wrap;
	margin: 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.92em;
	line-height: 1.5;
}

.login__sep::before {
	content: '·';
	margin-inline: calc(var(--default-grid-baseline) * 2);
}

.login__address {
	font-variant-numeric: tabular-nums;
	overflow-wrap: anywhere;
}

.more {
	align-self: flex-start;
}

@media (max-width: 480px) {
	.login__meta {
		flex-direction: column;
	}

	.login__sep::before {
		content: none;
	}
}
</style>
