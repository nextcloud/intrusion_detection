<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { ActivityItem, Login } from '../types.ts'

import { mdiAccountCancelOutline, mdiAccountCheckOutline, mdiApplicationOutline, mdiCellphone, mdiCheckCircleOutline, mdiLaptop, mdiLockAlertOutline, mdiShieldEditOutline, mdiShieldOutline } from '@mdi/js'
import { n, t } from '@nextcloud/l10n'
import { computed } from 'vue'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import ShowMore from '../../components/common/ShowMore.vue'
import StateBadge from '../../components/common/StateBadge.vue'
import EventDetails from './EventDetails.vue'
import { APP_ID } from '../../utils/format.ts'
import { changedBy, changeValues, confirmationLabel, methodLabel } from '../activity.ts'
import { clock, dateTime } from '../time.ts'

const props = defineProps<{
	item: ActivityItem
	timeZone?: string
}>()

/**
 * @param login - The login
 */
function loginIcon(login: Login): string {
	if (/android|iphone|ipad|ios/i.test(login.userAgent ?? '')) {
		return mdiCellphone
	}
	return login.method === 'app_password' || login.method === 'client_password' || login.method === 'token' ? mdiApplicationOutline : mdiLaptop
}

const row = computed(() => {
	const { login, change, failedLogins, event } = props.item
	if (login) {
		return {
			icon: loginIcon(login),
			title: t(APP_ID, 'Login with {device}', { device: login.device }, { escape: false }),
			values: null,
			meta: [login.ip, methodLabel(login), confirmationLabel(login)],
		}
	}
	if (change) {
		return {
			icon: mdiShieldEditOutline,
			title: change.label,
			values: changeValues(change),
			meta: [changedBy(change), change.address ? t(APP_ID, 'from {address}', { address: change.address }, { escape: false }) : null],
		}
	}
	if (failedLogins) {
		return {
			icon: mdiLockAlertOutline,
			title: n(APP_ID, '%n failed login with a wrong password', '%n failed logins with a wrong password', failedLogins.count),
			values: null,
			meta: [],
		}
	}
	return {
		icon: event?.verdict === 'confirmed' ? mdiAccountCheckOutline : event?.verdict === 'denied' ? mdiAccountCancelOutline : mdiShieldOutline,
		title: event?.subject ?? '',
		values: null,
		meta: [event?.address ?? null],
	}
})

/** Failed logins are counted per day; their time is the time of the last one */
const time = computed(() => {
	const at = clock(props.item.at, props.timeZone)
	return props.item.kind === 'failed_logins' ? t(APP_ID, 'the last one at {time}', { time: at }) : at
})
const meta = computed(() => row.value.meta.filter((part): part is string => !!part))

const answer = computed(() => {
	const event = props.item.event
	if (!event || event.verdict === null) {
		return null
	}
	return event.verdict === 'confirmed'
		? t(APP_ID, 'You answered "Yes, it was me".')
		: t(APP_ID, 'You answered "No, it was not me". Your administrators were told.')
})
</script>

<template>
	<li :class="$style.row" :data-test="`activity-${item.id}`">
		<span :class="$style.row__icon" aria-hidden="true">
			<NcIconSvgWrapper :path="row.icon" :size="20" />
		</span>
		<div :class="$style.row__main">
			<p :class="$style.row__title">
				<span :class="$style.row__label">{{ row.title }}</span>
				<span v-if="row.values" :class="$style.row__values">{{ row.values }}</span>
				<StateBadge v-if="item.login?.current" type="active" :icon="mdiCheckCircleOutline">
					{{ t(APP_ID, 'This session') }}
				</StateBadge>
			</p>
			<p :class="$style.row__meta">
				<time :datetime="new Date(item.at * 1000).toISOString()" :title="dateTime(item.at, timeZone)">{{ time }}</time>
				<span v-for="(part, index) in meta" :key="index" :class="$style.row__part">{{ part }}</span>
			</p>
			<p v-if="answer" :class="$style.row__answer" data-test="answer">
				{{ answer }}
			</p>
			<ShowMore v-if="item.event" :label="t(APP_ID, 'Details')" data-test="toggle">
				<EventDetails :event="item.event" />
			</ShowMore>
		</div>
	</li>
</template>

<style module>
.row {
	display: flex;
	align-items: flex-start;
	gap: calc(var(--default-grid-baseline) * 3);
	padding-block: calc(var(--default-grid-baseline) * 2.5);
}

.row__icon {
	display: inline-flex;
	flex: 0 0 auto;
	align-items: center;
	justify-content: center;
	width: 32px;
	height: 32px;
	color: var(--color-text-maxcontrast);
}

.row__main {
	display: flex;
	flex: 1 1 auto;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 0.5);
	min-width: 0;
}

.row__title {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: var(--default-grid-baseline) calc(var(--default-grid-baseline) * 2);
	margin: 0;
	line-height: 1.5;
}

.row__label {
	font-weight: 600;
	overflow-wrap: anywhere;
}

.row__values {
	overflow-wrap: anywhere;
}

/* Each part wraps on its own, at its spaces; only a part too long for a line, such as an address, breaks inside */
.row__meta {
	display: flex;
	flex-wrap: wrap;
	align-items: baseline;
	column-gap: calc(var(--default-grid-baseline) * 1.5);
}

.row__meta,
.row__answer {
	margin: 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.92em;
	line-height: 1.5;
	overflow-wrap: break-word;
}

.row__meta time {
	font-variant-numeric: tabular-nums;
	white-space: nowrap;
}

.row__part {
	min-width: 0;
}

.row__part::before {
	content: '·';
	margin-inline-end: calc(var(--default-grid-baseline) * 1.5);
}
</style>
