<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { NcSelectUsersModel } from '@nextcloud/vue/components/NcSelectUsers'
import type { IncidentRequest, IncidentSubjectType } from '../../types.ts'

import { mdiFileChartOutline } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import debounce from 'debounce'
import { computed, onBeforeUnmount, ref, useId } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcDateTimePickerNative from '@nextcloud/vue/components/NcDateTimePickerNative'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcRadioGroup from '@nextcloud/vue/components/NcRadioGroup'
import NcRadioGroupButton from '@nextcloud/vue/components/NcRadioGroupButton'
import NcSelectUsers from '@nextcloud/vue/components/NcSelectUsers'
import NcTextField from '@nextcloud/vue/components/NcTextField'
import { searchAccounts } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { APP_ID } from '../../utils/format.ts'
import { vRadioGroupName } from '../../utils/radioGroupName.ts'
import { isCidr } from '../../utils/validate.ts'

const props = defineProps<{
	busy?: boolean
	/** Fills the form, e.g. with the request of the report shown */
	initial?: IncidentRequest | null
}>()

const emit = defineEmits<{
	build: [request: IncidentRequest]
}>()

/** The longest period one report covers, as on the server */
const MAX_DAYS = 90
const DAY = 86400

type Period = '1' | '7' | '30' | '90' | 'custom'

const id = useId()
const type = ref<IncidentSubjectType>('user')
const account = ref<NcSelectUsersModel | null>(null)
const address = ref('')
const period = ref<Period>('7')
const from = ref<Date | null>(null)
const to = ref<Date | null>(null)
const options = ref<NcSelectUsersModel[]>([])
const searching = ref(false)
const touched = ref(false)

const periods: { value: Period, label: () => string }[] = [
	{ value: '1', label: () => t(APP_ID, '24 hours') },
	{ value: '7', label: () => t(APP_ID, '7 days') },
	{ value: '30', label: () => t(APP_ID, '30 days') },
	{ value: '90', label: () => t(APP_ID, '90 days') },
	{ value: 'custom', label: () => t(APP_ID, 'Custom') },
]

const addressError = computed(() => {
	const value = address.value.trim()
	if (value === '') {
		return touched.value ? t(APP_ID, 'Enter an address.') : null
	}
	return isCidr(value) && !value.includes('/') ? null : t(APP_ID, 'Enter a single IPv4 or IPv6 address, for example 203.0.113.7.')
})

const accountError = computed(() => (touched.value && account.value === null ? t(APP_ID, 'Choose an account.') : null))

const periodError = computed(() => {
	if (period.value !== 'custom') {
		return null
	}
	if (from.value === null || to.value === null) {
		return touched.value ? t(APP_ID, 'Choose the start and the end of the period.') : null
	}
	if (from.value >= to.value) {
		return t(APP_ID, 'The start of the period must be before its end.')
	}
	if (to.value.getTime() - from.value.getTime() > MAX_DAYS * DAY * 1000) {
		return t(APP_ID, 'A report covers at most {days} days. Choose a shorter period.', { days: MAX_DAYS })
	}
	return null
})

const subjectValid = computed(() => (type.value === 'user' ? account.value !== null : address.value.trim() !== '' && addressError.value === null))
const valid = computed(() => subjectValid.value && periodError.value === null && (period.value !== 'custom' || (from.value !== null && to.value !== null)))

/** Cancels the search under way, whose answer would be for older text */
let searchController: AbortController | null = null

const runSearch = debounce(async (term: string) => {
	searchController?.abort()
	const controller = new AbortController()
	searchController = controller
	let users: Awaited<ReturnType<typeof searchAccounts>> = []
	try {
		users = await searchAccounts(term, controller.signal)
	} catch (error) {
		if (!controller.signal.aborted) {
			logger.error('Could not search for accounts', { error })
		}
	}
	if (controller === searchController) {
		options.value = users.map((user) => ({ id: user.uid, user: user.uid, displayName: user.displayName, subname: user.email ?? user.uid }))
		searching.value = false
	}
}, 250)
onBeforeUnmount(() => {
	runSearch.clear()
	searchController?.abort()
})

/**
 * @param term - What was typed into the account picker
 */
function onSearch(term: string) {
	if (term.trim().length < 1) {
		return
	}
	searching.value = true
	runSearch(term.trim())
}

/**
 * The request for the chosen subject and period.
 */
function request(): IncidentRequest {
	const value = type.value === 'user' ? account.value!.id : address.value.trim()
	if (period.value === 'custom') {
		return { type: type.value, value, since: Math.floor(from.value!.getTime() / 1000), until: Math.floor(to.value!.getTime() / 1000) }
	}
	const until = Math.floor(Date.now() / 1000)
	return { type: type.value, value, since: until - Number(period.value) * DAY, until }
}

/**
 * Build the report, or show what is missing.
 */
function submit() {
	touched.value = true
	if (!valid.value) {
		return
	}
	emit('build', request())
}

/**
 * Fill the form from a request. A period that ended a moment ago and has the
 * length of a choice is shown as that choice.
 *
 * @param prefill - Subject and period
 */
function fill(prefill: IncidentRequest) {
	type.value = prefill.type
	if (prefill.type === 'user') {
		account.value = { id: prefill.value, user: prefill.value, displayName: prefill.value }
	} else {
		address.value = prefill.value
	}
	period.value = '7'
	if (prefill.since !== null && prefill.until !== null) {
		const days = String((prefill.until - prefill.since) / DAY)
		const recent = Date.now() / 1000 - prefill.until < 3600
		if (recent && periods.some((option) => option.value === days)) {
			period.value = days as Period
		} else {
			period.value = 'custom'
			from.value = new Date(prefill.since * 1000)
			to.value = new Date(prefill.until * 1000)
		}
	}
	touched.value = false
}

if (props.initial) {
	fill(props.initial)
}
</script>

<template>
	<form :class="$style.form" novalidate @submit.prevent="submit">
		<div :class="$style.form__row">
			<NcRadioGroup
				v-model="type"
				v-radio-group-name
				:class="$style.form__choice"
				:label="t(APP_ID, 'Report about')">
				<NcRadioGroupButton value="user" :label="t(APP_ID, 'Account')" />
				<NcRadioGroupButton value="address" :label="t(APP_ID, 'Address')" />
			</NcRadioGroup>
			<div :class="$style.form__subject">
				<template v-if="type === 'user'">
					<NcSelectUsers
						v-model="account"
						:inputId="`${id}-account`"
						:inputLabel="t(APP_ID, 'Account')"
						:placeholder="t(APP_ID, 'Search by name or email address')"
						:options="options"
						:loading="searching"
						@search="onSearch" />
					<p v-if="accountError" :class="$style.form__error" role="alert">
						{{ accountError }}
					</p>
				</template>
				<NcTextField
					v-else
					v-model="address"
					:label="t(APP_ID, 'Address')"
					:placeholder="t(APP_ID, 'e.g. {example}', { example: '203.0.113.7' })"
					autocomplete="off"
					spellcheck="false"
					:error="addressError !== null"
					:helperText="addressError ?? t(APP_ID, 'IPv6 addresses include their /64 network, as Nextcloud blocks them.')" />
			</div>
		</div>

		<div :class="$style.form__row">
			<NcRadioGroup
				v-model="period"
				v-radio-group-name
				:class="$style.form__choice"
				:label="t(APP_ID, 'Period, ending now')">
				<NcRadioGroupButton
					v-for="option in periods"
					:key="option.value"
					:value="option.value"
					:label="option.label()" />
			</NcRadioGroup>
			<div v-if="period === 'custom'" :class="$style.form__dates">
				<NcDateTimePickerNative
					v-model="from"
					:class="$style.form__date"
					type="datetime-local"
					:label="t(APP_ID, 'From')" />
				<NcDateTimePickerNative
					v-model="to"
					:class="$style.form__date"
					type="datetime-local"
					:label="t(APP_ID, 'To')" />
			</div>
			<p v-if="periodError" :class="$style.form__error" role="alert">
				{{ periodError }}
			</p>
		</div>

		<div :class="$style.form__actions">
			<NcButton type="submit" variant="primary" :disabled="busy">
				<template #icon>
					<NcLoadingIcon v-if="busy" :size="20" />
					<NcIconSvgWrapper v-else :path="mdiFileChartOutline" />
				</template>
				{{ busy ? t(APP_ID, 'Building the report …') : t(APP_ID, 'Build report') }}
			</NcButton>
			<p :class="$style.form__hint">
				{{ t(APP_ID, 'You may be asked for your password. The report is written to the audit log.') }}
			</p>
		</div>
	</form>
</template>

<style module>
.form {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 5);
	padding-block-end: calc(var(--default-grid-baseline) * 3);
}

.form__row {
	display: flex;
	flex-wrap: wrap;
	align-items: flex-end;
	gap: calc(var(--default-grid-baseline) * 3) calc(var(--default-grid-baseline) * 5);
}

.form__choice {
	flex: 0 0 auto;
	max-width: 100%;
}

/* Segments keep their label on one line and wrap as a whole on narrow screens. */
.form__choice div {
	flex-wrap: wrap;
	white-space: nowrap;
}

.form__subject {
	flex: 1 1 280px;
	max-width: 420px;
	min-width: 0;
}

.form__dates {
	display: flex;
	flex-wrap: wrap;
	gap: calc(var(--default-grid-baseline) * 3);
}

.form__date {
	min-width: 200px;
}

.form__error {
	flex-basis: 100%;
	margin: 0;
	color: var(--color-text-error, var(--color-error-text));
	font-size: 0.9em;
}

.form__actions {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 3);
}

.form__hint {
	margin: 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}

@media (max-width: 600px) {
	.form__subject {
		max-width: none;
	}
}
</style>
