<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { LearningRecap } from '../../types.ts'

import { mdiShieldCheckOutline } from '@mdi/js'
import { computed } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import { useAction } from '../../composables/useAction.ts'
import { closeRecap } from '../../stores/overview.ts'
import { APP_ID, formatNumber } from '../../utils/format.ts'
import { n, t } from '../../utils/l10n.ts'

const props = defineProps<{
	recap: LearningRecap
}>()

const { busy, run } = useAction()

/** The first learning period of seven days is "your first week" */
const firstWeek = computed(() => props.recap.first && props.recap.days === 7)

const quiet = computed(() => props.recap.attempts === 0 && props.recap.wouldHaveBlocked === 0)

const lead = computed(() => {
	const { attempts, addresses, days, first } = props.recap
	if (quiet.value) {
		return firstWeek.value ? t(APP_ID, 'A quiet first week: nothing to block.') : t(APP_ID, 'A quiet learning period: nothing to block.')
	}
	const figures = {
		attempts: n(APP_ID, '{count} attempt', '{count} attempts', attempts, { count: formatNumber(attempts) }),
		addresses: n(APP_ID, '{count} address', '{count} addresses', addresses, { count: formatNumber(addresses) }),
	}
	if (firstWeek.value) {
		return t(APP_ID, 'In your first week: {attempts} from {addresses}.', figures)
	}
	return first
		? n(APP_ID, 'In your first %n day: {attempts} from {addresses}.', 'In your first %n days: {attempts} from {addresses}.', days, figures)
		: n(APP_ID, 'In %n day of learning: {attempts} from {addresses}.', 'In %n days of learning: {attempts} from {addresses}.', days, figures)
})

/** Accounts that logged in from an address that would have been blocked and are not named */
const unnamed = computed(() => props.recap.ownPeople - props.recap.accounts.length)

const close = () => run('close', closeRecap, { fallback: t(APP_ID, 'That did not work. Please reload the page and try again.') })
</script>

<template>
	<section
		id="overview-recap"
		:class="$style.recap"
		aria-labelledby="ids-recap-heading"
		data-test="learning-recap">
		<div :class="$style.recap__head">
			<span :class="$style.recap__icon" aria-hidden="true">
				<NcIconSvgWrapper :path="mdiShieldCheckOutline" :size="28" />
			</span>
			<div :class="$style.recap__title">
				<h3 id="ids-recap-heading" :class="$style.recap__heading">
					{{ t(APP_ID, 'Learning mode is over') }}
				</h3>
				<p :class="$style.recap__muted">
					{{ t(APP_ID, 'Checks set to Protect act now. This is what they saw while learning.') }}
				</p>
			</div>
		</div>

		<p :class="$style.recap__lead" data-test="recap-lead">
			{{ lead }}
		</p>

		<template v-if="!quiet">
			<dl :class="$style.figures" data-test="recap-figures">
				<div v-if="recap.topAttack" :class="[$style.figure, $style.figure_wide]">
					<dt :class="$style.figure__label">
						{{ t(APP_ID, 'Top attack') }}
					</dt>
					<dd :class="$style.figure__name">
						{{ recap.topAttack.name }}
					</dd>
					<dd :class="$style.figure__detail">
						{{ recap.topAttack.summary }}
						{{ n(APP_ID, 'Seen {count} time.', 'Seen {count} times.', recap.topAttack.attempts, { count: formatNumber(recap.topAttack.attempts) }) }}
					</dd>
				</div>
				<div :class="$style.figure">
					<dt :class="$style.figure__label">
						{{ n(APP_ID, 'address would have been blocked', 'addresses would have been blocked', recap.wouldHaveBlocked) }}
					</dt>
					<dd :class="$style.figure__value">
						{{ formatNumber(recap.wouldHaveBlocked) }}
					</dd>
				</div>
			</dl>

			<NcNoteCard
				v-if="recap.ownPeople === 0"
				type="success"
				:class="$style.note"
				:heading="t(APP_ID, 'None of your own people would have been blocked')"
				data-test="recap-own-people">
				<p>{{ t(APP_ID, 'No account logged in from an address the checks would have blocked.') }}</p>
			</NcNoteCard>
			<NcNoteCard
				v-else
				type="warning"
				:class="$style.note"
				:heading="n(APP_ID, '{count} of your own people would have been blocked', '{count} of your own people would have been blocked', recap.ownPeople, { count: formatNumber(recap.ownPeople) })"
				data-test="recap-own-people">
				<p>
					{{ n(APP_ID, 'This account logged in from an address the checks would have blocked. Look it up below to see why.', 'These accounts logged in from an address the checks would have blocked. Look them up below to see why.', recap.ownPeople) }}
				</p>
				<ul :class="$style.accounts" data-test="recap-accounts">
					<li v-for="account in recap.accounts" :key="account.uid" :class="$style.account">
						<strong>{{ account.displayName }}</strong>
						<span v-if="account.displayName !== account.uid" :class="$style.recap__muted">({{ account.uid }})</span>
					</li>
					<li v-if="unnamed > 0" :class="$style.recap__muted">
						{{ n(APP_ID, 'and %n more', 'and %n more', unnamed) }}
					</li>
				</ul>
			</NcNoteCard>
		</template>
		<p v-else :class="$style.recap__muted">
			{{ t(APP_ID, 'No check found anything it would have blocked. Nextcloud is watching.') }}
		</p>

		<p v-if="!recap.complete" :class="[$style.recap__muted, $style.recap__small]" data-test="recap-incomplete">
			{{ t(APP_ID, 'Some detections of the learning period were deleted after the retention period or were too many to read, so the real numbers can be higher.') }}
		</p>

		<div :class="$style.recap__actions">
			<NcButton variant="primary" :disabled="busy !== null" @click="close">
				<template v-if="busy === 'close'" #icon>
					<NcLoadingIcon />
				</template>
				{{ t(APP_ID, 'Got it') }}
			</NcButton>
		</div>
	</section>
</template>

<style module>
.recap {
	composes: card from '../../styles/shared.module.css';
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-4);
	padding: var(--ids-space-5);
	border-color: var(--color-border-success, var(--color-success));
}

.recap__head {
	display: flex;
	align-items: center;
	gap: var(--ids-space-3);
}

.recap__icon {
	display: inline-flex;
	flex: 0 0 auto;
	align-items: center;
	justify-content: center;
	width: var(--ids-space-12);
	height: var(--ids-space-12);
	border-radius: 50%;
	background-color: var(--color-success);
	color: var(--color-success-text, #fff);
}

.recap__title {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-half);
	min-width: 0;
}

.recap__heading {
	margin: 0;
	font-size: 1.15em;
	font-weight: 700;
}

.recap__muted {
	composes: muted from '../../styles/shared.module.css';
	margin: 0;
}

.recap__small {
	font-size: 0.92em;
}

.recap__lead {
	margin: 0;
	font-size: 1.35em;
	font-weight: 700;
	line-height: 1.3;
	font-variant-numeric: tabular-nums;
}

.recap__actions {
	display: flex;
	flex-wrap: wrap;
	gap: var(--ids-space-2);
}

.figures {
	display: grid;
	grid-template-columns: minmax(0, 2fr) minmax(0, 1fr);
	gap: var(--ids-space-3);
	margin: 0;
}

.figure {
	display: flex;
	flex-direction: column;
	min-width: 0;
	padding: var(--ids-space-3) var(--ids-space-4);
	border-radius: var(--border-radius-large);
	background-color: var(--color-background-hover);
}

.figure dd,
.figure dt {
	margin: 0;
	padding: 0;
	text-align: start;
}

.figure__label {
	composes: muted from '../../styles/shared.module.css';
	font-size: 0.92em;
	overflow-wrap: anywhere;
}

.figure_wide .figure__label {
	order: -2;
}

.figure__value {
	order: -1;
	font-size: 1.8em;
	font-weight: 700;
	line-height: 1.15;
	font-variant-numeric: tabular-nums;
}

.figure__name {
	order: -1;
	font-size: 1.2em;
	font-weight: 700;
}

.figure__detail {
	composes: muted from '../../styles/shared.module.css';
	margin: var(--ids-space-half) 0 0;
	font-size: 0.9em;
}

.note {
	margin-block: 0 !important;
}

.accounts {
	composes: plainList from '../../styles/shared.module.css';
	display: flex;
	flex-wrap: wrap;
	gap: var(--ids-space-1) var(--ids-space-4);
	margin-top: var(--ids-space-2);
}

.account {
	display: inline-flex;
	gap: var(--ids-space-1);
}

@media (max-width: 600px) {
	.recap {
		padding: var(--ids-space-4);
	}

	.figures {
		grid-template-columns: minmax(0, 1fr);
	}

	.recap__lead {
		font-size: 1.15em;
	}
}
</style>
