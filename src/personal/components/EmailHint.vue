<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { mdiEmailOutline, mdiTwoFactorAuthentication } from '@mdi/js'
import { computed, useId } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import { APP_ID } from '../../utils/format.ts'
import { t } from '../../utils/l10n.ts'
import { personal } from '../store.ts'

const id = useId()
const hint = computed(() => personal.overview?.emailHint ?? null)
</script>

<template>
	<section
		v-if="hint"
		:class="$style.hint"
		:aria-labelledby="id"
		data-test="email-hint">
		<span :class="$style.hint__icon" aria-hidden="true">
			<NcIconSvgWrapper :path="mdiEmailOutline" :size="22" />
		</span>
		<div :class="$style.hint__body">
			<h3 :id="id" :class="$style.hint__heading">
				{{ t(APP_ID, 'Add a way to confirm it\'s you') }}
			</h3>
			<p :class="$style.hint__text">
				{{ t(APP_ID, 'If Nextcloud notices something suspicious, it can only confirm it\'s you with an email address or a second factor. Without either, some logins may be refused.') }}
			</p>
			<div :class="$style.hint__actions">
				<NcButton variant="primary" :href="hint.emailUrl" data-test="add-email">
					<template #icon>
						<NcIconSvgWrapper :path="mdiEmailOutline" />
					</template>
					{{ t(APP_ID, 'Add email address') }}
				</NcButton>
				<NcButton
					v-if="hint.secondFactorUrl"
					variant="secondary"
					:href="hint.secondFactorUrl"
					data-test="set-up-second-factor">
					<template #icon>
						<NcIconSvgWrapper :path="mdiTwoFactorAuthentication" />
					</template>
					{{ t(APP_ID, 'Set up two-factor authentication') }}
				</NcButton>
			</div>
		</div>
	</section>
</template>

<style module>
.hint {
	display: flex;
	align-items: flex-start;
	gap: var(--ids-space-4);
	padding: var(--ids-space-5);
	border: 1px solid color-mix(in srgb, var(--color-warning) 35%, var(--color-border));
	border-radius: var(--border-radius-large);
	background-color: color-mix(in srgb, var(--color-warning) 7%, var(--color-main-background));
}

.hint__icon {
	display: inline-flex;
	flex: 0 0 auto;
	align-items: center;
	justify-content: center;
	width: 40px;
	height: 40px;
	border-radius: 50%;
	background-color: color-mix(in srgb, var(--color-warning) 20%, var(--color-main-background));
	color: var(--color-warning-text);
}

.hint__body {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-2);
	min-width: 0;
}

.hint__heading {
	margin: 0;
	font-size: 1.1em;
	font-weight: 600;
	line-height: 1.4;
}

.hint__text {
	margin: 0;
	max-width: 70ch;
	line-height: 1.5;
}

.hint__actions {
	display: flex;
	flex-wrap: wrap;
	gap: var(--ids-space-2);
	margin-block-start: var(--ids-space-1);
}

@media (max-width: 480px) {
	.hint {
		flex-direction: column;
		padding: var(--ids-space-4);
	}
}
</style>
