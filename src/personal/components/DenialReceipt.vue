<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { DenialReceipt } from '../types.ts'

import { mdiCheck, mdiShieldAccountOutline } from '@mdi/js'
import { generateUrl } from '@nextcloud/router'
import { useId } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import { APP_ID } from '../../utils/format.ts'
import { t } from '../../utils/l10n.ts'

/** What Nextcloud did after "No, it was not me", as the server reported it */
defineProps<{
	receipt: DenialReceipt
}>()

const emit = defineEmits<{
	/** The user closed the receipt */
	close: []
}>()

const id = useId()
const checklistUrl = generateUrl('/apps/intrusion_detection/secure-account')
</script>

<template>
	<li
		:class="$style.receipt"
		role="group"
		:aria-labelledby="`${id}-title`"
		:data-test="`receipt-${receipt.id}`">
		<h4 :id="`${id}-title`" :class="$style.receipt__title">
			{{ t(APP_ID, 'You said it was not you') }}
		</h4>
		<p :class="$style.receipt__subject">
			{{ receipt.subject }}
		</p>
		<template v-if="receipt.lines.length > 0">
			<p :class="$style.receipt__text">
				{{ t(APP_ID, 'This is what Nextcloud did:') }}
			</p>
			<ul :class="$style.receipt__list" data-test="receipt-lines">
				<li v-for="line in receipt.lines" :key="line" :class="$style.receipt__line">
					<NcIconSvgWrapper :path="mdiCheck" :size="18" :class="$style.receipt__check" />
					<span>{{ line }}</span>
				</li>
			</ul>
		</template>
		<p v-else :class="$style.receipt__text" data-test="receipt-nothing">
			{{ t(APP_ID, 'Your answer was recorded. Nothing else could be ended or blocked automatically.') }}
		</p>
		<p :class="$style.receipt__text">
			{{ t(APP_ID, 'A few short steps make sure your account is safe again.') }}
		</p>
		<div :class="$style.receipt__buttons">
			<NcButton variant="primary" :href="checklistUrl" data-test="receipt-secure">
				<template #icon>
					<NcIconSvgWrapper :path="mdiShieldAccountOutline" :size="20" />
				</template>
				{{ t(APP_ID, 'Secure my account') }}
			</NcButton>
			<NcButton variant="tertiary" data-test="receipt-close" @click="emit('close')">
				{{ t(APP_ID, 'Close') }}
			</NcButton>
		</div>
	</li>
</template>

<style module>
.receipt {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-2);
	padding: var(--ids-space-4);
	border: 1px solid color-mix(in srgb, var(--color-success) 45%, var(--color-border));
	border-radius: var(--border-radius-large);
	background-color: var(--color-main-background);
}

.receipt__title {
	margin: 0;
	font-size: 1em;
	font-weight: 600;
	line-height: 1.4;
}

.receipt__subject {
	composes: muted from '../../styles/shared.module.css';
	margin: 0;
	font-size: 0.92em;
	overflow-wrap: anywhere;
}

.receipt__text {
	margin: 0;
	max-width: 75ch;
	line-height: 1.5;
}

.receipt__list {
	composes: plainList from '../../styles/shared.module.css';
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-1);
}

.receipt__line {
	display: flex;
	align-items: flex-start;
	gap: var(--ids-space-2);
	line-height: 1.5;
}

.receipt__check {
	flex: 0 0 auto;
	color: var(--color-success-text);
}

.receipt__buttons {
	display: flex;
	flex-wrap: wrap;
	gap: var(--ids-space-2);
	margin-block-start: var(--ids-space-1);
}

@media (max-width: 480px) {
	.receipt {
		padding: var(--ids-space-3);
	}
}
</style>
