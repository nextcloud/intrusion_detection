<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { SecureAccountProgress } from '../../secureAccountTypes.ts'

import { mdiShieldAccountOutline } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { generateUrl } from '@nextcloud/router'
import { onMounted, ref } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import SectionCard from '../../components/common/SectionCard.vue'
import { logger } from '../../services/logger.ts'
import { fetchSecureAccountProgress } from '../../services/secureAccount.ts'
import { APP_ID } from '../../utils/format.ts'

const progress = ref<SecureAccountProgress | null>(null)
const checklistUrl = generateUrl('/apps/intrusion_detection/secure-account')

onMounted(async () => {
	try {
		const current = await fetchSecureAccountProgress()
		progress.value = current.active ? current : null
	} catch (e) {
		// The rest of the section still shows; the checklist page has its own errors.
		logger.error('Could not load the "Secure my account" checklist', { error: e })
	}
})
</script>

<template>
	<SectionCard
		v-if="progress"
		:heading="t(APP_ID, 'Secure your account')"
		:icon="mdiShieldAccountOutline"
		data-test="secure-account">
		<template #description>
			{{ t(APP_ID, 'Something unusual happened with your account. A few short steps make sure it is safe again.') }}
		</template>

		<div :class="$style.progress">
			<progress
				:class="$style.progress__bar"
				:value="progress.done"
				:max="progress.total"
				:aria-label="t(APP_ID, 'Steps done')" />
			<p :class="$style.progress__text" data-test="secure-account-progress">
				{{ t(APP_ID, '{done} of {total} steps done', { done: progress.done, total: progress.total }) }}
			</p>
		</div>
		<NcButton variant="primary" :href="checklistUrl" data-test="secure-account-open">
			{{ progress.done === 0 ? t(APP_ID, 'Start') : t(APP_ID, 'Continue') }}
		</NcButton>
	</SectionCard>
</template>

<style module>
.progress {
	display: flex;
	flex-direction: column;
	gap: var(--default-grid-baseline);
	margin-block-end: calc(var(--default-grid-baseline) * 3);
}

.progress__bar {
	width: 100%;
	height: calc(var(--default-grid-baseline) * 2);
	accent-color: var(--color-primary-element);
}

.progress__text {
	margin: 0;
	color: var(--color-text-maxcontrast);
}
</style>
