<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { mdiShieldAccountOutline } from '@mdi/js'
import { generateUrl } from '@nextcloud/router'
import { computed } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import SectionCard from '../../components/common/SectionCard.vue'
import { APP_ID } from '../../utils/format.ts'
import { t } from '../../utils/l10n.ts'
import { useSecureAccountProgress } from '../store.ts'

// A failure shows nothing here: the rest of the section still shows, and the checklist page has its own errors.
const { data } = useSecureAccountProgress()
const progress = computed(() => data.value?.active ? data.value : null)
const checklistUrl = generateUrl('/apps/intrusion_detection/secure-account')
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
	gap: var(--ids-space-1);
	margin-block-end: var(--ids-space-3);
}

.progress__bar {
	width: 100%;
	height: var(--ids-space-2);
	accent-color: var(--color-primary-element);
}

.progress__text {
	composes: muted from '../../styles/shared.module.css';
	margin: 0;
}
</style>
