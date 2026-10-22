<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Check } from '../../types.ts'

import { mdiArrowRight } from '@mdi/js'
import { n, t } from '@nextcloud/l10n'
import { computed } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import { APP_ID } from '../../utils/format.ts'

const props = defineProps<{
	check: Check
}>()

/**
 * @param name - A setting of the check
 */
function value(name: string) {
	return props.check.params.find((p) => p.name === name)?.value
}

const summary = computed(() => {
	if (props.check.id === 'reserved_name') {
		const names = value('names')
		const list = Array.isArray(names) ? names : []
		return list.length === 0
			? t(APP_ID, 'No name is reserved yet.')
			: n(APP_ID, '%n name is reserved: {names}', '%n names are reserved: {names}', list.length, { names: list.join(', ') }, { escape: false, sanitize: false })
	}
	const paths = value('paths')
	const own = Array.isArray(paths) ? paths.length : 0
	const builtin = value('builtin_enabled') === true ? t(APP_ID, 'The built-in trap paths are on.') : t(APP_ID, 'The built-in trap paths are off.')
	return builtin + ' ' + n(APP_ID, 'You added %n path of your own.', 'You added %n paths of your own.', own)
})
</script>

<template>
	<fieldset :class="$style.link">
		<legend :class="$style.link__legend">
			{{ check.id === 'reserved_name' ? t(APP_ID, 'Reserved names') : t(APP_ID, 'Trap paths') }}
		</legend>
		<p :class="$style.link__text">
			{{ summary }}
		</p>
		<div>
			<NcButton variant="secondary" href="#blocks-decoys">
				<template #icon>
					<NcIconSvgWrapper :path="mdiArrowRight" />
				</template>
				{{ t(APP_ID, 'Manage them on the Blocks tab') }}
			</NcButton>
		</div>
	</fieldset>
</template>

<style module>
.link {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-2);
	min-width: 0;
	margin: 0;
	padding: 0;
	border: none;
}

.link__legend {
	margin-bottom: var(--ids-space-2);
	padding: 0;
	font-weight: 700;
}

.link__text {
	margin: 0;
	line-height: 1.5;
	overflow-wrap: anywhere;
}
</style>
