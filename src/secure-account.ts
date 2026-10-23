/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import axios from '@nextcloud/axios'
import { addPasswordConfirmationInterceptors } from '@nextcloud/password-confirmation'
import { createApp } from 'vue'
import SecureAccount from './views/SecureAccount.vue'

import 'vite/modulepreload-polyfill'
import './styles/tokens.css'

addPasswordConfirmationInterceptors(axios)

createApp(SecureAccount).mount('#intrusion_detection-secure-account')
