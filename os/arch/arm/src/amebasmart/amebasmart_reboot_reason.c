/****************************************************************************
 *
 * Copyright 2023 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ****************************************************************************/
/****************************************************************************
 *
 *   Copyright (C) 2020 Gregory Nutt. All rights reserved.
 *   Author: Gregory Nutt <gnutt@nuttx.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name NuttX nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <tinyara/config.h>

#include <stdbool.h>
#include <debug.h>
#include <tinyara/reboot_reason.h>
#include "ameba_soc.h"
#include "amebasmart_reboot_reason.h"
/****************************************************************************
 * Public functions
 ****************************************************************************/
#ifdef CONFIG_SYSTEM_REBOOT_REASON

static reboot_reason_code_t reboot_reason;

static reboot_reason_code_t up_reboot_reason_get_hw_value(void)
{
	u32 boot_reason = 0;
	u32 boot_reason_reg2 = 0;

	/* Read the same backup register for the boot reason */
	boot_reason = BKUP_Read(BKUP_REG1);
	boot_reason_reg2 = BKUP_Read(BKUP_REG2);

	if ((boot_reason != REBOOT_REASON_INITIALIZED) && (boot_reason != 0)) {
		if (boot_reason_reg2 == 0x1) {
			BKUP_Write(BKUP_REG2, 0);
			boot_reason = REBOOT_SYSTEM_NP_LP_FAULT;
		}
		return boot_reason;
	} else {
		/* Read AmebaSmart Boot Reason, WDT and HW reset supported */
		boot_reason = BOOT_Reason();

		/* HW reset */
		if (boot_reason == 0) {
			return REBOOT_SYSTEM_HW_RESET;
		}

		/* CA32:WDG4 or KM4:WDG2 or KM0:IWDG NonSecure WDG reset */
		else if ((boot_reason & AON_BIT_RSTF_WDG4) || (boot_reason & AON_BIT_RSTF_WDG2)) {
			/* CA32 Secure ATF doesn't have OS, no implementation for CA32 Secure Watchdog WDG3
			 * When CA32 occurred Secure Fault, it will rely on CA32 NonSecure WDG4 to Reset
			 * BKUP_REG2 is use to distinguish whether the fault originated from the CA32 S or NS */

			 /* CA32:WDG3 Secure WDG reset */
			if (boot_reason_reg2 & AON_BIT_RSTF_WDG3) {
				BKUP_Write(BKUP_REG2, 0);
				return REBOOT_SYSTEM_TZWD_RESET;
			}
			else {
				if (boot_reason & AON_BIT_RSTF_WDG4) {
					lldbg("Reboot reason: WDG4 reset\n");
				} else if (boot_reason & AON_BIT_RSTF_WDG2) {
					lldbg("Reboot reason: WDG2 reset\n");
				}
				return REBOOT_SYSTEM_WATCHDOG;
			}
		}

		/* KM4:WDG1 Secure WDG reset */
		else if (boot_reason & AON_BIT_RSTF_WDG1) {
			return REBOOT_SYSTEM_TZWD_RESET;
		}
		/* KM0: IWDG reset*/
		else if (boot_reason & AON_BIT_RSTF_IWDG) {
			/* KM0: IWDG is used in KM0 to ensure KM0 is working properly, KM4 is wakeup properly from PG, CA32 power is power-on from PG
			* backup register will be used to record the case that triggered IWDG reboot
			*/
			if (boot_reason_reg2 == 0x2) {
				BKUP_Write(BKUP_REG2, 0);
				lldbg("Reboot reason: IWDG reset, KM4 wakeup failed\n");
			} else if (boot_reason_reg2 == 0x3) {
				BKUP_Write(BKUP_REG2, 0);
				lldbg("Reboot reason: IWDG reset, CA32 wakeup failed\n");
			}
			return REBOOT_SYSTEM_RESET_IWDG;
		}

		/* KM4 deep sleep handled by KM0 (KM4 sleep + KM0 tickless, KM4 deep sleep + KM0 deep sleep AON) */
		else if (boot_reason & AON_BIT_RSTF_DSLP) {
			return REBOOT_SYSTEM_DSLP_RESET;
		}

		/* CA32:AP or KM4:NP or KM0:LP System reset */
		else if ((boot_reason & AON_BIT_RSTF_APSYS) || (boot_reason & AON_BIT_RSTF_NPSYS) || (boot_reason & AON_BIT_RSTF_LPSYS)) {
			if (boot_reason & AON_BIT_RSTF_APSYS) {			/* CA32 */
				lldbg("Reboot reason: APSYS reset\n");
			} else if (boot_reason & AON_BIT_RSTF_NPSYS) {	/* KM4 */
				lldbg("Reboot reason: NPSYS reset\n");
			} else {										/* (boot_reason & AON_BIT_RSTF_LPSYS) */
				lldbg("Reboot reason: LPSYS reset\n");
			}
			return REBOOT_SYSTEM_SYS_RESET_CORE;
		}

		/* Brownout reset */
		else if (boot_reason & AON_BIT_RSTF_BOR) {
			return REBOOT_SYSTEM_BOD_RESET;
		}
	}

	return REBOOT_UNKNOWN;
}

void up_reboot_reason_init(void)
{
	reboot_reason = up_reboot_reason_get_hw_value();
	BKUP_Write(BKUP_REG1, REBOOT_REASON_INITIALIZED);
}

reboot_reason_code_t up_reboot_reason_read(void)
{
	int reason = reboot_reason;
	rrvdbg("Read Reboot Reason : %d\n", reason);
	return reason;
}

void up_reboot_reason_write(reboot_reason_code_t reason)
{
	rrvdbg("Write Reboot Reason : %d\n", reason);
	/* Set the specific bit in BKUP_REG1 */
	BKUP_Write(BKUP_REG1, (u32)reason);
}

void up_reboot_reason_clear(void)
{
	rrvdbg("Clear Reboot Reason\n");
	/* Reboot Reason Clear API writes the REBOOT_REASON_INITIALIZED by default.
	 * If chip vendor needs another thing to do, please change the below.
	 */
	up_reboot_reason_write(REBOOT_REASON_INITIALIZED);
	reboot_reason = REBOOT_REASON_INITIALIZED;
}

bool up_reboot_reason_is_written(void)
{
	if (BKUP_Read(BKUP_REG1) != REBOOT_REASON_INITIALIZED) {
		return true;
	}

	return false;
}
#endif
