/****************************************************************************
 *
 * Copyright 2024 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/
/****************************************************************************
 * arch/arm/src/armv7-a/arm_cpugating.c
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <tinyara/config.h>

#include <stdint.h>
#include <assert.h>
#include <debug.h>

#include <tinyara/arch.h>
#include <tinyara/sched.h>
#include <tinyara/sched_note.h>

#include "up_internal.h"
#include "cp15_cacheops.h"
#include "gic.h"
#include "sched/sched.h"
#include "barriers.h"
#include "arch_timer.h"

#ifdef CONFIG_CPU_GATING
static volatile uint32_t g_cpugating_flag[CONFIG_SMP_NCPUS];

/****************************************************************************
 * Public Functions
 ****************************************************************************/

void up_set_gating_flag_status(uint32_t CoreID, uint32_t val)
{
	g_cpugating_flag[CoreID] = val;
	ARM_DSB();
	/* Flag already reach 0 */
	if (!g_cpugating_flag[CoreID]) {
		if (this_cpu() != 0) {
			up_timer_disable();
		}
		SP_SEV();
	}
}

uint32_t up_get_gating_flag_status(uint32_t CoreID)
{
	return g_cpugating_flag[CoreID];
}


void up_do_gating(void)
{
	int cpu = this_cpu();
	if (g_cpugating_flag[cpu] == 1) {
		uint32_t PrevIrqStatus = irqsave();
		g_cpugating_flag[cpu]++;
		ARM_DSB();
		ARM_ISB();
		while (g_cpugating_flag[cpu]) {
			SP_WFE();
		}
		irqrestore(PrevIrqStatus);
	}

}

/****************************************************************************
 * Name: arm_gating_handler
 *
 * Description:
 *   This is the handler for SGI3.  This handler simply send the another core
 *	 to wfe mode, to prevent from hang when flash operation is invoked
 *
 * Input Parameters:
 *   Standard interrupt handling
 *
 * Returned Value:
 *   Zero on success; a negated errno value on failure.
 *
 ****************************************************************************/
int arm_gating_handler(int irq, void *context, void *arg)
{
	up_do_gating();
	return OK;
}

/****************************************************************************
 * Name: up_cpu_gating
 *
 * Description:
 *   Send signal for target CPU to enter gating.
 *
 * Input Parameters:
 *   cpu - The index of the CPU being gated.
 *
 * Returned Value:
 *   None
 *
 ****************************************************************************/
void up_cpu_gating(int cpu)
{
	DEBUGASSERT(cpu >= 0 && cpu < CONFIG_SMP_NCPUS && cpu != this_cpu());

	/* If this cpu has already been paused, then we 
	 * will not perform gating. However, we will set
	 * the gating flag as if gating is performed. This
	 * is because, the main intention of both gating and 
	 * pausing the cpu is to prevent the cpu from running.
	 * Since this is already handled and cpu is in pause state,
	 * we can perform critical operation assuming gating is done.
	 * At a future point of time, the cpu will get resumed
	 * by the code which had initially paused it
	 */

	/* NOTE: This only works for 2 cpu case, in case of more cpus, 
	 * we need to redesign the pause and gating logic such that only
	 * the cpu or the task which called pause is allowed to call resume.
	 */

	if (up_is_cpu_paused(cpu)) {
		g_cpugating_flag[cpu] = 2;
		return;
	} else if (up_cpu_pausereq(cpu)) {
		/* On the other hand, if a pause request is pending, it 
		 * has to be handled first and then the caller must retry
		 * gating request
		 */
		return;
	}

	/* Fire SGI for cpu to enter gating */
	arm_cpu_sgi(GIC_IRQ_SGI3, (1 << cpu));

	/* after gating other CPU, this cpu is the active timer, since the other one will be gated */
	if (cpu == 0 && g_cpugating_flag[cpu] != 0) {
		up_timer_enable();
	}
}

#endif /* CONFIG_CPU_GATING */
