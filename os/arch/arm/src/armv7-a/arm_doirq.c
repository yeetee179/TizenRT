/****************************************************************************
 *
 * Copyright 2023 Samsung Electronics All Rights Reserved.
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
 * arch/arm/src/armv7-a/arm_doirq.c
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <tinyara/config.h>

#include <stdint.h>
#include <assert.h>
#include <debug.h>

#include <tinyara/irq.h>
#include <tinyara/arch.h>
#include <tinyara/board.h>
#include <arch/board/board.h>

#include "up_internal.h"
#include "group/group.h"
#include "gic.h"

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int g_irq_num[CONFIG_SMP_NCPUS] = {-1, };				/* Array to store the last three interrupt numbers */
/****************************************************************************
 * Name: arm_doirq
 *
 * Description:
 *   Receives the decoded GIC interrupt information and dispatches control
 *   to the attached interrupt handler.
 *
 ****************************************************************************/

uint32_t *arm_doirq(int irq, uint32_t *regs)
{
	/* Store the interrupt number for reference during assert */
	g_irq_num[up_cpu_index()] = irq;

	board_autoled_on(LED_INIRQ);
#ifdef CONFIG_SUPPRESS_INTERRUPTS
	PANIC();
#else
	/* Nested interrupts are not supported */

	DEBUGASSERT(CURRENT_REGS == NULL);

	/* Current regs non-zero indicates that we are processing an interrupt;
	 * CURRENT_REGS is also used to manage interrupt level context switches.
	 */

	CURRENT_REGS = regs;

	/* Deliver the IRQ */

	irq_dispatch(irq, regs);

  if (regs != CURRENT_REGS)
    {
#ifdef CONFIG_ARCH_ADDRENV
	/* Check for a context switch.  If a context switch occurred, then
	 * CURRENT_REGS will have a different value than it did on entry.  If an
	 * interrupt level context switch has occurred, then establish the correct
	 * address environment before returning from the interrupt.
	 */

      /* Make sure that the address environment for the previously
       * running task is closed down gracefully (data caches dump,
       * MMU flushed) and set up the address environment for the new
       * thread at the head of the ready-to-run list.
       */

      group_addrenv(NULL);
#endif

      restore_critical_section();
      regs = (uint32_t *)CURRENT_REGS;    
    }

  /* Set CURRENT_REGS to NULL to indicate that we are no longer in an
   * interrupt handler.
   */

  CURRENT_REGS = NULL;
#endif
	/* Reset the interrupt number values */
	g_irq_num[up_cpu_index()] = -1;

	board_autoled_off(LED_INIRQ);
	return regs;
}
