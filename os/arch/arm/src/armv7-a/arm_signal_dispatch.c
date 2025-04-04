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
 * arch/arm/src/armv7-a/arm_signal_dispatch.c
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
#include <tinyara/arch.h>

#include <arch/syscall.h>

#include "up_internal.h"

#if !defined(CONFIG_BUILD_FLAT) && defined(__KERNEL__)

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: up_signal_dispatch
 *
 * Description:
 *   In the kernel mode build, this function will be called to execute a
 *   a signal handler in user-space.  When the signal is delivered, a
 *   kernel-mode stub will first run to perform some housekeeping functions.
 *   This kernel-mode stub will then be called transfer control to the user
 *   mode signal handler by calling this function.
 *
 *   Normally the user-mode signaling handling stub will also execute
 *   before the ultimate signal handler is called.  See
 *   arch/arm/src/armvx-y/arm_signal_handler.S.  This function is the
 *   user-space, signal handler trampoline function.  It is called from
 *   up_signal_dispatch() in user-mode.
 *
 * Input Parameters:
 *   sighand - The address user-space signal handling function
 *   signo, info, and ucontext - Standard arguments to be passed to the
 *     signal handling function.
 *
 * Returned Value:
 *   None.  This function does not return in the normal sense.  It returns
 *   via an architecture specific system call made by up_signal_handler().
 *   However, this will look like a normal return by the caller of
 *   up_signal_dispatch.
 *
 ****************************************************************************/

#ifndef CONFIG_DISABLE_SIGNALS
void up_signal_dispatch(_sa_sigaction_t sighand, int signo, siginfo_t *info, void *ucontext)
{
	/* Let sys_call4() do all of the work */

	sys_call4(SYS_signal_handler, (uintptr_t) sighand, (uintptr_t) signo, (uintptr_t) info, (uintptr_t) ucontext);
}
#endif
#endif							/* !CONFIG_BUILD_FLAT && __KERNEL__ */
