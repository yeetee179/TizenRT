/****************************************************************************
 *
 * Copyright 2016 Samsung Electronics All Rights Reserved.
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
 * kernel/pthread/pthread_condtimedwait.c
 *
 *   Copyright (C) 2007-2009, 2013-2014 Gregory Nutt. All rights reserved.
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
#include <tinyara/compiler.h>

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <debug.h>

#include <tinyara/cancelpt.h>
#include <tinyara/wdog.h>

#include "sched/sched.h"
#include "pthread/pthread.h"
#include "clock/clock.h"
#include "signal/signal.h"

/****************************************************************************
 * Definitions
 ****************************************************************************/

/****************************************************************************
 * Private Type Declarations
 ****************************************************************************/

/****************************************************************************
 * Global Variables
 ****************************************************************************/

/****************************************************************************
 * Private Variables
 ****************************************************************************/

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: pthread_condtimedout
 *
 * Description:
 *   This function is called if the timeout elapses before
 *   the condition is signaled.
 *
 * Parameters:
 *   argc  - the number of arguments (should be 2)
 *   pid   - the task ID of the task to wakeup
 *   signo - The signal to use to wake up the task
 *
 * Return Value:
 *   None
 *
 * Assumptions:
 *
 ****************************************************************************/

static void pthread_condtimedout(int argc, uint32_t pid, uint32_t signo)
{
#ifdef HAVE_GROUP_MEMBERS

	FAR struct tcb_s *tcb;
	siginfo_t info;

	/* The logic below if equivalent to sigqueue(), but uses sig_tcbdispatch()
	 * instead of sig_dispatch().  This avoids the group signal deliver logic
	 * and assures, instead, that the signal is delivered specifically to this
	 * thread that is known to be waiting on the signal.
	 */

	/* Get the waiting TCB.  sched_gettcb() might return NULL if the task has
	 * exited for some reason.
	 */

	tcb = sched_gettcb((pid_t)pid);
	if (tcb) {
		/* Create the siginfo structure */

		info.si_signo = signo;
		info.si_code = SI_QUEUE;
		info.si_value.sival_ptr = NULL;
#ifdef CONFIG_SCHED_HAVE_PARENT
		info.si_pid = (pid_t)pid;
		info.si_status = OK;
#endif

		/* Process the receipt of the signal.  The scheduler is not locked as
		 * is normally the case when this function is called because we are in
		 * a watchdog timer interrupt handler.
		 */

		(void)sig_tcbdispatch(tcb, &info);
	}
#else							/* HAVE_GROUP_MEMBERS */

	/* Things are a little easier if there are not group members.  We can just
	 * use sigqueue().
	 */

#ifdef CONFIG_CAN_PASS_STRUCTS
	union sigval value;

	/* Send the specified signal to the specified task. */

	value.sival_ptr = NULL;
	(void)sigqueue((int)pid, (int)signo, value);
#else
	(void)sigqueue((int)pid, (int)signo, NULL);
#endif

#endif							/* HAVE_GROUP_MEMBERS */
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: pthread_cond_timedwait
 *
 * Description:
 *   A thread can perform a timed wait on a condition variable.
 *
 * Parameters:
 *   cond   - the condition variable to wait on
 *   mutex   - the mutex that protects the condition variable
 *   abstime - wait until this absolute time
 *
 * Return Value:
 * OK (0) on success; A non-zero errno value is returned on failure.
 *
 * Assumptions:
 *   Timing is of resolution 1 msec, with +/-1 millisecond accuracy.
 *
 ****************************************************************************/

int pthread_cond_timedwait(FAR pthread_cond_t *cond, FAR pthread_mutex_t *mutex, FAR const struct timespec *abstime)
{
	FAR struct tcb_s *rtcb = this_task();
	int ticks;
	int mypid = (int)getpid();
	irqstate_t int_state;
	uint16_t oldstate;
	int ret = OK;
	int status;

	svdbg("cond=0x%p mutex=0x%p abstime=0x%p\n", cond, mutex, abstime);

	DEBUGASSERT(rtcb->waitdog == NULL);

	/* pthread_cond_timedwait() is a cancellation point */
	(void)enter_cancellation_point();

	/* Make sure that non-NULL references were provided. */

	if (!cond || !mutex) {
		ret = EINVAL;
	}

	/* Make sure that the caller holds the mutex */

	else if (mutex->pid != mypid) {
		ret = EPERM;
	}

	/* If no wait time is provided, this function degenerates to
	 * the same behavior as pthread_cond_wait().
	 */

	else if (!abstime) {
		ret = pthread_cond_wait(cond, mutex);
	}

	else {
		/* Create a watchdog */

		rtcb->waitdog = wd_create();
		if (!rtcb->waitdog) {
			ret = ENOMEM;
		} else {
			svdbg("Give up mutex...\n");

			/* We must disable pre-emption and interrupts here so that
			 * the time stays valid until the wait begins.   This adds
			 * complexity because we assure that interrupts and
			 * pre-emption are re-enabled correctly.
			 */

			sched_lock();
			int_state = enter_critical_section();

			/* Convert the timespec to clock ticks.  We must disable pre-emption
			 * here so that this time stays valid until the wait begins.
			 */

			ret = clock_abstime2ticks(CLOCK_REALTIME, abstime, &ticks);
			if (ret) {
				/* Restore interrupts  (pre-emption will be enabled when
				 * we fall through the if/then/else)
				 */

				leave_critical_section(int_state);
			} else {
				/* Check the absolute time to wait.  If it is now or in the past, then
				 * just return with the timedout condition.
				 */

				if (ticks <= 0) {
					/* Restore interrupts and indicate that we have already timed out.
					 * (pre-emption will be enabled when we fall through the
					 * if/then/else
					 */

					leave_critical_section(int_state);
					ret = ETIMEDOUT;
				} else {
					/* Give up the mutex */

					mutex->pid = -1;
					ret = pthread_mutex_give(mutex);
					if (ret != 0) {
						/* Restore interrupts  (pre-emption will be enabled when
						 * we fall through the if/then/else)
						 */

						leave_critical_section(int_state);
					} else {
						/* Start the watchdog */

						wd_start(rtcb->waitdog, ticks, (wdentry_t)pthread_condtimedout, 2, (uint32_t)mypid, (uint32_t)SIGCONDTIMEDOUT);

						/* Take the condition semaphore.  Do not restore interrupts
						 * until we return from the wait.  This is necessary to
						 * make sure that the watchdog timer and the condition wait
						 * are started atomically.
						 */

						status = sem_wait((sem_t *)&cond->sem);

						/* Did we get the condition semaphore. */

						if (status != OK) {
							/* NO.. Handle the special case where the semaphore wait was
							 * awakened by the receipt of a signal -- presumably the
							 * signal posted by pthread_condtimedout().
							 */

							if (get_errno() == EINTR) {
								sdbg("Timedout!\n");
								ret = ETIMEDOUT;
							} else {
								ret = EINVAL;
							}
						}

						/* The interrupts stay disabled until after we sample the errno.
						 * This is because when debug is enabled and the console is used
						 * for debug output, then the errno can be altered by interrupt
						 * handling! (bad)
						 */

						leave_critical_section(int_state);
					}

					/* Reacquire the mutex (retaining the ret). */

					svdbg("Re-locking...\n");

					oldstate = pthread_disable_cancel();
					status = pthread_mutex_take(mutex);
					pthread_enable_cancel(oldstate);

					if (status == OK) {
						mutex->pid = mypid;
					} else if (ret == 0) {
						ret = status;
					}
				}

				/* Re-enable pre-emption (It is expected that interrupts
				 * have already been re-enabled in the above logic)
				 */

				sched_unlock();
			}

			/* We no longer need the watchdog */

			wd_delete(rtcb->waitdog);
			rtcb->waitdog = NULL;
		}
	}

	svdbg("Returning %d\n", ret);
	leave_cancellation_point();
	return ret;
}
