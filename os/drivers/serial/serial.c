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
/************************************************************************************
 * drivers/serial/serial.c
 *
 *   Copyright (C) 2007-2009, 2011-2013 Gregory Nutt. All rights reserved.
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
 ************************************************************************************/

/************************************************************************************
 * Included Files
 ************************************************************************************/

#include <tinyara/config.h>

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <debug.h>
#include <mqueue.h>

#include <tinyara/irq.h>
#include <tinyara/arch.h>
#include <tinyara/semaphore.h>
#include <tinyara/fs/fs.h>
#include <tinyara/serial/serial.h>
#include <tinyara/fs/ioctl.h>
#ifdef CONFIG_LOG_DUMP
#include <tinyara/log_dump/log_dump.h>
#include <tinyara/log_dump/log_dump_internal.h>
#endif
#ifdef CONFIG_PM
#include <tinyara/pm/pm.h>
#endif


/************************************************************************************
 * Definitions
 ************************************************************************************/

/* The architecture must provide up_putc for this driver */

#ifndef CONFIG_ARCH_LOWPUTC
#error "Architecture must provide up_putc() for this driver"
#endif

#ifdef CONFIG_PM
#define PM_UART_DOMAIN "UART"
#endif

#define uart_putc(ch) up_putc(ch)

#define HALF_SECOND_MSEC 500
#define HALF_SECOND_USEC 500000L

/************************************************************************************
 * Private Types
 ************************************************************************************/

/************************************************************************************
 * Private Function Prototypes
 ************************************************************************************/

static int uart_open(FAR struct file *filep);
static int uart_close(FAR struct file *filep);
static ssize_t uart_read(FAR struct file *filep, FAR char *buffer, size_t buflen);
static ssize_t uart_write(FAR struct file *filep, FAR const char *buffer, size_t buflen);
static int uart_ioctl(FAR struct file *filep, int cmd, unsigned long arg);
#ifndef CONFIG_DISABLE_POLL
static int uart_poll(FAR struct file *filep, FAR struct pollfd *fds, bool setup);
#endif

/************************************************************************************
 * Private Variables
 ************************************************************************************/

#ifdef CONFIG_PM
static int pm_uart_domain_id = -1;
#endif 

static const struct file_operations g_serialops = {
	uart_open,					/* open */
	uart_close,					/* close */
	uart_read,					/* read */
	uart_write,					/* write */
	0,							/* seek */
	uart_ioctl					/* ioctl */
#ifndef CONFIG_DISABLE_POLL
	, uart_poll				/* poll */
#endif
};

/************************************************************************************
 * Private Functions
 ************************************************************************************/

/************************************************************************************
 * Name: uart_takesem
 ************************************************************************************/

static int uart_takesem(FAR sem_t *sem, bool errout)
{
	/* Loop, ignoring interrupts, until we have successfully acquired the semaphore */

	while (sem_wait(sem) != OK) {
		/* The only case that an error should occur here is if the wait was awakened
		 * by a signal.
		 */

		ASSERT(get_errno() == EINTR);

		/* When the signal is received, should we errout? Or should we just continue
		 * waiting until we have the semaphore?
		 */

		if (errout) {
			return -EINTR;
		}
	}

	return OK;
}


/************************************************************************************
 * Name: uart_givesem
 ************************************************************************************/

#define uart_givesem(sem) (void)sem_post(sem)

/****************************************************************************
 * Name: uart_pollnotify
 ****************************************************************************/

#ifndef CONFIG_DISABLE_POLL
static void uart_pollnotify(FAR uart_dev_t *dev, pollevent_t eventset)
{
	int i;

	for (i = 0; i < CONFIG_SERIAL_NPOLLWAITERS; i++) {
		struct pollfd *fds = dev->fds[i];
		if (fds) {
#ifdef CONFIG_SERIAL_REMOVABLE
			fds->revents |= ((fds->events | (POLLERR | POLLHUP)) & eventset);
#else
			fds->revents |= (fds->events & eventset);
#endif
			if (fds->revents != 0) {
				fvdbg("Report events: %02x\n", fds->revents);
				sem_post(fds->sem);
			}
		}
	}
}
#else
#define uart_pollnotify(dev, event)
#endif


/************************************************************************************
 * Name: uart_datareceived
 *
 * Description:
 *   This function is called from uart_recvchars when new serial data is place in
 *   the driver's circular buffer.  This function will wake-up any stalled read()
 *   operations that are waiting for incoming data.
 *
 ************************************************************************************/

void uart_datareceived(FAR uart_dev_t *dev)
{
	/* Is there a thread waiting for read data?  */

	if (dev->recvwaiting) {
		/* Yes... wake it up */

		dev->recvwaiting = false;
		(void)sem_post(&dev->recvsem);
	}

	/* Notify all poll/select waiters that they can read from the recv buffer */

	uart_pollnotify(dev, POLLIN);
}

/************************************************************************************
 * Name: uart_datasent
 *
 * Description:
 *   This function is called from uart_xmitchars after serial data has been sent,
 *   freeing up some space in the driver's circular buffer. This function will
 *   wake-up any stalled write() operations that was waiting for space to buffer
 *   outgoing data.
 *
 ************************************************************************************/

void uart_datasent(FAR uart_dev_t *dev)
{
	/* Is there a thread waiting for space in xmit.buffer?  */

	if (dev->xmitwaiting) {
		/* Yes... wake it up */

		dev->xmitwaiting = false;
		(void)sem_post(&dev->xmitsem);
	}

	/* Notify all poll/select waiters that they can write to xmit buffer */

	uart_pollnotify(dev, POLLOUT);
}

/************************************************************************************
 * Name: uart_putxmitchar
 ************************************************************************************/

static int uart_putxmitchar(FAR uart_dev_t *dev, int ch, bool oktoblock)
{
	irqstate_t flags;
	int nexthead;
	int ret;

	/* Increment to see what the next head pointer will be.  We need to use the "next"
	 * head pointer to determine when the circular buffer would overrun
	 */

	nexthead = dev->xmit.head + 1;
	if (nexthead >= dev->xmit.size) {
		nexthead = 0;
	}

	/* Loop until we are able to add the character to the TX buffer */

	for (;;) {
		if (nexthead != dev->xmit.tail) {
			dev->xmit.buffer[dev->xmit.head] = ch;
#ifdef CONFIG_LOG_DUMP
			/* only save UART data that is being transmitted to the console */

			if (dev->isconsole) {
				log_dump_save(ch);
			}
#endif
			dev->xmit.head = nexthead;
			return OK;
		}

		/* The buffer is full and no data is available now.  Should be block,
		 * waiting for the hardware to remove some data from the TX
		 * buffer?
		 */

		else if (oktoblock) {
			/* Inform the interrupt level logic that we are waiting. This and
			 * the following steps must be atomic.
			 */

			flags = enter_critical_section();

			/* Check again...  In certain race conditions an interrupt may
			 * have occurred between the test at the top of the loop and
			 * entering the critical section and the TX buffer may no longer
			 * be full.
			 *
			 * NOTE: On certain devices, such as USB CDC/ACM, the entire TX
			 * buffer may have been emptied in this race condition.  In that
			 * case, the logic would hang below waiting for space in the TX
			 * buffer without this test.
			 */

			if (nexthead != dev->xmit.tail) {
				ret = OK;
			}
#ifdef CONFIG_SERIAL_REMOVABLE
			/* Check if the removable device is no longer connected while we
			 * have interrupts off.  We do not want the transition to occur
			 * as a race condition before we begin the wait.
			 */

			else if (dev->disconnected) {
				ret = -ENOTCONN;
			}
#endif
			else {
				/* Wait for some characters to be sent from the buffer with
				 * the TX interrupt enabled.  When the TX interrupt is
				 * enabled, uart_xmitchars should execute and remove some
				 * of the data from the TX buffer.
				 */

				dev->xmitwaiting = true;
				uart_enabletxint(dev);
				ret = uart_takesem(&dev->xmitsem, true);
				uart_disabletxint(dev);
			}

			leave_critical_section(flags);

#ifdef CONFIG_SERIAL_REMOVABLE
			/* Check if the removable device was disconnected while we were
			 * waiting.
			 */

			if (dev->disconnected) {
				return -ENOTCONN;
			}
#endif
			/* Check if we were awakened by signal. */

			if (ret < 0) {
				/* A signal received while waiting for the xmit buffer to become
				 * non-full will abort the transfer.
				 */

				return -EINTR;
			}
		}

		/* The caller has request that we not block for data.  So return the
		 * EAGAIN error to signal this situation.
		 */

		else {
			return -EAGAIN;
		}
	}

	/* We won't get here.  Some compilers may complain that this code is
	 * unreachable.
	 */

	return OK;
}

/************************************************************************************
 * Name: uart_irqwrite
 ************************************************************************************/

static inline ssize_t uart_irqwrite(FAR uart_dev_t *dev, FAR const char *buffer, size_t buflen)
{
	ssize_t ret = buflen;

	/* Force each character through the low level interface */

	for (; buflen; buflen--) {
		int ch = *buffer++;

		/* If this is the console, then we should replace LF with CR-LF */

		if (ch == '\n') {
			uart_putc('\r');
		}

		/* Output the character, using the low-level direct UART interfaces */

		uart_putc(ch);
	}

	return ret;
}

/************************************************************************************
 * Name: uart_write
 ************************************************************************************/

static ssize_t uart_write(FAR struct file *filep, FAR const char *buffer, size_t buflen)
{
	FAR struct inode *inode = filep->f_inode;
	FAR uart_dev_t *dev = inode->i_private;
	ssize_t nwritten = buflen;
	bool oktoblock;
	int ret;
	char ch;

	/* We may receive console writes through this path from interrupt handlers and
	 * from debug output in the IDLE task!  In these cases, we will need to do things
	 * a little differently.
	 */

	if (up_interrupt_context() || getpid() == 0) {
#ifdef CONFIG_SERIAL_REMOVABLE
		/* If the removable device is no longer connected, refuse to write to
		 * the device.
		 */

		if (dev->disconnected) {
			return -ENOTCONN;
		}
#endif

		/* up_putc() will be used to generate the output in a busy-wait loop.
		 * up_putc() is only available for the console device.
		 */

		if (dev->isconsole) {
			irqstate_t flags = enter_critical_section();
			ret = uart_irqwrite(dev, buffer, buflen);
			leave_critical_section(flags);
			return ret;
		} else {
			return -EPERM;
		}
	}

	/* Only one user can access dev->xmit.head at a time */

	ret = (ssize_t)uart_takesem(&dev->xmit.sem, true);
	if (ret < 0) {
		/* A signal received while waiting for access to the xmit.head will
		 * abort the transfer.  After the transfer has started, we are committed
		 * and signals will be ignored.
		 */

		return ret;
	}
#ifdef CONFIG_SERIAL_REMOVABLE
	/* If the removable device is no longer connected, refuse to write to the
	 * device.  This check occurs after taking the xmit.sem because the
	 * disconnection event might have occurred while we were waiting for
	 * access to the transmit buffers.
	 */

	if (dev->disconnected) {
		uart_givesem(&dev->xmit.sem);
		return -ENOTCONN;
	}
#endif

	/* Can the following loop block, waiting for space in the TX
	 * buffer?
	 */

	oktoblock = ((filep->f_oflags & O_NONBLOCK) == 0);

#ifdef CONFIG_PM
	/* Suspend board sleep to avoid data loss during write */
	(void)pm_suspend(pm_uart_domain_id);
#endif

	/* Loop while we still have data to copy to the transmit buffer.
	 * we add data to the head of the buffer; uart_xmitchars takes the
	 * data from the end of the buffer.
	 */

	uart_disabletxint(dev);
	for (; buflen; buflen--) {
		ch = *buffer++;
		ret = OK;

#ifdef CONFIG_SERIAL_TERMIOS
		/* Do output post-processing */

		if ((dev->tc_oflag & OPOST) != 0) {
			/* Mapping CR to NL? */

			if ((ch == '\r') && (dev->tc_oflag & OCRNL) != 0) {
				ch = '\n';
			}

			/* Are we interested in newline processing? */

			if ((ch == '\n') && (dev->tc_oflag & (ONLCR | ONLRET)) != 0) {
				ret = uart_putxmitchar(dev, '\r', oktoblock);
				if (ret < 0) {
					nwritten = ret;
					break;
				}
			}

			/* Specifically not handled:
			 *
			 * OXTABS - primarily a full-screen terminal optimisation
			 * ONOEOT - Unix interoperability hack
			 * OLCUC  - Not specified by POSIX
			 * ONOCR  - low-speed interactive optimisation
			 */
		}
#else							/* !CONFIG_SERIAL_TERMIOS */
		/* If this is the console, convert \n -> \r\n */

		if (dev->isconsole && ch == '\n') {
			ret = uart_putxmitchar(dev, '\r', oktoblock);
		}
#endif

		/* Put the character into the transmit buffer */

		if (ret == OK) {
			ret = uart_putxmitchar(dev, ch, oktoblock);
		}

		/* uart_putxmitchar() might return an error under one of two
		 * conditions:  (1) The wait for buffer space might have been
		 * interrupted by a signal (ret should be -EINTR), (2) if
		 * CONFIG_SERIAL_REMOVABLE is defined, then uart_putxmitchar()
		 * might also return if the serial device was disconnected
		 * (with -ENOTCONN), or (3) if O_NONBLOCK is specified, then
		 * then uart_putxmitchar() might return -EAGAIN if the output
		 * TX buffer is full.
		 */

		if (ret < 0) {
			/* POSIX requires that we return -1 and errno set if no data was
			 * transferred.  Otherwise, we return the number of bytes in the
			 * interrupted transfer.
			 */

			if (buflen < nwritten) {
				/* Some data was transferred.  Return the number of bytes that
				 * were successfully transferred.
				 */

				nwritten -= buflen;
			} else {
				/* No data was transferred. Return the negated errno value.
				 * The VFS layer will set the errno value appropriately).
				 */

				nwritten = ret;
			}

			break;
		}
	}

	if (dev->xmit.head != dev->xmit.tail) {
		uart_enabletxint(dev);
	}

#ifdef CONFIG_PM
	/* Enable board sleep after completing write operation */
	(void)pm_resume(pm_uart_domain_id);
#endif
	uart_givesem(&dev->xmit.sem);
	return nwritten;
}

/************************************************************************************
 * Name: uart_read
 ************************************************************************************/

static ssize_t uart_read(FAR struct file *filep, FAR char *buffer, size_t buflen)
{
	FAR struct inode *inode = filep->f_inode;
	FAR uart_dev_t *dev = inode->i_private;
	FAR struct uart_buffer_s *rxbuf = &dev->recv;
#ifdef CONFIG_SERIAL_IFLOWCONTROL_WATERMARKS
	unsigned int nbuffered;
	unsigned int watermark;
#endif
	irqstate_t flags;
	ssize_t recvd = 0;
	int16_t tail;
	char ch;
	int ret;

	/* Only one user can access rxbuf->tail at a time */

	ret = uart_takesem(&rxbuf->sem, true);
	if (ret < 0) {
		/* A signal received while waiting for access to the recv.tail will avort
		 * the transfer.  After the transfer has started, we are committed and
		 * signals will be ignored.
		 */

		return ret;
	}

	/* Loop while we still have data to copy to the receive buffer.
	 * we add data to the head of the buffer; uart_xmitchars takes the
	 * data from the end of the buffer.
	 */

	while (recvd < buflen) {
#ifdef CONFIG_SERIAL_REMOVABLE
		/* If the removable device is no longer connected, refuse to read any
		 * further from the device.
		 */

		if (dev->disconnected) {
			if (recvd == 0) {
				recvd = -ENOTCONN;
			}

			break;
		}
#endif

		/* Check if there is more data to return in the circular buffer.
		 * NOTE: Rx interrupt handling logic may asynchronously increment
		 * the head index but must not modify the tail index.  The tail
		 * index is only modified in this function.  Therefore, no
		 * special handshaking is required here.
		 *
		 * The head and tail pointers are 16-bit values.  The only time that
		 * the following could be unsafe is if the CPU made two non-atomic
		 * 8-bit accesses to obtain the 16-bit head index.
		 */

		tail = rxbuf->tail;
		if (rxbuf->head != tail) {
			/* Take the next character from the tail of the buffer */

			ch = rxbuf->buffer[tail];

			/* Increment the tail index.  Most operations are done using the
			 * local variable 'tail' so that the final rxbuf->tail update
			 * is atomic.
			 */

			if (++tail >= rxbuf->size) {
				tail = 0;
			}

			rxbuf->tail = tail;

#ifdef CONFIG_SERIAL_TERMIOS
			/* Do input processing if any is enabled */

			if (dev->tc_iflag & (INLCR | IGNCR | ICRNL)) {
				/* \n -> \r or \r -> \n translation? */

				if ((ch == '\n') && (dev->tc_iflag & INLCR)) {
					ch = '\r';
				} else if ((ch == '\r') && (dev->tc_iflag & ICRNL)) {
					ch = '\n';
				}

				/* Discarding \r ? */

				if ((ch == '\r') & (dev->tc_iflag & IGNCR)) {
					continue;
				}
			}

			/* Specifically not handled:
			 *
			 * All of the local modes; echo, line editing, etc.
			 * Anything to do with break or parity errors.
			 * ISTRIP - we should be 8-bit clean.
			 * IUCLC - Not Posix
			 * IXON/OXOFF - no xon/xoff flow control.
			 */
#endif

			/* Store the received character */

			*buffer++ = ch;
			recvd++;
		}
#ifdef CONFIG_DEV_SERIAL_FULLBLOCKS
		/* No... then we would have to wait to get receive more data.
		 * If the user has specified the O_NONBLOCK option, then just
		 * return what we have.
		 */

		else if ((filep->f_oflags & O_NONBLOCK) != 0) {
			/* If nothing was transferred, then return the -EAGAIN
			 * error (not zero which means end of file).
			 */

			if (recvd < 1) {
				recvd = -EAGAIN;
			}

			break;
		}
#else
		/* No... the circular buffer is empty.  Have we returned anything
		 * to the caller?
		 */

		else if (recvd > 0) {
			/* Yes.. break out of the loop and return the number of bytes
			 * received up to the wait condition.
			 */

			break;
		}

		/* No... then we would have to wait to get receive some data.
		 * If the user has specified the O_NONBLOCK option, then do not
		 * wait.
		 */

		else if ((filep->f_oflags & O_NONBLOCK) != 0) {
			/* Break out of the loop returning -EAGAIN */

			recvd = -EAGAIN;
			break;
		}
#endif
		/* Otherwise we are going to have to wait for data to arrive */

		else {
			/* Disable Rx interrupts and test again... */

			uart_disablerxint(dev);

			/* If the Rx ring buffer still empty?  Bytes may have been addded
			 * between the last time that we checked and when we disabled Rx
			 * interrupts.
			 */

			if (rxbuf->head == rxbuf->tail) {
				/* Yes.. the buffer is still empty.  Wait for some characters
				 * to be received into the buffer with the RX interrupt re-
				 * enabled.  All interrupts are disabled briefly to assure
				 * that the following operations are atomic.
				 */

				flags = enter_critical_section();
				uart_enablerxint(dev);

#ifdef CONFIG_SERIAL_REMOVABLE
				/* Check again if the removable device is still connected
				 * while we have interrupts off.  We do not want the transition
				 * to occur as a race condition before we begin the wait.
				 */

				if (dev->disconnected) {
					ret = -ENOTCONN;
				} else
#endif
				{
					/* Now wait with the Rx interrupt re-enabled.  TinyAra will
					 * automatically re-enable global interrupts when this
					 * thread goes to sleep.
					 */

					dev->recvwaiting = true;
					ret = uart_takesem(&dev->recvsem, true);
				}

				leave_critical_section(flags);

				/* Was a signal received while waiting for data to be
				 * received?  Was a removable device disconnected while
				 * we were waiting?
				 */

#ifdef CONFIG_SERIAL_REMOVABLE
				if (ret < 0 || dev->disconnected)
#else
				if (ret < 0)
#endif
				{
					/* POSIX requires that we return after a signal is received.
					 * If some bytes were read, we need to return the number of bytes
					 * read; if no bytes were read, we need to return -1 with the
					 * errno set correctly.
					 */

					if (recvd == 0) {
						/* No bytes were read, return -EINTR (the VFS layer will
						 * set the errno value appropriately.
						 */

#ifdef CONFIG_SERIAL_REMOVABLE
						recvd = dev->disconnected ? -ENOTCONN : -EINTR;
#else
						recvd = -EINTR;
#endif
					}

					break;
				}
			} else {
				/* No... the ring buffer is no longer empty.  Just re-enable Rx
				 * interrupts and accept the new data on the next time through
				 * the loop.
				 */

				uart_enablerxint(dev);
			}
		}
	}

#ifdef CONFIG_SERIAL_IFLOWCONTROL
#ifdef CONFIG_SERIAL_IFLOWCONTROL_WATERMARKS
	/* How many bytes are now buffered */

	rxbuf = &dev->recv;
	if (rxbuf->head >= rxbuf->tail) {
		nbuffered = rxbuf->head - rxbuf->tail;
	} else {
		nbuffered = rxbuf->size - rxbuf->tail + rxbuf->head;
	}

	/* Is the level now below the watermark level that we need to report? */

	watermark = (CONFIG_SERIAL_IFLOWCONTROL_LOWER_WATERMARK * rxbuf->size) / 100;
	if (nbuffered <= watermark) {
		/* Let the lower level driver know that the watermark level has been
		 * crossed.  It will probably deactivate RX flow control.
		 */

		(void)uart_rxflowcontrol(dev, nbuffered, false);
	}
#else
	/* If the RX  buffer empty */

	if (rxbuf->head == rxbuf->tail) {
		/* Deactivate RX flow control. */

		(void)uart_rxflowcontrol(dev, 0, false);
	}
#endif
#endif

	uart_givesem(&dev->recv.sem);
	return recvd;
}

/************************************************************************************
 * Name: uart_ioctl
 ************************************************************************************/

static int uart_ioctl(FAR struct file *filep, int cmd, unsigned long arg)
{
	FAR struct inode *inode = filep->f_inode;
	FAR uart_dev_t *dev = inode->i_private;

	/* Handle TTY-level IOCTLs here */
	/* Let low-level driver handle the call first */

	int ret = dev->ops->ioctl(dev, cmd, arg);

	/* The device ioctl() handler returns -ENOTTY when it doesn't know
	 * how to handle the command. Check if we can handle it here.
	 */

	if (ret == -ENOTTY) {
		switch (cmd) {
		case FIONREAD: {
			int count;
			irqstate_t state = enter_critical_section();

			/* Determine the number of bytes available in the buffer */

			if (dev->recv.tail <= dev->recv.head) {
				count = dev->recv.head - dev->recv.tail;
			} else {
				count = dev->recv.size - (dev->recv.tail - dev->recv.head);
			}

			leave_critical_section(state);

			*(int *)arg = count;
			ret = 0;
		}
		break;

		case FIONWRITE: {
			int count;
			irqstate_t state = enter_critical_section();

			/* Determine the number of bytes free in the buffer */

			if (dev->xmit.head < dev->xmit.tail) {
				count = dev->xmit.tail - dev->xmit.head - 1;
			} else {
				count = dev->xmit.size - (dev->xmit.head - dev->xmit.tail) - 1;
			}

			leave_critical_section(state);

			*(int *)arg = count;
			ret = 0;
		}
		break;

#ifdef CONFIG_SERIAL_TERMIOS
		case TCFLSH: {
			ret = -EINVAL;
			if (arg == TCIOFLUSH || arg == TCIFLUSH) {
				ret = uart_takesem(&dev->recv.sem, true);
				if (ret < 0) {
					break;
				}
				dev->recv.tail = dev->recv.head;
#ifdef CONFIG_SERIAL_IFLOWCONTROL
				uart_rxflowcontrol(dev, 0, false);
#endif
					uart_givesem(&dev->recv.sem);
					ret = OK;
				}
				if (arg == TCIOFLUSH || arg == TCOFLUSH) {
				ret = uart_takesem(&dev->xmit.sem, true);
				if (ret < 0) {
					break;
				}
				dev->xmit.head = dev->xmit.tail;
				uart_givesem(&dev->xmit.sem);

				/* wake up waiters if any */
				uart_datasent(dev);
				ret = OK;
			}
		}
		break;
#endif							/* CONFIG_SERIAL_TERMIOS */
		}
	}
#ifdef CONFIG_SERIAL_TERMIOS
	/* Append any higher level TTY flags */

	else if (ret == OK) {
		switch (cmd) {
		case TCGETS: {
			FAR struct termios *termiosp = (struct termios *)arg;

			if (!termiosp) {
				ret = -EINVAL;
				break;
			}

			/* And update with flags from this layer */

			termiosp->c_iflag = dev->tc_iflag;
			termiosp->c_oflag = dev->tc_oflag;
			termiosp->c_lflag = dev->tc_lflag;
		}
		break;

		case TCSETS: {
			FAR struct termios *termiosp = (struct termios *)arg;

			if (!termiosp) {
				ret = -EINVAL;
				break;
			}

			/* Update the flags we keep at this layer */

			dev->tc_iflag = termiosp->c_iflag;
			dev->tc_oflag = termiosp->c_oflag;
			dev->tc_lflag = termiosp->c_lflag;
		}
		break;
		}
	}
#endif

	return ret;
}

/****************************************************************************
 * Name: uart_poll
 ****************************************************************************/

#ifndef CONFIG_DISABLE_POLL
int uart_poll(FAR struct file *filep, FAR struct pollfd *fds, bool setup)
{
	FAR struct inode *inode = filep->f_inode;
	FAR uart_dev_t *dev = inode->i_private;
	pollevent_t eventset;
	int ndx;
	int ret;
	int i;

	/* Some sanity checking */

#ifdef CONFIG_DEBUG
	if (!dev || !fds) {
		return -ENODEV;
	}
#endif

	/* Are we setting up the poll?  Or tearing it down? */

	ret = uart_takesem(&dev->pollsem, true);
	if (ret < 0) {
		/* A signal received while waiting for access to the poll data
		 * will abort the operation.
		 */

		return ret;
	}

	if (setup) {
		/* This is a request to set up the poll.  Find an available
		 * slot for the poll structure reference
		 */

		for (i = 0; i < CONFIG_SERIAL_NPOLLWAITERS; i++) {
			/* Find an available slot */

			if (!dev->fds[i]) {
				/* Bind the poll structure and this slot */

				dev->fds[i] = fds;
				fds->priv = &dev->fds[i];
				fds->filep = (void *)filep;
				break;
			}
		}

		if (i >= CONFIG_SERIAL_NPOLLWAITERS) {
			fds->priv = NULL;
			fds->filep = NULL;
			ret = -EBUSY;
			goto errout;
		}

		/* Should we immediately notify on any of the requested events?
		 * First, check if the xmit buffer is full.
		 *
		 * Get exclusive access to the xmit buffer indices.  NOTE: that we do not
		 * let this wait be interrupted by a signal (we probably should, but that
		 * would be a little awkward).
		 */

		eventset = 0;
		(void)uart_takesem(&dev->xmit.sem, false);

		ndx = dev->xmit.head + 1;
		if (ndx >= dev->xmit.size) {
			ndx = 0;
		}

		if (ndx != dev->xmit.tail) {
			eventset |= (fds->events & POLLOUT);
		}

		uart_givesem(&dev->xmit.sem);

		/* Check if the receive buffer is empty.
		 *
		 * Get exclusive access to the recv buffer indices.  NOTE: that we do not
		 * let this wait be interrupted by a signal (we probably should, but that
		 * would be a little awkward).
		 */

		(void)uart_takesem(&dev->recv.sem, false);
		if (dev->recv.head != dev->recv.tail) {
			eventset |= (fds->events & POLLIN);
		}

		uart_givesem(&dev->recv.sem);

#ifdef CONFIG_SERIAL_REMOVABLE
		/* Check if a removable device has been disconnected. */

		if (dev->disconnected) {
			eventset |= (POLLERR | POLLHUP);
		}
#endif

		if (eventset) {
			uart_pollnotify(dev, eventset);
		}

	} else if (fds->priv) {
		/* This is a request to tear down the poll. */

		struct pollfd **slot = (struct pollfd **)fds->priv;

		/* Remove all memory of the poll setup */

		*slot = NULL;
		fds->priv = NULL;
		fds->filep = NULL;
	}

errout:
	uart_givesem(&dev->pollsem);
	return ret;
}
#endif

/************************************************************************************
 * Name: uart_close
 *
 * Description:
 *   This routine is called when the serial port gets closed.
 *   It waits for the last remaining data to be sent.
 *
 ************************************************************************************/

static int uart_close(FAR struct file *filep)
{
	FAR struct inode *inode = filep->f_inode;
	FAR uart_dev_t *dev = inode->i_private;
	irqstate_t flags;
#ifndef CONFIG_DISABLE_POLL
	int i;
#endif

	/* Get exclusive access to the close semaphore (to synchronize open/close operations.
	 * NOTE: that we do not let this wait be interrupted by a signal.  Technically, we
	 * should, but almost no one every checks the return value from close() so we avoid
	 * a potential memory leak by ignoring signals in this case.
	 */

	(void)uart_takesem(&dev->closesem, false);

#ifndef CONFIG_DISABLE_POLL
	/* Check if this file is registered in a list of waiters for polling.
	 * For example, when task A is blocked by calling poll and task B try to terminate task A,
	 * a pollfd of A remains in this list. If it is, it should be cleared.
	 */
	(void)uart_takesem(&dev->pollsem, false);
	for (i = 0; i < CONFIG_SERIAL_NPOLLWAITERS; i++) {
		struct pollfd *fds = dev->fds[i];
		if (fds && (FAR struct file *)fds->filep == filep) {
			dev->fds[i] = NULL;
		}
	}
	uart_givesem(&dev->pollsem);
#endif

	if (dev->open_count > 1) {
		dev->open_count--;
		uart_givesem(&dev->closesem);
		return OK;
	}

	/* There are no more references to the port */

	dev->open_count = 0;

	/* Stop accepting input */

	uart_disablerxint(dev);

	/* Now we wait for the transmit buffer to clear */

	while (dev->xmit.head != dev->xmit.tail) {
#ifndef CONFIG_DISABLE_SIGNALS
		usleep(HALF_SECOND_USEC);
#else
		up_mdelay(HALF_SECOND_MSEC);
#endif
	}

	/* And wait for the TX fifo to drain */

	while (!uart_txempty(dev)) {
#ifndef CONFIG_DISABLE_SIGNALS
		usleep(HALF_SECOND_USEC);
#else
		up_mdelay(HALF_SECOND_MSEC);
#endif
	}

	/* Free the IRQ and disable the UART */

	flags = enter_critical_section();			/* Disable interrupts */
	uart_detach(dev);			/* Detach interrupts */
	if (!dev->isconsole) {		/* Check for the serial console UART */
		uart_shutdown(dev);		/* Disable the UART */
	}

	leave_critical_section(flags);

	/*
	 * We need to re-initialize the semaphores if this is the last close
	 * of the device, as the close might be caused by pthread_cancel() of
	 * a thread currently blocking on any of them.
	 */

	sem_reset(&dev->xmitsem, 0);
	sem_reset(&dev->recvsem, 0);
	sem_reset(&dev->xmit.sem, 1);
	sem_reset(&dev->recv.sem, 1);
#ifndef CONFIG_DISABLE_POLL
	sem_reset(&dev->pollsem, 1);
#endif

	uart_givesem(&dev->closesem);
	return OK;
}

/************************************************************************************
 * Name: uart_open
 *
 * Description:
 *   This routine is called whenever a serial port is opened.
 *
 ************************************************************************************/

static int uart_open(FAR struct file *filep)
{
	FAR struct inode *inode = filep->f_inode;
	FAR uart_dev_t *dev = inode->i_private;
	uint8_t tmp;
	int ret;

#ifdef CONFIG_PM
	/* Register PM_UART_DOMAIN to access PM APIs during UART operations. */
	if (pm_uart_domain_id == -1) {
		ret = pm_domain_register(PM_UART_DOMAIN);
		if (ret < 0) {
			return ret;
		}
		pm_uart_domain_id = ret;
	}
#endif

	/* If the port is the middle of closing, wait until the close is finished.
	 * If a signal is received while we are waiting, then return EINTR.
	 */

	ret = uart_takesem(&dev->closesem, true);
	if (ret < 0) {
		/* A signal received while waiting for the last close operation. */

		return ret;
	}
#ifdef CONFIG_SERIAL_REMOVABLE
	/* If the removable device is no longer connected, refuse to open the
	 * device.  We check this after obtaining the close semaphore because
	 * we might have been waiting when the device was disconnected.
	 */

	if (dev->disconnected) {
		ret = -ENOTCONN;
		goto errout_with_sem;
	}
#endif

	/* Start up serial port */
	/* Increment the count of references to the device. */

	tmp = dev->open_count + 1;
	if (tmp == 0) {
		/* More than 255 opens; uint8_t overflows to zero */

		ret = -EMFILE;
		goto errout_with_sem;
	}

	/* Check if this is the first time that the driver has been opened. */

	if (tmp == 1) {
		irqstate_t flags = enter_critical_section();

		/* If this is the console, then the UART has already been initialized. */

		if (!dev->isconsole) {
			/* Perform one time hardware initialization */

			ret = uart_setup(dev);
			if (ret < 0) {
				leave_critical_section(flags);
				goto errout_with_sem;
			}
		}

		/* In any event, we do have to configure for interrupt driven mode of
		 * operation.  Attach the hardware IRQ(s). Hmm.. should shutdown() the
		 * the device in the rare case that uart_attach() fails, tmp==1, and
		 * this is not the console.
		 */

		ret = uart_attach(dev);
		if (ret < 0) {
			uart_shutdown(dev);
			leave_critical_section(flags);
			goto errout_with_sem;
		}

		/* Mark the io buffers empty */

		dev->xmit.head = 0;
		dev->xmit.tail = 0;
		dev->recv.head = 0;
		dev->recv.tail = 0;

		/* Initialise termios state */

#ifdef CONFIG_SERIAL_TERMIOS
		dev->tc_iflag = 0;
		if (dev->isconsole) {
			/* Enable \n -> \r\n translation for the console */

			dev->tc_oflag = OPOST | ONLCR;
		} else {
			dev->tc_oflag = 0;
		}
#endif

		/* Enable the RX interrupt */

		uart_enablerxint(dev);
		leave_critical_section(flags);
	}

	/* Save the new open count on success */

	dev->open_count = tmp;

errout_with_sem:
	uart_givesem(&dev->closesem);
	return ret;
}

/************************************************************************************
 * Public Functions
 ************************************************************************************/

/************************************************************************************
 * Name: uart_register
 *
 * Description:
 *   Register serial console and serial ports.
 *
 ************************************************************************************/

int uart_register(FAR const char *path, FAR uart_dev_t *dev)
{
	/* Initialize semaphores */
	sem_init(&dev->xmit.sem, 0, 1);
	sem_init(&dev->recv.sem, 0, 1);
	sem_init(&dev->closesem, 0, 1);
	sem_init(&dev->xmitsem, 0, 0);
	sem_init(&dev->recvsem, 0, 0);
#ifndef CONFIG_DISABLE_POLL
	sem_init(&dev->pollsem, 0, 1);
#endif

	/*
	 * The recvsem and xmitsem are used for signaling and, hence, should
	 * not have priority inheritance enabled.
	 */
	sem_setprotocol(&dev->xmitsem, SEM_PRIO_NONE);
	sem_setprotocol(&dev->recvsem, SEM_PRIO_NONE);
	dev->sent = uart_datasent;
	dev->received = uart_datareceived;

	/* Register the serial driver */
	dbg("Registering %s\n", path);
	return register_driver(path, &g_serialops, 0666, dev);
}

/************************************************************************************
 * Name: uart_connected
 *
 * Description:
 *   Serial devices (like USB serial) can be removed.  In that case, the "upper
 *   half" serial driver must be informed that there is no longer a valid serial
 *   channel associated with the driver.
 *
 *   In this case, the driver will terminate all pending transfers wint ENOTCONN and
 *   will refuse all further transactions while the "lower half" is disconnected.
 *   The driver will continue to be registered, but will be in an unusable state.
 *
 *   Conversely, the "upper half" serial driver needs to know when the serial
 *   device is reconnected so that it can resume normal operations.
 *
 * Assumptions/Limitations:
 *   This function may be called from an interrupt handler.
 *
 ************************************************************************************/

#ifdef CONFIG_SERIAL_REMOVABLE
void uart_connected(FAR uart_dev_t *dev, bool connected)
{
	irqstate_t flags;

	/* Is the device disconnected?  Interrupts are disabled because this
	 * function may be called from interrupt handling logic.
	 */

	flags = enter_critical_section();
	dev->disconnected = !connected;
	if (!connected) {
		/* Yes.. wake up all waiting threads.  Each thread should detect the
		 * disconnection and return the ENOTCONN error.
		 */

		/* Is there a thread waiting for space in xmit.buffer?  */

		if (dev->xmitwaiting) {
			/* Yes... wake it up */

			dev->xmitwaiting = false;
			(void)sem_post(&dev->xmitsem);
		}

		/* Is there a thread waiting for read data?  */

		if (dev->recvwaiting) {
			/* Yes... wake it up */

			dev->recvwaiting = false;
			(void)sem_post(&dev->recvsem);
		}

		/* Notify all poll/select waiters that a hangup occurred */

		uart_pollnotify(dev, (POLLERR | POLLHUP));
	}

	leave_critical_section(flags);
}
#endif
