/*
 *******************************************************************************
 * Copyright(c) 2021, Realtek Semiconductor Corporation. All rights reserved.
 *******************************************************************************
 */

#include "trace_uart.h"
#include "hci_dbg.h"
#include "hci_platform.h"
#include "osif.h"

static void *trace_mutex = NULL;
bool bt_trace_init(void)
{
	if (!CHECK_CFG_SW(CFG_SW_BT_TRACE_LOG) || !CHECK_CFG_SW(CFG_SW_BT_FW_LOG)) {
		hci_platform_bt_log_init();
	}

	if (!CHECK_CFG_SW(CFG_SW_BT_TRACE_LOG)) {
		osif_mutex_create(&trace_mutex);
		hci_platform_bt_trace_log_open();
		printf("bt_trace_init: TRACE LOG OPEN\r\n");
	}

	return true;
}


bool bt_trace_deinit(void)
{
	/* Keep loguart channel always on for coex log. */
	return true;
}

bool trace_print(void *data, uint16_t len)
{
	if (!CHECK_CFG_SW(CFG_SW_BT_TRACE_LOG)) {
#if defined(ARM_CORE_CM4) && ARM_CORE_CM4
		if (trace_mutex)
			osif_mutex_take(trace_mutex, BT_TIMEOUT_FOREVER);
#endif
		LOGUART_BT_SendData(data, len);
#if defined(ARM_CORE_CM4) && ARM_CORE_CM4
		if (trace_mutex)
			osif_mutex_give(trace_mutex);
#endif

	}

	return true;
}
