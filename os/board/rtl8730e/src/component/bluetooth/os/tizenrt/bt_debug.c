#include <stdio.h>
#include <string.h>
#include <basic_types.h>
#include <bt_debug.h>


#if BT_LOG_USE_MUTEX
void *bt_log_mtx = NULL;
#endif

void rtk_bt_log_init(void)
{
#if BT_LOG_USE_MUTEX
	if (bt_log_mtx == NULL) {
		osif_mutex_create(&bt_log_mtx);
	}
#endif
}

void rtk_bt_log_deinit(void)
{
#if BT_LOG_USE_MUTEX
	if (bt_log_mtx) {
		osif_mutex_delete(bt_log_mtx);
		bt_log_mtx = NULL;
	}
#endif
}

void rtk_bt_log_dump(uint8_t unit, const char *str, void *buf, uint16_t len)
{
	int i = 0;
	int num = 16 / unit;

	BT_LOG_MUTEX_TAKE
	RTK_LOGS(NOTAG, "%s\r\n", str);
	for (i = 0; i < len; i++) {
		if (unit == 4) {
			RTK_LOGS(NOTAG, "%08x ", *((uint32_t *)buf + i));
		} else if (unit == 2) {
			RTK_LOGS(NOTAG, "%04x ", *((uint16_t *)buf + i));
		} else {
			RTK_LOGS(NOTAG, "%02x ", *((uint8_t *)buf + i));
		}
		if ((i + 1) % num == 0 || (i + 1) == len) {
			RTK_LOGS(NOTAG, "\r\n");
		}
	}
	BT_LOG_MUTEX_GIVE
}