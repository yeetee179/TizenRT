/**
 * @file      rtk_bt_power_control.h
 * @author
 * @brief     Bluetooth Common function definition
 * @copyright Copyright (c) 2022. Realtek Semiconductor Corporation. All rights reserved.
 */

#ifndef __RTK_BT_POWER_CONTROL_H__
#define __RTK_BT_POWER_CONTROL_H__

#include <rtk_bt_def.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct 
{
    uint8_t pm_ble_init_status;         //1:enable, 0:disable
    uint8_t pm_ble_conn_status_0;       //0:not connected, other values: connection interval
    uint8_t pm_ble_conn_status_1;       //0:not connected, other values: connection interval
    uint8_t pm_ble_conn_status_2;       //0:not connected, other values: connection interval
    uint8_t pm_adv_interval_idx_0;      //advertising interval of adv handle 0, 
                                        //if le_adv_start is used only this will contain the adv interval value
    uint8_t pm_adv_interval_idx_1;      //advertising interval of adv handle 1
    uint8_t pm_adv_interval_idx_2;      //advertising interval of adv handle 2
} TIZENERT_BLE_PM_STATUS;

typedef void (*rtk_bt_ps_callback)(void);

/*
 * 
 * 
 * @defgroup  bt_power_control BT Power Control APIs
 * @brief     BT power control function APIs
 * @ingroup   BT_APIs
 * @{
 */

/**
* @brief     BT enable power save.
* @param     None
* @return    None
*/
void rtk_bt_enable_power_save(void);

/**
* @brief     BT disable power save.
* @param     None
* @return    None
*/
void rtk_bt_disable_power_save(void);

/**
* @brief     BT power save init.
* @param[in] p_suspend_callback: Callback invoked before system entering power save mode.
* @param[in] p_resume_callback: Callback invoked after system waking from power save mode.
* @return    None
*/
#ifndef CONFIG_PLATFORM_TIZENRT_OS
void rtk_bt_power_save_init(rtk_bt_ps_callback p_suspend_callback, rtk_bt_ps_callback p_resume_callback);
#else 
void rtk_bt_power_save_init(void);
#endif

/**
* @brief     BT power save deinit.
* @param     None
* @return    None
*/
void rtk_bt_power_save_deinit(void);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* __RTK_BT_POWER_CONTROL_H__ */
