/**
 * @file src/UIScaleHelper.h
 * @brief for Windows UI scale
 */
#pragma once
#include <Windows.h>
#include <vector>
#include <iostream>
#include <cstdint>

namespace ui_scale{

    enum class DISPLAYCONFIG_DEVICE_INFO_TYPE_CUSTOM : int
    {
        DISPLAYCONFIG_DEVICE_INFO_GET_DPI_SCALE = -3, 
        DISPLAYCONFIG_DEVICE_INFO_SET_DPI_SCALE = -4,
        DISPLAYCONFIG_DEVICE_INFO_GET_MONITOR_BRIGHTNESS_INFO = -7,
        DISPLAYCONFIG_DEVICE_INFO_GET_MONITOR_INTERNAL_INFO = DISPLAYCONFIG_DEVICE_INFO_GET_MONITOR_BRIGHTNESS_INFO,
        DISPLAYCONFIG_DEVICE_INFO_GET_MONITOR_UNIQUE_NAME = DISPLAYCONFIG_DEVICE_INFO_GET_MONITOR_BRIGHTNESS_INFO,
    };

    struct UIScalingInfo
    {
        UINT32 mininum = 100;
        UINT32 maximum = 100;
        UINT32 current = 100;
        UINT32 recommended = 100;
        bool bInitDone = false;
    };

    struct DISPLAYCONFIG_SOURCE_UI_SCALE_GET
    {
        DISPLAYCONFIG_DEVICE_INFO_HEADER header;
        std::int32_t minScaleRel;
        std::int32_t curScaleRel;  
        std::int32_t maxScaleRel;
    };

    struct DISPLAYCONFIG_SOURCE_UI_SCALE_SET
    {
        DISPLAYCONFIG_DEVICE_INFO_HEADER header;

        int32_t scaleRel;
    };


    template<class T, size_t sz>
    static size_t CountOf(const T (&arr)[sz])
    {
        //UNREFERENCED_PARAMETER(arr);
        return sz;
    }

    UIScalingInfo GetUIScalingInfo(LUID adapterID, UINT32 sourceID);
    bool SetUIScaling(LUID adapterID, UINT32 sourceID, UINT32 dpiPercentToSet);

    int SetVirtualDisplayUIScaling(int uiScalueValue);
};
