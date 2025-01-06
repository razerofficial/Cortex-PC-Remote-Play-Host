#include "UIScaleHelper.h"
#include "logging.h"

namespace ui_scale{

    static const UINT32 UiVals[] = { 100,125,150,175,200,225,250,300,350, 400, 450, 500 };


    UIScalingInfo GetUIScalingInfo(LUID adapterID, UINT32 sourceID){
        UIScalingInfo dpiInfo = {};

        DISPLAYCONFIG_SOURCE_UI_SCALE_GET requestPacket = {};
        requestPacket.header.type = (DISPLAYCONFIG_DEVICE_INFO_TYPE)(ui_scale::DISPLAYCONFIG_DEVICE_INFO_TYPE_CUSTOM::DISPLAYCONFIG_DEVICE_INFO_GET_DPI_SCALE);
        requestPacket.header.size = sizeof(requestPacket);
        if(sizeof(requestPacket) != 0x20){
            BOOST_LOG(error) << "faild to get UI scale, OS not support this API anymore";
            return dpiInfo;
        }
        requestPacket.header.adapterId = adapterID;
        requestPacket.header.id = sourceID;

        auto res = ::DisplayConfigGetDeviceInfo(&requestPacket.header);
        if (ERROR_SUCCESS == res)
        {//success
            if (requestPacket.curScaleRel < requestPacket.minScaleRel)
            {
                requestPacket.curScaleRel = requestPacket.minScaleRel;
            }
            else if (requestPacket.curScaleRel > requestPacket.maxScaleRel)
            {
                requestPacket.curScaleRel = requestPacket.maxScaleRel;
            }

            std::int32_t minAbs = abs((int)requestPacket.minScaleRel);
            if (ui_scale::CountOf(UiVals) >= (size_t)(minAbs + requestPacket.maxScaleRel + 1))
            {
                dpiInfo.current = UiVals[minAbs + requestPacket.curScaleRel];
                dpiInfo.recommended = UiVals[minAbs];
                dpiInfo.maximum = UiVals[minAbs + requestPacket.maxScaleRel];
                dpiInfo.bInitDone = true;
            }
            else
            {
                //Error! Probably DpiVals array is outdated
                return dpiInfo;
            }
        }
        else
        {
            //DisplayConfigGetDeviceInfo() failed
            return dpiInfo;
        }

        return dpiInfo;
    }
    
    bool SetUIScaling(LUID adapterID, UINT32 sourceID, UINT32 dpiPercentToSet)
    {
        UIScalingInfo dPIScalingInfo = GetUIScalingInfo(adapterID, sourceID);
        BOOST_LOG(info) << "Get display info: " << dPIScalingInfo.mininum <<"-" << dPIScalingInfo.maximum << " ,current" << dPIScalingInfo.current << " recommend" << dPIScalingInfo.recommended;
        if (dpiPercentToSet == dPIScalingInfo.current)
        {
            return true;
        }

        if (dpiPercentToSet < dPIScalingInfo.mininum)
        {
            dpiPercentToSet = dPIScalingInfo.mininum;
        }
        else if (dpiPercentToSet > dPIScalingInfo.maximum)
        {
            dpiPercentToSet = dPIScalingInfo.maximum;
        }

        int idx1 = -1, idx2 = -1;

        int i = 0;
        for (const auto& val : UiVals)
        {
            if (val == dpiPercentToSet)
            {
                idx1 = i;
            }

            if (val == dPIScalingInfo.recommended)
            {
                idx2 = i;
            }
            i++;
        }

        if ((idx1 == -1) || (idx2 == -1))
        {
            //Error cannot find dpi value
            BOOST_LOG(error) << "Scalue value index error";
            return false;
        }

        int dpiRelativeVal = idx1 - idx2;

        DISPLAYCONFIG_SOURCE_UI_SCALE_SET setPacket = {};
        setPacket.header.adapterId = adapterID;
        setPacket.header.id = sourceID;
        setPacket.header.size = sizeof(setPacket);
        if(sizeof(setPacket) != 0x18){
            BOOST_LOG(error) << "faild to set UI scale, OS not support this API anymore";
            return false;
        }
        setPacket.header.type = (DISPLAYCONFIG_DEVICE_INFO_TYPE)ui_scale::DISPLAYCONFIG_DEVICE_INFO_TYPE_CUSTOM::DISPLAYCONFIG_DEVICE_INFO_SET_DPI_SCALE;
        setPacket.scaleRel = (UINT32)dpiRelativeVal;

        auto res = ::DisplayConfigSetDeviceInfo(&setPacket.header);
        if (ERROR_SUCCESS == res)
        {
            BOOST_LOG(info) << "Set scale value success";
            return true;
        }
        else
        {
            BOOST_LOG(error) << "Set scale value failed " << GetLastError();
            return false;
        }
        return true;
    }

    bool GetPathsAndModes(std::vector<DISPLAYCONFIG_PATH_INFO>& pathsV, std::vector<DISPLAYCONFIG_MODE_INFO>& modesV, int flags)
    {
        UINT32 numPaths = 0, numModes = 0;
        auto status = GetDisplayConfigBufferSizes(flags, &numPaths, &numModes);
        if (ERROR_SUCCESS != status)
        {
            return false;
        }

        std::unique_ptr<DISPLAYCONFIG_PATH_INFO[]> paths(new DISPLAYCONFIG_PATH_INFO[numPaths]);
        std::unique_ptr<DISPLAYCONFIG_MODE_INFO[]> modes(new DISPLAYCONFIG_MODE_INFO[numModes]);
        status = QueryDisplayConfig(flags, &numPaths, paths.get(), &numModes, modes.get(), nullptr);
        if (ERROR_SUCCESS != status)
        {
            return false;
        }

        for (unsigned int i = 0; i < numPaths; i++)
        {
            pathsV.push_back(paths[i]);
        }

        for (unsigned int i = 0; i < numModes; i++)
        {
            modesV.push_back(modes[i]);
        }

        return true;
    }

    bool GetRemotePlayMonitorInfo(LUID &adapterId, UINT32 &sourceId) {
        std::vector<DISPLAYCONFIG_PATH_INFO> pathsV;
        std::vector<DISPLAYCONFIG_MODE_INFO> modesV;
        int flags = QDC_ONLY_ACTIVE_PATHS;
        if (false == GetPathsAndModes(pathsV, modesV, flags))
        {
            BOOST_LOG(error) << "GetPathsAndModes() failed";
            return false;
        }

        for (const auto& path : pathsV)
        {
            //get display name
            auto adapterLUID = path.targetInfo.adapterId;
            auto targetID = path.targetInfo.id;
            auto sourceID = path.sourceInfo.id;

            DISPLAYCONFIG_TARGET_DEVICE_NAME deviceName;
            deviceName.header.size = sizeof(deviceName);
            deviceName.header.type = DISPLAYCONFIG_DEVICE_INFO_GET_TARGET_NAME;
            deviceName.header.adapterId = adapterLUID;
            deviceName.header.id = targetID;
            if (ERROR_SUCCESS != DisplayConfigGetDeviceInfo(&deviceName.header))
            {
                BOOST_LOG(error) << "DisplayConfigGetDeviceInfo() failed";
                return false;
            }
            else
            {
                if(std::wstring(deviceName.monitorFriendlyDeviceName) == L"Remote Play"){
                    adapterId = adapterLUID;
                    sourceId = sourceID;
                    return true;
                }
            }
        }

        BOOST_LOG(info) << "No display named 'Remote Play' found." << std::endl;
        return false;
    }

    int SetVirtualDisplayUIScaling(int uiScalueValue){
        LUID adapterID = {};
        UINT32 sourceID = 0;
        //std::string targetDisplayName = "Razer Virtual Desktop"; // 指定目标显示器描述

        if (GetRemotePlayMonitorInfo(adapterID, sourceID)) {
            //BOOST_LOG(info) << "Adapter ID: HighPart=" << adapterID.HighPart << ", LowPart=" << adapterID.LowPart << std::endl;
            //BOOST_LOG(info) << "Source ID: " << sourceID << std::endl;

            SetUIScaling(adapterID, sourceID, uiScalueValue);

            return 0;
        }
        else{
            BOOST_LOG(error) << "Not found the virtual display";
            return 1;
        }
    }
};