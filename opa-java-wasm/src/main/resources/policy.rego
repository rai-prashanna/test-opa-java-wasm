package authz.policy

default allow = false

allow {
	__local9__1 = input.resource
	regex.match("AService", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readAService" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("AService/ASources", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readAService" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("AService/ASources", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"createASource" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("AService/ASources/[^/]", __local9__1)
	"GET" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"readAService" = __local4__1
}

allow {
	__local9__1 = input.resource
	regex.match("files/Prai", __local9__1)
	"POST" = input.method
	__local1__1 = input.roles[__local0__1]
	data.authz.policy.findpermissionByRole(__local1__1, __local7__1)
	__local4__1 = __local7__1[__local3__1]
	"uploadPrai" = __local4__1
}

findpermissionByRole(__local5__2) = ["PraiSystem.Override", "PraiSystem.Reset", "createASource", "createMyPOD", "deleteASource", "downloadLogs", "patchASource", "readAService", "readPrashannaAlarm", "readPraiAlarm", "readPraiTram", "readMYCertificate", "readDevices", "readLogService", "readPRAIManagers", "readPraiNetworkProtocol", "readMyNetworks", "readKey", "readBags", "readPraiAssets", "readPraiBackupService", "readPraiPraiRemoteUpdateService", "readConfiguration", "readPraiDelays", "readPRAIPods", "readCycles", "readMySwitches", "readPraiService", "readPraiLink", "readMyUpdateService", "readMyPODs", "PraiBackupService.CreateAndTransferBackup", "PraiRemoteUpdateService.AbortAssetUpgradeJob", "PraiRemoteUpdateService.CreateAssetUpgradeJob", "PraiRemoteUpdateService.RemoveAssetUpgradeJob", "PraiRemoteUpdateService.RemoveSoftwarePrai", "PraiRemoteUpdateService.RemoveSoftwareVersion", "PraiRemoteUpdateService.StartAssetUpgradeJob", "PraiRemoteUpdateService.UpdateManager", "PraiRemoteUpdateService.UpdateManagerCancel", "PraiRemoteUpdateService.UploadSoftwarePrai", "removeNetwork", "removePrai", "removeMyPOD", "retrieveLogs", "PRAIPod.ModifyPmJob", "PRAIPod.readPrashannaAlarm", "setLogServer", "updatePraiSystem", "updateNetwork", "updatepraiCredentials", "updateMyPOD", "uploadPrai", "MyPOD.Allocate", "MyPOD.CreateL2Network", "MyPOD.CreateL2NetworkWithAutomaticConnectivityForAllPorts", "MyPOD.CreateL2NetworkWithAutomaticConnectivityForSelectedPorts", "MyPOD.ConnectManualSelectedPorts", "MyPOD.Deallocate", "MyPOD.DisconnectManualSelectedPorts"] {
	"Administrator" = __local5__2
}

findpermissionByRole(__local5__2) = ["createASource", "patchASource", "readAService", "readKey", "readPraiService"] {
	"CreateRole" = __local5__2
}

findpermissionByRole(__local5__2) = ["createCertificate", "createKey", "deleteKey", "readAService", "readPrashannaAlarm", "readPraiAlarm", "readpraiInternalAlarm", "readMYCertificate", "readPRAIManagers", "readKey", "readPraiAssets", "readPraiService", "PraiAsset.RemoveCredential", "PraiAsset.SetCredential", "deleteData", "PRAIPod.readPrashannaAlarm"] {
	"SecurityAdministrator" = __local5__2
}

findpermissionByRole(__local5__2) = ["deleteASource", "readAService", "readKey", "readPraiService"] {
	"DeleteRole" = __local5__2
}

findpermissionByRole(__local5__2) = ["readAService", "readPrashannaAlarm", "readPraiAlarm", "readPraiTram", "readMYCertificate", "readDevices", "readLogService", "readPRAIManagers", "readPraiNetworkProtocol", "readMyNetworks", "readConfiguration", "readKey", "readBags", "readPraiAssets", "readPraiDelays", "readPraiBackupService", "readPraiPraiRemoteUpdateService", "readPRAIPods", "readCycles", "readSystems", "readPraiLink", "readMyUpdateService", "readMyPODs", "PRAIPod.readPrashannaAlarm"] {
	"Observer" = __local5__2
}

findpermissionByRole(__local5__2) = ["readAService", "readPrashannaAlarm", "readpraiInternalAlarm", "readMYCertificate", "readPRAIManagers", "readKey", "readPraiBackupService"] {
	"SchoolObserver" = __local5__2
}

findpermissionByRole(__local5__2) = ["readAService", "readPrashannaAlarm", "readpraiInternalAlarm", "readMYCertificate", "readPRAIManagers", "readKey", "readPraiBackupService", "readPraiService", "removeTask", "PraiBackupService.CreateAndTransferBackup"] {
	"SchoolAdministrator" = __local5__2
}
