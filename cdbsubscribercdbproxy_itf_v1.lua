-- 这个脚本用来解析eNB version 14.3的60100端口的消息，CDB proxy <==> CDB subscriber

-- How to use it
-- 1. make sure your wireshark support Lua, open your wireshark, click "help"-->"about wireshark",
--    if you see "with Lua5.2" or something like that, that means wireshark support Lua, now you 
--    can use this Lua script
-- 2. find your wireshark installation location, you can find init.lua there, put this script along 
--    with init.lua
-- 3. edit init.lua, to make sure Lua feature is activated and your script is loaded in this file:
--    a). activate Lua feature in init.lua, in the beginning of the file:
--        disable_lua = false
--        if disable_lua then
--          return
--        end 
--    b). load the script, add below line at the end of the file
--        dofile(DATA_DIR.."cdbsubscribercdbproxy_itf_v1.lua")
-- 4. now, you can open a pcap file to browse your CDB interface data after decoded.

do
    --创建一个Proto类的对象，表示本插件解析的是CDB proxy和CDB subscriber之间的接口消息
    local p_cdbsubscriberitf = Proto("cdbsubscriberitf","CDBsubscriberCDBproxyItf");

	--从接口文件enodeb.h中得到，目录位于/enodeb_itf/enodeb/里面，还有一部分接口文件定义在/enodeb_itf/oam/中
	local vs_familys = {
		[128] = "ID_FAM_APP_MIN",
		[128] = "ID_FAM_CALLP",
		[129] = "ID_FAM_CALLP_UBM",
		[130] = "ID_FAM_SCTP_ACCESS",
		[131] = "ID_FAM_CALLP_BRC",
		[132] = "ID_FAM_BRC_DLS",
		[132] = "ID_FAM_BRC_DLT",
		[132] = "ID_FAM_BRC_UPA",
		[133] = "ID_FAM_BRC_CE",
		[133] = "ID_FAM_BRC_DSP",
		[134] = "ID_FAM_OAM",
		[135] = "ID_FAM_GCPP",
		[136] = "ID_FAM_ADMIN",
		[137] = "ID_FAM_DLT_CE",
		[137] = "ID_FAM_UPA_DSP",
		[138] = "ID_FAM_CALLP_TEST",
		[139] = "ID_FAM_SLOAM_INTERNAL",
		[140] = "ID_FAM_SLOAM_CE",
		[141] = "ID_FAM_SLOAM_DLS",
		[141] = "ID_FAM_SLOAM_DLT",
		[141] = "ID_FAM_SLOAM_UPA",
		[141] = "ID_FAM_HRAL_DLT",
		[141] = "ID_FAM_HRAL_DLS",
		[142] = "ID_FAM_SLOAM_LED",
		[143] = "ID_FAM_SLOAM_TIMER",
		[144] = "ID_FAM_SLOAM_DWL",
		[145] = "ID_FAM_SLOAM_HSSL",
		[146] = "ID_FAM_SLOAM_PQ3HANDLER",
		[147] = "ID_FAM_SLOAM_BRC",
		[147] = "ID_FAM_HRAL_BRC",
		[148] = "ID_FAM_CI_MGR_USER",
		[149] = "ID_FAM_UBM_WAL",
		[150] = "ID_FAM_CALLP_UPA",
		[150] = "ID_FAM_CALLP_DLS",
		[150] = "ID_FAM_CALLP_DLT",
		[150] = "ID_FAM_CALLP_ULU",
		[151] = "ID_FAM_ULT_CE",
		[152] = "ID_FAM_BCI_CE_DBG",
		[153] = "ID_FAM_ULU_CE",
		[154] = "ID_FAM_BRC_ULS",
		[154] = "ID_FAM_BRC_ULT",
		[155] = "ID_FAM_SLOAM_ULT",
		[156] = "ID_FAM_HRAL_ULT",
		[157] = "ID_FAM_ULT_DLT",
		[158] = "ID_FAM_CEPROXY_SLOAM",
		[159] = "ID_FAM_CEPROXY_BRC",
		[160] = "ID_FAM_CEPROXY_DEBUG",
		[161] = "ID_FAM_CEPROXY_MPCRO",
		[162] = "ID_FAM_CEPROXY_HRAL",
		[163] = "ID_FAM_PROG_MON",
		[164] = "ID_FAM_PRB_ULT",
		[165] = "ID_FAM_PRB_DLT",
		[166] = "ID_FAM_HRAL_MPC_L1DBG",
		[167] = "ID_FAM_UBM_PDCP",
		[168] = "ID_FAM_SIM",         
		[169] = "ID_FAM_SONA", 
		[170] = "ID_FAM_CALLP_CRM",
		[171] = "ID_FAM_CALLP_MCE",
		[192] = "ID_FAM_HOST_L1_ITF_METRO",
		[193] = "ID_FAM_PMCA",       
		[255] = "ID_FAM_APP_MAX"
	}
	
	-- 从接口文件enodeb.h中得到，目录位于/enodeb_itf/enodeb/里面，还有一部分接口文件定义在/enodeb_itf/oam/中
	local vs_classes = {
		[128] = "ID_CLA_APP_MIN",
		[128] = "ID_CLA_ADMIN",
		[129] = "ID_CLA_CELL",
		[130] = "ID_CLA_CELLRRC",
		[131] = "ID_CLA_UECALL",
		[132] = "ID_CLA_CPM",
		[133] = "ID_CLA_BRC_CC",
		[134] = "ID_CLA_BRC_UC",
		[135] = "ID_CLA_GCPP",
		[136] = "ID_CLA_CALLPTEST",
		[137] = "ID_CLA_BRC_STUB",
		[138] = "ID_CLA_CORE_OAM_STUB",
		[139] = "ID_CLA_RRC_STUB",
		[140] = "ID_CLA_UBM_STUB",
		[141] = "ID_CLA_UPA_STUB",
		[142] = "ID_CLA_CE_STUB",
		[143] = "ID_CLA_S1AP_STUB",
		[144] = "ID_CLA_X2AP_STUB",
		[145] = "ID_CLA_SCTP_ACCESS_STUB",
		[146] = "ID_CLA_SCENARIO_STUB",
		[147] = "ID_CLA_SLOAM",
		[147] = "ID_CLA_HRAL",
		[148] = "ID_CLA_UBM",
		[149] = "ID_CLA_PMLA",
		[150] = "ID_CLA_PMCA",
		[151] = "ID_CLA_PMCA_STUB",
		[152] = "ID_CLA_DLT",
		[153] = "ID_CLA_ULT",
		[154] = "ID_CLA_DSP",
		[155] = "ID_CLA_CTLA",
		[156] = "ID_CLA_CTCA",
		[157] = "ID_CLA_CTCA_STUB",
		[158] = "ID_CLA_WAL",
		[159] = "ID_CLA_DLS_STUB",
		[160] = "ID_CLA_ULS_STUB",
		[161] = "ID_CLA_DSP_STUB",
		[162] = "ID_CLA_WAL_STUB",
		[163] = "ID_CLA_CRM",
		[164] = "ID_CLA_L1DBG",
		[165] = "ID_CLA_PMS",
		[166] = "ID_CLA_PDCP",
		[167] = "ID_CLA_PDCP_STUB",
		[168] = "ID_CLA_GTP_STUB",
		[169] = "ID_CLA_M3AP_STUB",
		[170] = "ID_CLA_MCE",
		[171] = "ID_CLA_CALLP_SCTP",
		[255] = "ID_CLA_APP_MAX",
		[0xFFFF] = "ID_CLA_SYS_NS"
	}
	
	-- 从RRT_DMD_Itf.h的枚举类型Rrt_Dmd_msgTypes中得到
	local vs_opcode = {
		[100] = "MT_OAMC_getAttributeReq",
		[101] = "MT_OAMC_getAttributeRes",
		[102] = "MT_OAMC_getDynAttributeReq",
    	[103] = "MT_OAMC_getDynAttributeRes",
		[104] = "MT_OAMC_setAttributeReq",
		[105] = "MT_OAMC_setAttributeRes",
		[106] = "MT_OAMC_consistencyCheckReq",
		[107] = "MT_OAMC_consistencyCheckRes",		
		[108] = "MT_OAMC_objectChangeReq",
		[109] = "MT_OAMC_objectChangeRes",
        [110] = "MT_OAMC_resetInd",		
		[111] = "MT_OAMC_createObjInd",
		[112] = "MT_OAMC_modifyObjInd",
		[113] = "MT_OAMC_deleteObjInd",
        [114] = "MT_OAMC_anrResetStartInd",
        [115] = "MT_OAMC_ncagentInitReq",
        [116] = "MT_OAMC_ncagentInitRes",
        [117] = "MT_OAMC_ncagentBackupReq",
        [118] = "MT_OAMC_ncagentBackupRes",
        [119] = "MT_OAMC_ncagentRestoreReq",
        [120] = "MT_OAMC_ncagentRestoreRes",
        [121] = "MT_OAMC_X2AccessOverflowInd",
        [122] = "MT_OAMC_disableObjReq",
        [123] = "MT_OAMC_disableObjRes",
        [124] = "MT_OAMC_setShadowAttributeReq",
        [125] = "MT_OAMC_setShadowAttributeRes",
        [126] = "MT_OAMC_getOriginalAttributeReq",
        [127] = "MT_OAMC_getOriginalAttributeRes",
        [128] = "MT_OAMC_originalAttributeChangeReq",
        [129] = "MT_OAMC_originalAttributeChangeRes",
        [130] = "MT_OAMC_OverflowInd",
        [131] = "MT_OAMC_objectChangeNotify",
        [132] = "MT_OAMC_oamCtrlReadyInd",
        [133] = "MT_OAMC_configCommit",
        [134] = "MT_OAMC_alarmNotifInfo",
		[135] = "MT_OAMC_cdbSubscribe",
		[136] = "MT_OAMC_attrChgInd",
		[137] = "MT_OAMC_faultInd",
		[138] = "MT_OAMC_eventInd",
		[139] = "MT_OAMC_triggerActionInd",
        [140] = "MT_OAMC_openSnmpInd",
    	[141] = "MT_OAMC_triggerActionReq",
    	[142] = "MT_OAMC_triggerActionRes",
    	[143] = "MT_OAMC_getFDNrequest",
    	[144] = "MT_OAMC_getFDNresult",
    	[145] = "MT_OAMC_cdbLockReq",
    	[146] = "MT_OAMC_cdbLockRes",
    	[147] = "MT_OAMC_cdbUnlockReq",
    	[148] = "MT_OAMC_cdbUnlockRes",
    	[149] = "MT_OAMC_reconfigurationInd",
    	[150] = "MT_OAMC_oldObjectChangeReq"		
	}

	-- 从RRT_DMD_Itf.h的枚举类型Rrt_Dmd_AnrResetType中得到	
	local vs_anrresettypes = {
		[0] = "ANR_RESET_TYPE_NONE",
		[1] = "ANR_RESET_TYPE_LTE_INTRA_FREQUENCY",
		[2] = "ANR_RESET_TYPE_LTE_INTER_FREQUENCY",
		[3] = "ANR_RESET_TYPE_INTER_RAT_UTRA",
		[4] = "ANR_RESET_TYPE_INTER_RAT_CDMA",
		[5] = "ANR_RESET_TYPE_INTER_RAT_GERAN"
	}
	
	-- 从RRT_DMD_Itf.h的枚举类型Rrt_Dmd_resetReason中得到
	local vs_resetReason = {
		[0] = "RECONFIG_REQ",
		[1] = "COMMUNICATION_FAILURE",
		[2] = "CDB_LOCKED_TIMEOUT"
	}
	
	-- 从RRT_DMD_Itf.h的枚举类型Rrt_Dmd_X2AccessOverflowType中得到	
	local vs_typeOfIndication = {
		[0] = "X2ACCESS_OVERFLOW_TYPE_UNSET",
		[1] = "X2ACCESS_OVERFLOW_TYPE_VISIBLE",
		[2] = "X2ACCESS_OVERFLOW_TYPE_INVISIBLE"
	}

	-- 从RRT_DMD_Itf.h的枚举类型Rrt_Dmd_OverflowType中得到
	local vs_overflowType = {
		[0] = "OVERFLOW_TYPE_NONE",
		[1] = "OVERFLOW_TYPE_UTRAFDD_ANR",
		[2] = "OVERFLOW_TYPE_RNC_ACCESS",
		[3] = "OVERFLOW_TYPE_LTE_NEIGBORING_CELL_RELATION",
		[4] = "OVERFLOW_TYPE_NCQUEUE_OVERFLOW_MSG_DISCARDED_ON",
		[5] = "OVERFLOW_TYPE_NCQUEUE_OVERFLOW_MSG_DISCARDED_OFF"
	}
	
	-- 从RRT_DMD_Itf.h的枚举类型Rrt_Dmd_TriggerActionType得到
	local vs_triggeractiontype = {
		[0] = "TRIGGER_ACTION_TYPE_MRO"
	}

	--预定义的变量，来自RRT_DMD_Itf.h的定义
	local MAX_NUM_OF_INSTANCES = 2048
	local MAX_ERROR_DETAILS_LEN = 101
	local MAX_ADDITIONAL_TEXT_LEN = 101
	local OAMC_ACTIONERRORMESSAGE_LENGTH = 255
	local OAM_MAX_OID_LEN = 300
	local MAX_ADDINFO_SIZE = 1024

	--来自oam_ro_attribute.h，位于/enodeb_itf/oam
	local OAM_L_ATTRIBUTE_NAME_MAX = 199
	local OAM_L_CLASSREF_MAX = 304
	
    --创建ProtoField对象，就是主界面中部Packet Details窗格中能显示的那些属性
    local f_family = ProtoField.uint16("cdbsubscriberitf.family","family",base.DEC,vs_familys)
    local f_opcode = ProtoField.uint16("cdbsubscriberitf.opcode","opcode",base.DEC,vs_opcode)
	local f_length = ProtoField.uint32("cdbsubscriberitf.length","len",base.DEC)
	local f_transactionid = ProtoField.uint32("cdbsubscriberitf.transactionid","transactionid",base.DEC)
	local f_destclass = ProtoField.uint16("cdbsubscriberitf.destclass","destclass",base.DEC,vs_classes)
	local f_srcclass = ProtoField.uint16("cdbsubscriberitf.srcclass","srcclass",base.DEC,vs_classes)
	local f_destinst = ProtoField.uint32("cdbsubscriberitf.destinst","destinst",base.HEX)
	local f_srcinst = ProtoField.uint32("cdbsubscriberitf.srcinst","srcinst",base.HEX)
	local f_tracekey = ProtoField.uint32("cdbsubscriberitf.tracekey","tracekey",base.HEX)
	local f_oamclassref = ProtoField.uint16("cdbsubscriberitf.oamclassref","oamclassref",base.DEC)
	local f_oaminstanceindex = ProtoField.uint16("cdbsubscriberitf.oaminstanceindex","oaminstanceindex",base.DEC)
	local f_oamstatus = ProtoField.uint16("cdbsubscriberitf.oamstatus","oamstatus",base.DEC,{[0]="ACK"})
	local f_nbrofinstances = ProtoField.uint16("cdbsubscriberitf.nbrofinstances","nbrofinstances",base.DEC)
	local f_indexarray = ProtoField.string("cdbsubscriberitf.indexarray","indexarray",base.HEX)
	local f_payloadlen = ProtoField.uint32("cdbsubscriberitf.payloadlen","payloadlen",base.DEC)
	local f_payload = ProtoField.string("cdbsubscriberitf.payload","payload",base.NONE)
	local f_nbrofchgattr = ProtoField.uint16("cdbsubscriberitf.nbrofchgattr","nbrofchgattr",base.DEC)
	local f_chgattributes = ProtoField.string("cdbsubscriberitf.chgattributes","chgattributes",base.NONE)
	local f_nbAttributesElements = ProtoField.uint16("cdbsubscriberitf.nbAttributesElements","nbAttributesElements",base.DEC)
	local f_changeref = ProtoField.string("cdbsubscriberitf.changeref","changeref",base.NONE)
	local f_successflag = ProtoField.uint16("cdbsubscriberitf.successflag","successflag",base.DEC,{[0]="ACK",[1]="NACK"})
	local f_errordetail = ProtoField.string("cdbsubscriberitf.errordetail","errordetail",base.NONE)
	local f_bulkadditionaltext = ProtoField.string("cdbsubscriberitf.bulkadditionaltext","bulkadditionaltext",base.NONE)
	local f_nbravcninfores = ProtoField.uint16("cdbsubscriberitf.nbravcninfores","nbravcninfores",base.DEC)
	local f_x2lcc_lcc = ProtoField.uint32("cdbsubscriberitf.x2lcc_lcc","x2lcc_lcc",base.DEC)
	local f_x2lcc_lccvalue = ProtoField.uint32("cdbsubscriberitf.x2lcc_lccvalue","x2lcc_lccvalue",base.DEC)
	local f_x2lcc_addtionaltext = ProtoField.string("cdbsubscriberitf.x2lcc_addtionaltext","x2lcc_addtionaltext",base.NONE)
	local f_cmlcc_lcc = ProtoField.uint32("cdbsubscriberitf.cmlcc_lcc","cmlcc_lcc",base.DEC)
	local f_cmlcc_lccvalue = ProtoField.uint32("cdbsubscriberitf.cmlcc_lccvalue","cmlcc_lccvalue",base.DEC)
	local f_cmlcc_addtionaltext = ProtoField.string("cdbsubscriberitf.cmlcc_addtionaltext","cmlcc_addtionaltext",base.NONE)
	local f_avcninfores_lcc = ProtoField.uint32("cdbsubscriberitf.avcninfores_lcc","avcninfores_lcc",base.DEC)
	local f_avcninfores_lccvalue = ProtoField.uint32("cdbsubscriberitf.avcninfores_lccvalue","avcninfores_lccvalue",base.DEC)
	local f_avcninfores_addtionaltext = ProtoField.string("cdbsubscriberitf.avcninfores_addtionaltext","avcninfores_addtionaltext",base.NONE)
	local f_anrresettype = ProtoField.uint32("cdbsubscriberitf.anrresettype","anrresettype",base.DEC,vs_anrresettypes)
	local f_forceincx2accesslcc = ProtoField.uint8("cdbsubscriberitf.forceincx2accesslcc","forceincx2accesslcc",base.DEC)
	local f_nbrofchangedobj = ProtoField.uint16("cdbsubscriberitf.nbrofchangedobj","nbrofchangedobj",base.DEC)
	local f_parentoamclassref = ProtoField.uint16("cdbsubscriberitf.parentoamclassref","parentoamclassref",base.DEC)
	local f_parentoaminstanceid = ProtoField.uint16("cdbsubscriberitf.parentoaminstanceid","parentoaminstanceid",base.DEC)
	local f_changetype = ProtoField.uint16("cdbsubscriberitf.changetype","changetype",base.DEC)
	local f_changeweight = ProtoField.uint16("cdbsubscriberitf.changeweight","changeweight",base.DEC)
	local f_exchangeweight = ProtoField.uint16("cdbsubscriberitf.exchangeweight","exchangeweight",base.DEC)
	local f_forceincmolcc = ProtoField.uint8("cdbsubscriberitf.forceincmolcc","forceincmolcc",base.DEC)
	local f_nbrofchangerefs = ProtoField.uint16("cdbsubscriberitf.nbrofchangerefs","nbrofchangerefs",base.DEC)
	local f_changerefs = ProtoField.string("cdbsubscriberitf.changerefs","changerefs",base.NONE)
	local f_actiontype = ProtoField.uint32("cdbsubscriberitf.actiontype","actiontype",base.DEC)
	local f_actionerrormessagelen = ProtoField.uint32("cdbsubscriberitf.actionerrormessagelen","actionerrormessagelen",base.DEC)
	local f_actionerrormessage = ProtoField.string("cdbsubscriberitf.actionerrormessage","actionerrormessage",base.NONE)
	local f_fdnlength = ProtoField.uint16("cdbsubscriberitf.fdnlength","fdnlength",base.DEC)
	local f_reference = ProtoField.uint32("cdbsubscriberitf.reference","reference",base.DEC)
	local f_status = ProtoField.uint16("cdbsubscriberitf.status","status",base.DEC)
	local f_cdbstatus = ProtoField.uint16("cdbsubscriberitf.cdbstatus","cdbstatus",base.DEC,{[0]="UNLOCK",[1]="LOCK"})
	local f_triggeractiontype = ProtoField.uint32("cdbsubscriberitf.triggeractiontype","triggeractiontype",base.DEC,vs_triggeractiontype)
	local f_objecttype = ProtoField.uint32("cdbsubscriberitf.objecttype","objecttype",base.DEC)
	local f_objectinstance = ProtoField.uint32("cdbsubscriberitf.objectinstance","objectinstance",base.DEC)
	local f_faultnumber = ProtoField.uint16("cdbsubscriberitf.faultnumber","faultnumber",base.DEC)
	local f_faultsubnumber = ProtoField.uint16("cdbsubscriberitf.faultsubnumber","faultsubnumber",base.DEC)
	local f_manuinfolength = ProtoField.uint32("cdbsubscriberitf.manuinfolength","manuinfolength",base.DEC)
	local f_manuinfo = ProtoField.string("cdbsubscriberitf.manuinfo","manuinfo",base.NONE)
	local f_perceivedseverity = ProtoField.uint32("cdbsubscriberitf.perceivedseverity","perceivedseverity",base.DEC)
	local f_nbAttributes = ProtoField.uint16("cdbsubscriberitf.nbAttributes","nbAttributes",base.DEC)
	local f_attributes = ProtoField.string("cdbsubscriberitf.attributes","attributes",base.NONE)
	local f_nbrOfAvcnAttr = ProtoField.uint16("cdbsubscriberitf.nbrOfAvcnAttr","nbrOfAvcnAttr",base.DEC)
	local f_avcnAttributes = ProtoField.string("cdbsubscriberitf.avcnAttributes","avcnAttributes",base.NONE)
	local f_nbrOfSvcnAttr = ProtoField.uint16("cdbsubscriberitf.nbrOfSvcnAttr","nbrOfSvcnAttr",base.DEC)
	local f_svcnAttributes = ProtoField.string("cdbsubscriberitf.svcnAttributes","svcnAttributes",base.NONE)
	local f_alarmLastChangeCounter = ProtoField.uint32("cdbsubscriberitf.alarmLastChangeCounter","alarmLastChangeCounter",base.DEC)
	local f_len_managedObjectInstance = ProtoField.uint32("cdbsubscriberitf.len_managedObjectInstance","len_managedObjectInstance",base.DEC)
	local f_managedObjectInstance = ProtoField.uint32("cdbsubscriberitf.managedObjectInstance","managedObjectInstance",base.DEC)
	local f_len_alarmTime = ProtoField.uint32("cdbsubscriberitf.len_alarmTime","len_alarmTime",base.DEC)
	local f_alarmTime = ProtoField.uint8("cdbsubscriberitf.alarmTime","alarmTime",base.DEC)
	local f_alarmType = ProtoField.int32("cdbsubscriberitf.alarmType","alarmType",base.DEC)
	local f_alarmSeverity = ProtoField.int32("cdbsubscriberitf.alarmSeverity","alarmSeverity",base.DEC)
	local f_alarmId = ProtoField.int32("cdbsubscriberitf.alarmId","alarmId",base.DEC)
	local f_len_alarmAdditionalInformation = ProtoField.uint32("cdbsubscriberitf.len_alarmAdditionalInformation","len_alarmAdditionalInformation",base.DEC)
	local f_alarmAdditionalInformation = ProtoField.uint8("cdbsubscriberitf.alarmAdditionalInformation","alarmAdditionalInformation",base.DEC)
	local f_alarmOperationalState = ProtoField.int32("cdbsubscriberitf.alarmOperationalState","alarmOperationalState",base.DEC)
	local f_alarmAvailabilityStatus = ProtoField.uint32("cdbsubscriberitf.alarmAvailabilityStatus","alarmAvailabilityStatus",base.DEC)
	local f_numberOfFilteredAlarmsSinceLastReporting = ProtoField.int32("cdbsubscriberitf.numberOfFilteredAlarmsSinceLastReporting","numberOfFilteredAlarmsSinceLastReporting",base.DEC)
	local f_len_lastFilteringTime = ProtoField.uint32("cdbsubscriberitf.len_lastFilteringTime","len_lastFilteringTime",base.DEC)
	local f_lastFilteringTime = ProtoField.uint8("cdbsubscriberitf.lastFilteringTime","lastFilteringTime",base.DEC)
	local f_lastFilteringType = ProtoField.int32("cdbsubscriberitf.lastFilteringType","lastFilteringType",base.DEC)
	local f_alarmNature = ProtoField.int32("cdbsubscriberitf.alarmNature","alarmNature",base.DEC)
	local f_len_alarmMonitoredAttribute = ProtoField.uint32("cdbsubscriberitf.len_alarmMonitoredAttribute","len_alarmMonitoredAttribute",base.DEC)
	local f_len_alarmSpecificProblem = ProtoField.uint32("cdbsubscriberitf.len_alarmSpecificProblem","len_alarmSpecificProblem",base.DEC)
	local f_alarmMonitoredAttribute = ProtoField.uint8("cdbsubscriberitf.alarmMonitoredAttribute","alarmMonitoredAttribute",base.DEC)
	local f_alarmSpecificProblem = ProtoField.uint8("cdbsubscriberitf.alarmSpecificProblem","alarmSpecificProblem",base.DEC)
	local f_objChgType = ProtoField.uint16("cdbsubscriberitf.objChgType","objChgType",base.DEC)
	local f_objChgOriginator = ProtoField.uint16("cdbsubscriberitf.objChgOriginator","objChgOriginator",base.DEC)
	local f_idxWithinObjChgReq = ProtoField.uint16("cdbsubscriberitf.idxWithinObjChgReq","idxWithinObjChgReq",base.DEC)
	local f_lcc = ProtoField.uint32("cdbsubscriberitf.lcc","lcc",base.DEC)
	local f_lccValue = ProtoField.uint32("cdbsubscriberitf.lccValue","lccValue",base.DEC)
	local f_cmLccValue = ProtoField.uint32("cdbsubscriberitf.cmLccValue","cmLccValue",base.DEC)
	local f_sourceIndicator = ProtoField.uint8("cdbsubscriberitf.sourceIndicator","sourceIndicator",base.DEC)
	local f_additionalText = ProtoField.uint8("cdbsubscriberitf.additionalText","additionalText",base.DEC)
	local f_fdnStrLen = ProtoField.uint32("cdbsubscriberitf.fdnStrLen","fdnStrLen",base.DEC)
	local f_modifyStrLen = ProtoField.uint32("cdbsubscriberitf.modifyStrLen","modifyStrLen",base.DEC)
	local f_fdnStr = ProtoField.uint8("cdbsubscriberitf.fdnStr","fdnStr",base.DEC)
	local f_modifyStr = ProtoField.uint8("cdbsubscriberitf.modifyStr","modifyStr",base.DEC)
	local f_resetReason = ProtoField.uint32("cdbsubscriberitf.resetReason","resetReason",base.DEC, vs_resetReason)
	local f_parentOamInstanceIndex = ProtoField.uint16("cdbsubscriberitf.parentOamInstanceIndex", "parentOamInstanceIndex", base.DEC)
	local f_data = ProtoField.uint16("cdbsubscriberitf.data","data",base.DEC)
	local f_nbrOfInstanceId = ProtoField.uint16("cdbsubscriberitf.nbrOfInstanceId","nbrOfInstanceId", base.DEC)
	local f_oamLteInstanceId = ProtoField.string("cdbsubscriberitf.oamLteInstanceId", "oamLteInstanceId", base.NONE)
	local f_configDir = ProtoField.string("cdbsubscriberitf.configDir", "configDir", base.NONE)
	local f_cbReplacement = ProtoField.new("cdbsubscriberitf.cbReplacement", "cbReplacement",ftypes.BOOLEAN, {}, base.NONE)
	local f_typeOfIndication = ProtoField.uint32("cdbsubscriberitf.typeOfIndication", "typeOfIndication", base.DEC, vs_typeOfIndication)
	local f_nbrOfDisabledObj = ProtoField.uint16("cdbsubscriberitf.nbrOfDisabledObj", "nbrOfDisabledObj", base.DEC)
	local f_oamInstanceId = ProtoField.uint16("cdbsubscriberitf.oamInstanceId", "oamInstanceId", base.DEC)
	local f_nbrOfAttrIds = ProtoField.uint16("cdbsubscriberitf.nbrOfAttrIds", "nbrOfAttrIds", base.DEC)
	local f_attributeIds = ProtoField.uint16("cdbsubscriberitf.attributeIds", "attributeIds", base.DEC)
	local f_nbrOfAttr = ProtoField.uint16("cdbsubscriberitf.nbrOfAttr", "nbrOfAttr", base.DEC)
	local f_overflowType = ProtoField.uint32("cdbsubscriberitf.overflowType", "overflowType", base.DEC, vs_overflowType)
	
	--把ProtoField对象加到Proto对象上
	p_cdbsubscriberitf.fields = { f_family, f_opcode, f_length, f_transactionid, f_destclass, f_srcclass, f_destinst, f_srcinst, f_tracekey, 
									f_objChgType, f_objChgOriginator, f_idxWithinObjChgReq, f_lcc, f_lccValue, f_cmLccValue, 
									f_resetReason, f_parentOamInstanceIndex, f_data, f_nbrOfInstanceId, f_oamLteInstanceId, f_configDir,
									f_cbReplacement, f_typeOfIndication, f_nbrOfDisabledObj, f_oamInstanceId, f_attributeIds, f_nbrOfAttrIds,
									f_nbrOfAttr, f_overflowType, 
									f_sourceIndicator, f_additionalText, f_fdnStrLen, f_modifyStrLen, f_fdnStr, f_modifyStr, 
									f_oamclassref, f_oaminstanceindex, f_oamstatus, f_nbrofinstances, f_indexarray, f_payloadlen, f_payload,
									f_nbrofchgattr, f_chgattributes, f_nbAttributesElements, f_changeref, f_successflag, f_errordetail, 
									f_bulkadditionaltext, f_nbravcninfores, f_x2lcc_lcc, f_x2lcc_lccvalue, f_x2lcc_addtionaltext, 
									f_cmlcc_lcc, f_cmlcc_lccvalue, f_cmlcc_addtionaltext, f_avcninfores_lcc, f_avcninfores_lccvalue, 
									f_avcninfores_addtionaltext, f_anrresettype, f_forceincx2accesslcc, f_nbrofchangedobj, f_parentoamclassref, 
									f_parentoaminstanceid, f_changetype, f_changeweight, f_exchangeweight, f_forceincmolcc, f_nbrofchangerefs, 
									f_changerefs, f_actiontype, f_actionerrormessagelen, f_actionerrormessage, f_fdnlength, f_cdbstatus, f_triggeractiontype,
									f_objecttype, f_objectinstance, f_faultnumber, f_faultsubnumber, f_manuinfolength, f_manuinfo, f_perceivedseverity,
									f_nbAttributes, f_attributes, f_nbrOfAvcnAttr, f_avcnAttributes, f_nbrOfSvcnAttr, f_svcnAttributes,
									f_alarmLastChangeCounter, f_alarmSpecificProblem, f_alarmMonitoredAttribute, f_len_alarmSpecificProblem, f_len_alarmMonitoredAttribute,
									f_alarmNature, f_lastFilteringType, f_lastFilteringTime, f_len_lastFilteringTime, f_numberOfFilteredAlarmsSinceLastReporting,
									f_alarmAvailabilityStatus, f_alarmOperationalState, f_alarmAdditionalInformation, f_len_alarmAdditionalInformation,
									f_alarmId, f_alarmSeverity, f_alarmType, f_alarmTime, f_len_alarmTime, f_managedObjectInstance, f_len_managedObjectInstance  }

    --用Dissector.get函数可以获得另外一个协议的解析组件
    --local data_dis = Dissector.get("data")

    --为Proto对象添加一个名为dissector的函数，
    --Wireshark会对每个“相关”数据包调用这个函数
    function p_cdbsubscriberitf.dissector(buf,pkt,root) 

		local offset = 0
		local buf_len = buf:len()
		
        --root:add会在Packet Details窗格中增加一行协议
        local t = root:add(p_cdbsubscriberitf,buf:range(offset))
        --t:add，在Packet Details窗格中增加一行属性，
        --并指定要鼠标点击该属性时Packet Bytes窗格中会选中哪些字节
        t:add(f_family,buf:range(offset,2))
		offset = offset + 2
		local myopcode = buf:range(offset,2):uint()
        t:add(f_opcode,buf:range(offset,2))
		offset = offset + 2
		t:add(f_length,buf:range(offset,4))
		offset = offset + 4
		t:add(f_transactionid,buf:range(offset,4))
		offset = offset + 4
		t:add(f_destclass,buf:range(offset,2))
		offset = offset + 2
		t:add(f_srcclass,buf:range(offset,2))
		offset = offset + 2
		t:add(f_destinst,buf:range(offset,4))
		offset = offset + 4
		t:add(f_srcinst,buf:range(offset,4))
		offset = offset + 4
		t:add(f_tracekey,buf:range(offset,4))
		offset = offset + 4
		
		local text_len = 0
		
		--用switch语句判断是哪条消息，再具体分析每条消息的特定字段
		local switch = {
			[100] = function()   --MT_OAMC_getAttributeReq 
				t:add(f_oamclassref,buf:range(offset,2))
				offset = offset + 2
				t:add(f_oaminstanceindex,buf:range(offset,2))
				offset = offset + 2
			end,
			[101] = function()   --MT_OAMC_getAttributeRes
				t:add(f_oamclassref,buf:range(offset,2))
				offset = offset + 2
				t:add(f_oaminstanceindex,buf:range(offset,2))
				offset = offset + 2
				t:add(f_oamstatus,buf:range(offset,2))
				offset = offset + 2
				t:add(f_nbrofinstances,buf:range(offset,2))
				offset = offset + 2
				t:add(f_indexarray,buf:range(offset,2*MAX_NUM_OF_INSTANCES))
				offset = offset + 2*MAX_NUM_OF_INSTANCES
				t:add(f_payloadlen,buf:range(offset,4))
				offset = offset + 4
				
				text_len = buf_len - offset
				t:add(f_payload,buf:range(offset,text_len))
				offset = offset + text_len
			end,
			[102] = function()	--GET_DYN_ATTR_REQ
				t:add(f_oamclassref, buf:range(offset,2))
				offset = offset + 2
				t:add(f_oaminstanceindex, buf:range(offset, 2))
				offset = offset + 2
			end,
			[103] = function()	--GET_DYN_ATTR_RES
				t:add(f_oamclassref, buf:range(offset,2))
				offset = offset + 2
				t:add(f_oaminstanceindex, buf:range(offset, 2))
				offset = offset + 2
				t:add(f_oamstatus,buf:range(offset,2))
				offset = offset + 2
				text_len = buf_len - offset
				t:add(f_payload,buf:range(offset,text_len))
				offset = offset + text_len								
			end,
			[104] = function()	--SET_ATTR_REQ
				t:add(f_oamclassref, buf:range(offset,2))
				offset = offset + 2
				t:add(f_oaminstanceindex, buf:range(offset, 2))
				offset = offset + 2
				t:add(f_nbAttributes, buf:range(offset, 2))
				offset = offset + 4	--4 byte align				
				t:add(f_attributes, buf:range(offset, 8 * OAM_L_ATTRIBUTE_NAME_MAX))
				offset = offset + 8 * OAM_L_ATTRIBUTE_NAME_MAX				
			end,
			[105] = function()	--SET_ATTR_RES
				t:add(f_oamclassref, buf:range(offset,2))
				offset = offset + 2
				t:add(f_oaminstanceindex, buf:range(offset, 2))
				offset = offset + 2
				t:add(f_oamstatus,buf:range(offset,2))
				offset = offset + 2	
				t:add(f_nbrOfAvcnAttr,buf:range(offset,2))
				offset = offset + 2
				t:add(f_avcnAttributes,buf:range(offset,8 * OAM_L_ATTRIBUTE_NAME_MAX))
				offset = offset + 8 * OAM_L_ATTRIBUTE_NAME_MAX			
				t:add(f_nbrOfSvcnAttr,buf:range(offset,2))
				offset = offset + 4	--4 byte align
				t:add(f_svcnAttributes,buf:range(offset,8 * 3))
				offset = offset + 8 * 3				
			end,
			[106] = function()	--CONS_CHK_REQ
			end,
			[107] = function()	--CONS_CHK_RES
				t:add(f_successflag, buf:range(offset,2))
				offset = offset + 2	
				t:add(f_errordetail, buf:range(offset,MAX_ERROR_DETAILS_LEN))
				offset = offset + MAX_ERROR_DETAILS_LEN + 1					
			end,			
			[108] = function()   --MT_OAMC_objectChangeReq 
				t:add(f_anrresettype,buf:range(offset,4))
				offset = offset + 4
				t:add(f_forceincx2accesslcc,buf:range(offset,1))
				offset = offset + 1 + 1
				t:add(f_nbrofchangedobj,buf:range(offset,2))
				offset = offset + 2
				t:add(f_oamclassref,buf:range(offset,2))
				offset = offset + 2
				t:add(f_oaminstanceindex,buf:range(offset,2))
				offset = offset + 2
				t:add(f_parentoamclassref,buf:range(offset,2))
				offset = offset + 2
				t:add(f_parentoaminstanceid,buf:range(offset,2))
				offset = offset + 2
				t:add(f_changetype,buf:range(offset,2))
				offset = offset + 2
				t:add(f_changeweight,buf:range(offset,2))
				offset = offset + 2
				t:add(f_exchangeweight,buf:range(offset,2))
				offset = offset + 2
				t:add(f_forceincmolcc,buf:range(offset,1))
				offset = offset + 1 + 1
				t:add(f_nbrofchangerefs,buf:range(offset,2))
				offset = offset + 2
				t:add(f_changerefs,buf:range(offset,1*OAM_L_ATTRIBUTE_NAME_MAX))
				offset = offset + 1*OAM_L_ATTRIBUTE_NAME_MAX + 3
			end,
			[109] = function()   --MT_OAMC_objectChangeRes 
				t:add(f_successflag,buf:range(offset,2))
				offset = offset + 2
				t:add(f_errordetail,buf:range(offset,1*MAX_ERROR_DETAILS_LEN))
				offset = offset + 1*MAX_ERROR_DETAILS_LEN+1
				t:add(f_x2lcc_lcc,buf:range(offset,4))
				offset = offset + 4
				t:add(f_x2lcc_lccvalue,buf:range(offset,4))
				offset = offset + 4
				t:add(f_x2lcc_addtionaltext,buf:range(offset,1*MAX_ADDITIONAL_TEXT_LEN))
				offset = offset + 1*MAX_ADDITIONAL_TEXT_LEN + 3
				t:add(f_cmlcc_lcc,buf:range(offset,4))
				offset = offset + 4
				t:add(f_cmlcc_lccvalue,buf:range(offset,4))
				offset = offset + 4
				t:add(f_cmlcc_addtionaltext,buf:range(offset,1*MAX_ADDITIONAL_TEXT_LEN))
				offset = offset + 1*MAX_ADDITIONAL_TEXT_LEN + 3
				t:add(f_bulkadditionaltext,buf:range(offset,1*MAX_ADDITIONAL_TEXT_LEN))
				offset = offset + 1*MAX_ADDITIONAL_TEXT_LEN+1
				t:add(f_nbravcninfores,buf:range(offset,2))
				offset = offset + 2
				t:add(f_avcninfores_lcc,buf:range(offset,4))
				offset = offset + 4
				t:add(f_avcninfores_lccvalue,buf:range(offset,4))
				offset = offset + 4
				t:add(f_avcninfores_addtionaltext,buf:range(offset,1*MAX_ADDITIONAL_TEXT_LEN))
				offset = offset + 1*MAX_ADDITIONAL_TEXT_LEN + 3
			end,
			[110] = function()	--ResetInd
				t:add(f_resetReason,buf:range(offset,4))
				offset = offset + 4
			end,			
			[111] = function()   --MT_OAMC_createObjInd   
				t:add(f_oamclassref,buf:range(offset,2))
				offset = offset + 2
				t:add(f_parentoamclassref, buf:range(offset,2))
				offset = offset + 2
				t:add(f_parentOamInstanceIndex, buf:range(offset,2))
				offset = offset + 2 
				text_len = buf_len - offset
				t:add(f_data,buf:range(offset,text_len))
				offset = offset + text_len
			end,
			[112] = function()   --MT_OAMC_modifyObjInd 
				t:add(f_oamclassref,buf:range(offset,2))
				offset = offset + 2
				t:add(f_oaminstanceindex,buf:range(offset,2))
				offset = offset + 2
				t:add(f_nbAttributesElements,buf:range(offset,2))
				offset = offset + 2
				t:add(f_changeref,buf:range(offset,1*OAM_L_ATTRIBUTE_NAME_MAX))
				offset = offset + 1*OAM_L_ATTRIBUTE_NAME_MAX
				
				text_len = buf_len - offset
				t:add(f_payload,buf:range(offset,text_len))
				offset = offset + text_len
			end,
			[113] = function()    --MT_OAMC_deleteObjInd
				t:add(f_oamclassref,buf:range(offset,2))
				offset = offset + 2
				t:add(f_oaminstanceindex,buf:range(offset,2))
				offset = offset + 2
			end,
			[114] = function()	--AnrResetStartInd
				t:add(f_anrresettype,buf:range(offset,4))
				offset = offset + 4 
				t:add(f_nbrOfInstanceId, buf:range(offset,2))
				offset = offset + 2
				text_len = buf_len - offset
				t:add(f_oamLteInstanceId,buf:range(offset,text_len))
				offset = offset + text_len
			end,
			[115] = function()	--NCAGENT_INIT_REQ
				t:add(f_configDir, buf:range(offset, 512))
				offset = offset + 512
				t:add(f_cbReplacement, buf:range(offset, 1))
				offset = offset + 4
			end,
			[116] = function()	--NCAGENT_INIT_RES
				t:add(f_oamstatus,buf:range(offset,2))
				offset = offset + 2				
			end,
			[117] = function()	--NCAGENT_BACKUP_REQ
				-- miss now
			end,
			[118] = function()	--NCAGENT_BACKUP_RES
				t:add(f_oamstatus,buf:range(offset,2))
				offset = offset + 2				
			end,
			[119] = function()	--NCAGENT_RESTORE_REQ
				-- miss now
			end,
			[120] = function()	--NCAGENT_RESTORE_RES
				t:add(f_oamstatus,buf:range(offset,2))
				offset = offset + 2				
			end,
			[121] = function()	--NCAGENT_X2Access_Overflow
				t:add(f_typeOfIndication, buf:range(offset,4))
				offset = offset + 4
			end,
			[122] = function()	--DisableObjReq
				t:add(f_nbrOfDisabledObj, buf:range(offset,2))
				offset = offset + 4
				t:add(f_oamclassref, buf:range(offset,2))
				offset = offset + 2,
				t:add(f_oamInstanceId, buf:range(offset,2))
				offset = offset + 2
			end,
			[123] = function()	--disableObjRes
				t:add(f_oamstatus,buf:range(offset,2))
				offset = offset + 2				
			end,
			[124] = function()	--SET_SHADOW_ATTR_REQ
				t:add(f_oamclassref, buf:range(offset,2))
				offset = offset + 2
				t:add(f_oaminstanceindex, buf:range(offset, 2))
				offset = offset + 2
				t:add(f_nbAttributes, buf:range(offset, 2))
				offset = offset + 4	--4 byte align				
				t:add(f_attributes, buf:range(offset, 12 * OAM_L_ATTRIBUTE_NAME_MAX))
				offset = offset + 2 * OAM_L_ATTRIBUTE_NAME_MAX					
			end,
			[125] = function()	--SET_SHADOW_ATTR_RES
				t:add(f_oamclassref, buf:range(offset,2))
				offset = offset + 2
				t:add(f_oaminstanceindex, buf:range(offset, 2))
				offset = offset + 2
				t:add(f_oamstatus,buf:range(offset,2))
				offset = offset + 2	
				t:add(f_nbrOfAvcnAttr,buf:range(offset,2))
				offset = offset + 2
				t:add(f_avcnAttributes,buf:range(offset,8 * OAM_L_ATTRIBUTE_NAME_MAX))
				offset = offset + 12 * OAM_L_ATTRIBUTE_NAME_MAX			
				t:add(f_nbrOfSvcnAttr,buf:range(offset,2))
				offset = offset + 4	--4 byte align
				t:add(f_svcnAttributes,buf:range(offset,8 * 3))
				offset = offset + 12 * 3					
			end,
			[126] = function()	--GET_ORIG_ATTR_REQ
				t:add(f_oamclassref, buf:range(offset,2))
				offset = offset + 2
				t:add(f_oaminstanceindex, buf:range(offset, 2))
				offset = offset + 2
				t:add(f_nbrOfAttrIds, buf:range(offset,2))
				offset = offset + 2,
				t:add(f_attributeIds, buf:range(offset, 2*OAM_L_ATTRIBUTE_NAME_MAX))
				offset = offset + 2*OAM_L_ATTRIBUTE_NAME_MAX
			end,
			[127] = function()	--GET_ORIG_ATTR_RES
				t:add(f_oamclassref, buf:range(offset,2))
				offset = offset + 2
				t:add(f_oaminstanceindex, buf:range(offset, 2))
				offset = offset + 2
				t:add(f_oamstatus,buf:range(offset,2))
				offset = offset + 2	
				t:add(f_nbrOfAttr,buf:range(offset,2))
				offset = offset + 2
				t:add(f_attributes,buf:range(offset, 12 * OAM_L_ATTRIBUTE_NAME_MAX))
				offset = 12 * OAM_L_ATTRIBUTE_NAME_MAX
			end,
			[128] = function()	--ORIG_ATTR_CHANGE_REQ
				t:add(f_anrresettype,buf:range(offset,4))
				offset = offset + 4
				t:add(f_forceincx2accesslcc,buf:range(offset,1))
				offset = offset + 1 + 1
				t:add(f_nbrofchangedobj,buf:range(offset,2))
				offset = offset + 2
				t:add(f_oamclassref,buf:range(offset,2))
				offset = offset + 2
				t:add(f_oaminstanceindex,buf:range(offset,2))
				offset = offset + 2
				t:add(f_parentoamclassref,buf:range(offset,2))
				offset = offset + 2
				t:add(f_parentoaminstanceid,buf:range(offset,2))
				offset = offset + 2
				t:add(f_changetype,buf:range(offset,2))
				offset = offset + 2
				t:add(f_changeweight,buf:range(offset,2))
				offset = offset + 2
				t:add(f_exchangeweight,buf:range(offset,2))
				offset = offset + 2
				t:add(f_forceincmolcc,buf:range(offset,1))
				offset = offset + 1 + 1
				t:add(f_nbrofchangerefs,buf:range(offset,2))
				offset = offset + 2
				t:add(f_changerefs,buf:range(offset,1*OAM_L_ATTRIBUTE_NAME_MAX))
				offset = offset + 1*OAM_L_ATTRIBUTE_NAME_MAX + 3			
			end,
			[129] = function() 	  --ORIG_ATTR_CHANGE_RES
				t:add(f_oamstatus,buf:range(offset,2))
				offset = offset + 2				
			end,
			[130] = function()	  --NCAGENT_Overflow
				t:add(f_overflowType,buf:range(offset,4))
				offset = offset + 4
			end,
			[131] = function()	  --MT_OAMC_objectChangeNotify
				t:add(f_oamclassref,buf:range(offset,2))
				offset = offset + 2
				t:add(f_oaminstanceindex,buf:range(offset,2))
				offset = offset + 2
				t:add(f_objChgType,buf:range(offset,2))
				offset = offset + 2
				t:add(f_objChgOriginator,buf:range(offset,2))
				offset = offset + 2
				t:add(f_idxWithinObjChgReq,buf:range(offset,2))
				offset = offset + 2 + 2
				t:add(f_lcc,buf:range(offset,4))
				offset = offset + 4
				t:add(f_lccValue,buf:range(offset,4))
				offset = offset + 4
				t:add(f_cmLccValue,buf:range(offset,4))
				offset = offset + 4
				t:add(f_sourceIndicator,buf:range(offset,1))
				offset = offset + 1
				t:add(f_additionalText,buf:range(offset,1*MAX_ADDITIONAL_TEXT_LEN))
				offset = offset + 1*MAX_ADDITIONAL_TEXT_LEN + 2
				t:add(f_fdnStrLen,buf:range(offset,4))
				offset = offset + 4
				t:add(f_modifyStrLen,buf:range(offset,4))
				offset = offset + 4
				t:add(f_fdnStr,buf:range(offset,1))
				offset = offset + 1
				t:add(f_modifyStr,buf:range(offset,1))
				offset = offset + 1
			end,
			[132] = function()	  --MT_OAMC_oamCtrlReadyInd
				--
			end,
			[133] = function()	  --MT_OAMC_configCommit
				-- miss now
			end,
			[134] = function()	  --MT_OAMC_alarmNotifInfo
				t:add(f_alarmLastChangeCounter,buf:range(offset,4))
				offset = offset + 4
				t:add(f_len_managedObjectInstance,buf:range(offset,4))
				offset = offset + 4
				t:add(f_managedObjectInstance,buf:range(offset,4*OAM_MAX_OID_LEN))
				offset = offset + 4*OAM_MAX_OID_LEN
				t:add(f_len_alarmTime,buf:range(offset,4))
				offset = offset + 4
				t:add(f_alarmTime,buf:range(offset,1*11))
				offset = offset + 1*11 + 1
				t:add(f_alarmType,buf:range(offset,4))
				offset = offset + 4
				t:add(f_alarmSeverity,buf:range(offset,4))
				offset = offset + 4
				t:add(f_alarmId,buf:range(offset,4))
				offset = offset + 4
				t:add(f_len_alarmAdditionalInformation,buf:range(offset,4))
				offset = offset + 4
				t:add(f_alarmAdditionalInformation,buf:range(offset,1*(MAX_ADDINFO_SIZE + 1)))
				offset = offset + 1*(MAX_ADDINFO_SIZE + 1) + 3
				t:add(f_alarmOperationalState,buf:range(offset,4))
				offset = offset + 4
				t:add(f_alarmAvailabilityStatus,buf:range(offset,4))
				offset = offset + 4
				t:add(f_numberOfFilteredAlarmsSinceLastReporting,buf:range(offset,4))
				offset = offset + 4
				t:add(f_len_lastFilteringTime,buf:range(offset,4))
				offset = offset + 4
				t:add(f_lastFilteringTime,buf:range(offset,1*11))
				offset = offset + 1*11 + 1
				t:add(f_lastFilteringType,buf:range(offset,4))
				offset = offset + 4
				t:add(f_alarmNature,buf:range(offset,4))
				offset = offset + 4
				t:add(f_len_alarmMonitoredAttribute,buf:range(offset,4))
				offset = offset + 4
				t:add(f_len_alarmSpecificProblem,buf:range(offset,4))
				offset = offset + 4
				t:add(f_alarmMonitoredAttribute,buf:range(offset,1*256))
				offset = offset + 1*256
				t:add(f_alarmSpecificProblem,buf:range(offset,1*256))
				offset = offset + 1*256
			end,
			[135] = function()    --MT_OAMC_cdbSubscribe
				t:add(f_oamclassref,buf:range(offset,2))
				offset = offset + 2
				t:add(f_indexarray,buf:range(offset,2*OAM_L_CLASSREF_MAX))
				offset = offset + 2*OAM_L_CLASSREF_MAX
			end,
			[136] = function()    --MT_OAMC_attrChgInd
				t:add(f_oamclassref,buf:range(offset,2))
				offset = offset + 2
				t:add(f_oaminstanceindex,buf:range(offset,2))
				offset = offset + 2
				t:add(f_nbrofchgattr,buf:range(offset,2))
				offset = offset + 2
				
				text_len = buf_len - offset
				t:add(f_chgattributes,buf:range(offset,text_len))
				offset = offset + text_len				
			end,
			[137] = function()    --MT_OAMC_faultInd
				t:add(f_objecttype,buf:range(offset,4))
				offset = offset + 4
				t:add(f_objectinstance,buf:range(offset,4))
				offset = offset + 4
				t:add(f_faultnumber,buf:range(offset,2))
				offset = offset + 2
				t:add(f_faultsubnumber,buf:range(offset,2))
				offset = offset + 2
				t:add(f_perceivedseverity,buf:range(offset,4))
				offset = offset + 4
				t:add(f_manuinfolength,buf:range(offset,4))
				offset = offset + 4
				
				text_len = buf_len - offset
				t:add(f_manuinfo,buf:range(offset,text_len))
				offset = offset + text_len
			end,
			[138] = function()    --MT_OAMC_eventInd
				t:add(f_objecttype,buf:range(offset,4))
				offset = offset + 4
				t:add(f_objectinstance,buf:range(offset,4))
				offset = offset + 4
				t:add(f_faultnumber,buf:range(offset,2))
				offset = offset + 2
				t:add(f_faultsubnumber,buf:range(offset,2))
				offset = offset + 2
				t:add(f_manuinfolength,buf:range(offset,4))
				offset = offset + 4
				
				text_len = buf_len - offset
				t:add(f_manuinfo,buf:range(offset,text_len))
				offset = offset + text_len	
			end,
			[139] = function()    --MT_OAMC_triggerActionInd
				t:add(f_oamclassref,buf:range(offset,2))
				offset = offset + 2
				t:add(f_oaminstanceindex,buf:range(offset,2))
				offset = offset + 2
				t:add(f_triggeractiontype,buf:range(offset,4))
				offset = offset + 4
			end,
			[140] = function()	  --MT_OAMC_openSnmpInd
				--
			end,
			[141] = function()	  --MT_OAMC_triggerActionReq
				t:add(f_oamclassref,buf:range(offset,2))
				offset = offset + 2
				t:add(f_oaminstanceindex,buf:range(offset,2))
				offset = offset + 2	
				t:add(f_actiontype,buf:range(offset,4))
				offset = offset + 4
				t:add(f_payloadlen,buf:range(offset,4))
				offset = offset + 4
				
				text_len = buf_len - offset
				t:add(f_payload,buf:range(offset,text_len))
				offset = offset + text_len	
			end,
			[142] = function()	  --MT_OAMC_triggerActionRes
				t:add(f_oamclassref,buf:range(offset,2))
				offset = offset + 2
				t:add(f_oaminstanceindex,buf:range(offset,2))
				offset = offset + 2	
				t:add(f_oamstatus,buf:range(offset,2))
				offset = offset + 4
				t:add(f_actiontype,buf:range(offset,4))
				offset = offset + 4
				t:add(f_actionerrormessagelen,buf:range(offset,4))
				offset = offset + 4
				t:add(f_actionerrormessage,buf:range(offset,1*OAMC_ACTIONERRORMESSAGE_LENGTH))
				offset = offset + 1*OAMC_ACTIONERRORMESSAGE_LENGTH + 1
				t:add(f_payloadlen,buf:range(offset,4))
				offset = offset + 4
				
				text_len = buf_len - offset
				t:add(f_payload,buf:range(offset,text_len))
				offset = offset + text_len	
			end,
			[143] = function()	  --MT_OAMC_getFDNrequest
				t:add(f_oamclassref,buf:range(offset,2))
				offset = offset + 2
				t:add(f_oaminstanceindex,buf:range(offset,2))
				offset = offset + 2
			end,
			[144] = function()	  --MT_OAMC_getFDNresult
				t:add(f_oamclassref,buf:range(offset,2))
				offset = offset + 2
				t:add(f_oaminstanceindex,buf:range(offset,2))
				offset = offset + 2	
				t:add(f_oamstatus,buf:range(offset,2))
				offset = offset + 2	
				t:add(f_fdnlength,buf:range(offset,2))
				offset = offset + 2	
				
				text_len = buf_len - offset
				t:add(f_payload,buf:range(offset,text_len))
				offset = offset + text_len	
			end,
			[145] = function()	  --MT_OAMC_cdbLockReq
				t:add(f_reference,buf:range(offset,4))
				offset = offset + 4
			end,
			[146] = function()	  --MT_OAMC_cdbLockRes
				t:add(f_reference,buf:range(offset,4))
				offset = offset + 4
				t:add(f_status,buf:range(offset,2))
				offset = offset + 2
			end,			
			[147] = function()	  --MT_OAMC_cdbUnlockReq
				t:add(f_reference,buf:range(offset,4))
				offset = offset + 4
			end,
			[148] = function()	  --MT_OAMC_cdbUnlockRes
				t:add(f_reference,buf:range(offset,4))
				offset = offset + 4
				t:add(f_status,buf:range(offset,2))
				offset = offset + 2
				t:add(f_cdbstatus,buf:range(offset,2))
				offset = offset + 2
			end,
			[149] = function()    --MT_OAMC_reconfigurationInd
				text_len = buf_len - offset
				t:add(f_payload,buf:range(offset,text_len))
				offset = offset + text_len
			end,
			[150] = function()    --MT_OAMC_oldObjectChangeReq
				-- miss now
			end
		}
		
		local f = switch[myopcode]
		if(f) then
			f()
		else
			--print "default."
		end
		
    end

    --这个是获得tcp协议的DissectorTable，并且以端口号排列
    local tce_port_table = DissectorTable.get("tcp.port")

    --为TCP的60100端口注册这个Proto对象，表明这个插件是解析60100端口的netconf消息
    --当遇到源或目的为TCP60100的数据包，就会调用上面的p_cdbsubscriberitf.dissector函数
    tce_port_table:add(60100,p_cdbsubscriberitf)
end