package zabbix

// For `HostObject` field: `Available`
const (
	HostAvailableUnknown     = 0
	HostAvailableAvailable   = 1
	HostAvailableUnavailable = 2
)

// For `HostObject` field: `Flags`
const (
	HostFlagsPlain      = 0
	HostFlagsDiscovered = 4
)

// For `HostObject` field: `Flags`
const (
	HostInventoryModeDisabled  = -1
	HostInventoryModeManual    = 0
	HostInventoryModeAutomatic = 1
)

// For `HostObject` field: `IpmiAuthtype`
const (
	HostIpmiAuthtypeDefault  = -1
	HostIpmiAuthtypeNone     = 0
	HostIpmiAuthtypeMD2      = 1
	HostIpmiAuthtypeMD5      = 2
	HostIpmiAuthtypeStraight = 4
	HostIpmiAuthtypeOEM      = 5
	HostIpmiAuthtypeRMCP     = 6
)

// For `HostObject` field: `IpmiAvailable`
const (
	HostIpmiAvailableUnknown     = 0
	HostIpmiAvailableAvailable   = 1
	HostIpmiAvailableUnavailable = 2
)

// For `HostObject` field: `IpmiPrivilege`
const (
	HostIpmiPrivilegeCallback = 1
	HostIpmiPrivilegeUser     = 2
	HostIpmiPrivilegeOperator = 3
	HostIpmiPrivilegeAdmin    = 4
	HostIpmiPrivilegeOEM      = 5
)

// For `HostObject` field: `JmxAvailable`
const (
	HostJmxAvailableUnknown     = 0
	HostJmxAvailableAvailable   = 1
	HostJmxAvailableUnavailable = 2
)

// For `HostObject` field: `MaintenanceStatus`
const (
	HostMaintenanceStatusDisable = 0
	HostMaintenanceStatusEnable  = 1
)

// For `HostObject` field: `MaintenanceType`
const (
	HostMaintenanceTypeDataCollectionEnabled  = 0
	HostMaintenanceTypeDataCollectionDisabled = 1
)

// For `HostObject` field: `SnmpAvailable`
const (
	HostSnmpAvailableUnknown     = 0
	HostSnmpAvailableAvailable   = 1
	HostSnmpAvailableUnavailable = 2
)

// For `HostObject` field: `Status`
const (
	HostStatusMonitored   = 0
	HostStatusUnmonitored = 1
)

// For `HostObject` field: `TLSConnect`
const (
	TLSConnectNoEncryption = 1
	TLSConnectPSK          = 2
	TLSConnectCertificate  = 4
)

// For `HostObject` field: `TLSAccept`
const (
	TLSAcceptNoEncryption = 1
	TLSAcceptPSK          = 2
	TLSAcceptCertificate  = 4
)

// For `HostGetParams` field: `Evaltype`
const (
	HostEvaltypeAndOr = 0
	HostEvaltypeOr    = 2
)

// For `HostTag` field: `Operator`
const (
	HostTagOperatorContains = 0
	HostTagOperatorEquals   = 1
)

// HostObject struct is used to store host operations results
//
// see: https://www.zabbix.com/documentation/5.0/manual/api/reference/host/object#host
type HostObject struct {
	HostID            int    `json:"hostid,omitempty"`
	Host              string `json:"host,omitempty"`
	Available         int    `json:"available,omitempty"` // has defined consts, see above
	Description       string `json:"description,omitempty"`
	DisableUntil      int    `json:"disable_until,omitempty"`
	Error             string `json:"error,omitempty"`
	ErrorsFrom        int    `json:"errors_from,omitempty"`
	Flags             int    `json:"flags,omitempty"`          // has defined consts, see above
	InventoryMode     int    `json:"inventory_mode,omitempty"` // has defined consts, see above
	IpmiAuthtype      int    `json:"ipmi_authtype,omitempty"`  // has defined consts, see above
	IpmiAvailable     int    `json:"ipmi_available,omitempty"` // has defined consts, see above
	IpmiDisableUntil  int    `json:"ipmi_disable_until,omitempty"`
	IpmiError         string `json:"ipmi_error,omitempty"`
	IpmiErrorsFrom    int    `json:"ipmi_errors_from,omitempty"`
	IpmiPassword      string `json:"ipmi_password,omitempty"`
	IpmiPrivilege     int    `json:"ipmi_privilege,omitempty"` // has defined consts, see above
	IpmiUsername      string `json:"ipmi_username,omitempty"`
	JmxAvailable      int    `json:"jmx_available,omitempty"` // has defined consts, see above
	JmxDisableUntil   int    `json:"jmx_disable_until,omitempty"`
	JmxError          string `json:"jmx_error,omitempty"`
	JmxErrorsFrom     int    `json:"jmx_errors_from,omitempty"`
	MaintenanceFrom   int    `json:"maintenance_from,omitempty"`
	MaintenanceStatus int    `json:"maintenance_status,omitempty"` // has defined consts, see above
	MaintenanceType   int    `json:"maintenance_type,omitempty"`   // has defined consts, see above
	MaintenanceID     int    `json:"maintenanceid,omitempty"`
	Name              string `json:"name,omitempty"`
	ProxyHostID       int    `json:"proxy_hostid,omitempty"`
	SnmpAvailable     int    `json:"snmp_available,omitempty"` // has defined consts, see above
	SnmpDisableUntil  int    `json:"snmp_disable_until,omitempty"`
	SnmpError         string `json:"snmp_error,omitempty"`
	SnmpErrorsFrom    int    `json:"snmp_errors_from,omitempty"`
	Status            int    `json:"status,omitempty"`      // has defined consts, see above
	TLSConnect        int    `json:"tls_connect,omitempty"` // has defined consts, see above
	TLSAccept         int    `json:"tls_accept,omitempty"`  // has defined consts, see above
	TLSIssuer         string `json:"tls_issuer,omitempty"`
	TLSSubject        string `json:"tls_subject,omitempty"`
	TLSPSKIdentity    string `json:"tls_psk_identity,omitempty"`
	TLSPSK            string `json:"tls_psk,omitempty"`

	Groups          []HostgroupObject     `json:"groups,omitempty"`
	Interfaces      []HostinterfaceObject `json:"interfaces,omitempty"`
	Tags            []HostTagObject       `json:"tags,omitempty"`
	InheritedTags   []HostTagObject       `json:"inheritedTags,omitempty"`
	Macros          []UsermacroObject     `json:"macros,omitempty"`
	Templates       []TemplateObject      `json:"templates,omitempty"`       // Used for `create` operations
	ParentTemplates []TemplateObject      `json:"parentTemplates,omitempty"` // Used to store result for `get` operations
	Inventory       HostInventoryObject   `json:"inventory,omitempty"`
}

// HostTagObject struct is used to store host tag
//
// see: https://www.zabbix.com/documentation/5.0/manual/api/reference/host/object#host_tag
type HostTagObject struct {
	Id    string `json:"id,omitempty"`
	Tag   string `json:"tag"`
	Value string `json:"value,omitempty"`

	Operator int `json:"operator,omitempty"` // Used for `get` operations, has defined consts, see above
}

// HostInventoryObject struct is used to store host Inventory objects
//
// see: https://www.zabbix.com/documentation/5.0/en/manual/api/reference/host/object#host-inventory
type HostInventoryObject struct {
	Type             string `json:"type,omitempty"`
	TypeFull         string `json:"type_full,omitempty"`
	Name             string `json:"name,omitempty"`
	Alias            string `json:"alias,omitempty"`
	OS               string `json:"os,omitempty"`
	OSFull           string `json:"os_full,omitempty"`
	OSShort          string `json:"os_short,omitempty"`
	SerialnoA        string `json:"serialno_a,omitempty"`
	SerialnoB        string `json:"serialno_b,omitempty"`
	Tag              string `json:"tag,omitempty"`
	AssetTag         string `json:"asset_tag,omitempty"`
	MacaddressA      string `json:"macaddress_a,omitempty"`
	MacaddressB      string `json:"macaddress_b,omitempty"`
	Hardware         string `json:"hardware,omitempty"`
	HardwareFull     string `json:"hardware_full,omitempty"`
	Software         string `json:"software,omitempty"`
	SoftwareFull     string `json:"software_full,omitempty"`
	SoftwareAppA     string `json:"software_app_a,omitempty"`
	SoftwareAppB     string `json:"software_app_b,omitempty"`
	SoftwareAppC     string `json:"software_app_c,omitempty"`
	SoftwareAppD     string `json:"software_app_d,omitempty"`
	SoftwareAppE     string `json:"software_app_e,omitempty"`
	Contact          string `json:"contact,omitempty"`
	Location         string `json:"location,omitempty"`
	LocationLat      string `json:"location_lat,omitempty"`
	LocationLon      string `json:"location_lon,omitempty"`
	Notes            string `json:"notes,omitempty"`
	Chassis          string `json:"chassis,omitempty"`
	Model            string `json:"model,omitempty"`
	HwArch           string `json:"hw_arch,omitempty"`
	Vendor           string `json:"vendor,omitempty"`
	ContractNumber   string `json:"contract_number,omitempty"`
	InstallerName    string `json:"installer_name,omitempty"`
	DeploymentStatus string `json:"deployment_status,omitempty"`
	UrlA             string `json:"url_a,omitempty"`
	UrlB             string `json:"url_b,omitempty"`
	UrlC             string `json:"url_c,omitempty"`
	HostNetworks     string `json:"host_networks,omitempty"`
	HostNetmask      string `json:"host_netmask,omitempty"`
	HostRouter       string `json:"host_router,omitempty"`
	OobIP            string `json:"oob_ip,omitempty"`
	OobNetmask       string `json:"oob_netmask,omitempty"`
	OobRouter        string `json:"oob_router,omitempty"`
	DateHwPurchase   string `json:"date_hw_purchase,omitempty"`
	DateHwInstall    string `json:"date_hw_install,omitempty"`
	DateHwExpiry     string `json:"date_hw_expiry,omitempty"`
	DateHwDecomm     string `json:"date_hw_decomm,omitempty"`
	SiteAddressA     string `json:"site_address_a,omitempty"`
	SiteAddressB     string `json:"site_address_b,omitempty"`
	SiteAddressC     string `json:"site_address_c,omitempty"`
	SiteCity         string `json:"site_city,omitempty"`
	SiteState        string `json:"site_state,omitempty"`
	SiteCountry      string `json:"site_country,omitempty"`
	SiteZip          string `json:"site_zip,omitempty"`
	SiteRack         string `json:"site_rack,omitempty"`
	SiteNotes        string `json:"site_notes,omitempty"`
	Poc1Name         string `json:"poc_1_name,omitempty"`
	Poc1Email        string `json:"poc_1_email,omitempty"`
	Poc1PhoneA       string `json:"poc_1_phone_a,omitempty"`
	Poc1PhoneB       string `json:"poc_1_phone_b,omitempty"`
	Poc1Cell         string `json:"poc_1_cell,omitempty"`
	Poc1Screen       string `json:"poc_1_screen,omitempty"`
	Poc1Notes        string `json:"poc_1_notes,omitempty"`
	Poc2Name         string `json:"poc_2_name,omitempty"`
	Poc2Email        string `json:"poc_2_email,omitempty"`
	Poc2PhoneA       string `json:"poc_2_phone_a,omitempty"`
	Poc2PhoneB       string `json:"poc_2_phone_b,omitempty"`
	Poc2Cell         string `json:"poc_2_cell,omitempty"`
	Poc2Screen       string `json:"poc_2_screen,omitempty"`
	Poc2Notes        string `json:"poc_2_notes,omitempty"`
}

type HostGetParams struct {
	GetParameters

	GroupIDs       []int `json:"groupids,omitempty"`
	ApplicationIDs []int `json:"applicationids,omitempty"`
	DserviceIDs    []int `json:"dserviceids,omitempty"`
	GraphIDs       []int `json:"graphids,omitempty"`
	HostIDs        []int `json:"hostids,omitempty"`
	HttptestIDs    []int `json:"httptestids,omitempty"`
	InterfaceIDs   []int `json:"interfaceids,omitempty"`
	ItemIDs        []int `json:"itemids,omitempty"`
	MaintenanceIDs []int `json:"maintenanceids,omitempty"`
	MonitoredHosts bool  `json:"monitored_hosts,omitempty"`
	ProxyHosts     bool  `json:"proxy_hosts,omitempty"`
	ProxyIDs       []int `json:"proxyids,omitempty"`
	TemplatedHosts bool  `json:"templated_hosts,omitempty"`
	TemplateIDs    []int `json:"templateids,omitempty"`
	TriggerIDs     []int `json:"triggerids,omitempty"`

	WithItems                     bool            `json:"with_items,omitempty"`
	WithItemPrototypes            bool            `json:"with_item_prototypes,omitempty"`
	WithSimpleGraphItemPrototypes bool            `json:"with_simple_graph_item_prototypes,omitempty"`
	WithApplications              bool            `json:"with_applications,omitempty"`
	WithGraphs                    bool            `json:"with_graphs,omitempty"`
	WithGraphPrototypes           bool            `json:"with_graph_prototypes,omitempty"`
	WithHttptests                 bool            `json:"with_httptests,omitempty"`
	WithMonitoredHttptests        bool            `json:"with_monitored_httptests,omitempty"`
	WithMonitoredItems            bool            `json:"with_monitored_items,omitempty"`
	WithMonitoredTriggers         bool            `json:"with_monitored_triggers,omitempty"`
	WithSimpleGraphItems          bool            `json:"with_simple_graph_items,omitempty"`
	WithTriggers                  bool            `json:"with_triggers,omitempty"`
	WithProblemsSuppressed        bool            `json:"withProblemsSuppressed,omitempty"`
	Evaltype                      int             `json:"evaltype,omitempty"` // has defined consts, see above
	Severities                    []int           `json:"severities,omitempty"`
	Tags                          []HostTagObject `json:"tags,omitempty"`
	InheritedTags                 bool            `json:"inheritedTags,omitempty"`

	// SelectApplications    SelectQuery `json:"selectApplications,omitempty"` // not implemented yet
	// SelectDiscoveries     SelectQuery `json:"selectDiscoveries,omitempty"` // not implemented yet
	// SelectDiscoveryRule   SelectQuery `json:"selectDiscoveryRule ,omitempty"` // not implemented yet
	// SelectGraphs          SelectQuery `json:"selectGraphs,omitempty"` // not implemented yet
	SelectHostGroups SelectQuery `json:"selectHostGroups,omitempty"`
	// SelectHostDiscovery   SelectQuery `json:"selectHostDiscovery ,omitempty"` // not implemented yet
	// SelectHTTPTests       SelectQuery `json:"selectHttpTests,omitempty"` // not implemented yet
	SelectInterfaces SelectQuery `json:"selectInterfaces,omitempty"`
	SelectInventory  SelectQuery `json:"selectInventory,omitempty"`
	// SelectItems           SelectQuery `json:"selectItems,omitempty"` // not implemented yet
	SelectMacros          SelectQuery `json:"selectMacros,omitempty"`
	SelectParentTemplates SelectQuery `json:"selectParentTemplates,omitempty"`
	// SelectScreens         SelectQuery `json:"selectScreens,omitempty"` // not implemented yet
	SelectTags          SelectQuery `json:"selectTags,omitempty"`
	SelectInheritedTags SelectQuery `json:"selectInheritedTags,omitempty"`
	// SelectTriggers        SelectQuery `json:"selectTriggers,omitempty"` // not implemented yet
}

// Structure to store creation result
type hostCreateResult struct {
	HostIDs []int `json:"hostids"`
}

// Structure to store updation result
type hostUpdateResult struct {
	HostIDs []int `json:"hostids"`
}

// Structure to store deletion result
type hostDeleteResult struct {
	HostIDs []int `json:"hostids"`
}

// HostGet gets hosts
func (z *Context) HostGet(params HostGetParams) ([]HostObject, int, error) {

	var result []HostObject

	status, err := z.request("host.get", params, &result)
	if err != nil {
		return nil, status, err
	}

	return result, status, nil
}

// HostCreate creates hosts
func (z *Context) HostCreate(params []HostObject) ([]int, int, error) {

	var result hostCreateResult

	status, err := z.request("host.create", params, &result)
	if err != nil {
		return nil, status, err
	}

	return result.HostIDs, status, nil
}

// HostUpdate updates hosts
func (z *Context) HostUpdate(params []HostObject) ([]int, int, error) {

	var result hostUpdateResult

	status, err := z.request("host.update", params, &result)
	if err != nil {
		return nil, status, err
	}

	return result.HostIDs, status, nil
}

// HostDelete deletes hosts
func (z *Context) HostDelete(hostIDs []int) ([]int, int, error) {

	var result hostDeleteResult

	status, err := z.request("host.delete", hostIDs, &result)
	if err != nil {
		return nil, status, err
	}

	return result.HostIDs, status, nil
}
