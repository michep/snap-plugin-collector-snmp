// +build linux

/*
http://www.apache.org/licenses/LICENSE-2.0.txt


Copyright 2016 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package snmp

import (
	"fmt"
	"strings"
	"time"

	"github.com/intelsdi-x/snap-plugin-collector-snmp/collector/configReader"
	"github.com/soniah/gosnmp"
)

func NewHandler(agentConfig configReader.SnmpAgent) (*gosnmp.GoSNMP, error) {
	handler := gosnmp.Default

	handler.Target = strings.Split(agentConfig.Address, ":")[0]
	handler.Community = agentConfig.Community
	handler.Version = getSNMPVersion(agentConfig.SnmpVersion)
	handler.Timeout = time.Duration(agentConfig.Timeout) * time.Second
	handler.Retries = int(agentConfig.Retries)

	//handler, err := gosnmp.NewGoSNMP(gosnmp.SNMPArguments{
	//	Version:          getSNMPVersion(agentConfig.SnmpVersion),
	//	Network:          agentConfig.Network,
	//	Address:          agentConfig.Address,
	//	Timeout:          time.Duration(agentConfig.Timeout) * time.Second,
	//	Retries:          agentConfig.Retries,
	//	Community:        agentConfig.Community,
	//	UserName:         agentConfig.UserName,
	//	SecurityLevel:    getSNMPSecurityLevel(agentConfig.SecurityLevel),
	//	AuthPassword:     agentConfig.AuthPassword,
	//	AuthProtocol:     getSNMPAuthProtocol(agentConfig.AuthProtocol),
	//	PrivPassword:     agentConfig.PrivPassword,
	//	PrivProtocol:     getPrivProtocol(agentConfig.PrivProtocol),
	//	SecurityEngineId: agentConfig.SecurityEngineId,
	//	ContextEngineId:  agentConfig.ContextEngineId,
	//	ContextName:      agentConfig.ContextName,
	//})

	err := handler.Connect()
	if err != nil {
		return nil, err
	}
	return handler, nil
}

func ReadElements(handler *gosnmp.GoSNMP, oid string, mode string) ([]gosnmp.SnmpPDU, error) {
	//results received through SNMP requests
	results := []gosnmp.SnmpPDU{}

	defer handler.Conn.Close()
	if err := handler.Connect(); err != nil {
		// Failed to open connection
		return results, err
	}

	var err error
	var sp *gosnmp.SnmpPacket
	switch mode {
	case configReader.ModeSingle:
		sp, err = handler.Get([]string{oid})
		if err != nil {
			// Failed to request
			return results, err
		}
		if sp.Error != gosnmp.NoError {
			// Received an error from the agent
			return results, fmt.Errorf("Received an error from the SNMP agent: %v", sp.Error)
		}
		results = sp.Variables
	case configReader.ModeTable, configReader.ModeWalk:
		results, err = handler.BulkWalkAll(oid)
		if len(results) == 1 && results[0].Type == gosnmp.NoSuchObject {
			return []gosnmp.SnmpPDU{}, nil
		}
	}
	if err != nil {
		// Failed to request
		return results, err
	}

	return results, nil
}

func getSNMPVersion(s string) gosnmp.SnmpVersion {
	var snmpVersion gosnmp.SnmpVersion
	switch s {
	case "v1":
		snmpVersion = gosnmp.Version1
	case "v2c":
		snmpVersion = gosnmp.Version2c
	case "v3":
		snmpVersion = gosnmp.Version3
	}
	return snmpVersion
}

func getSNMPSecurityLevel(s string) gosnmp.SnmpV3MsgFlags {
	var securitylevel gosnmp.SnmpV3MsgFlags
	switch s {
	case "NoAuthNoPriv":
		securitylevel = gosnmp.NoAuthNoPriv
	case "AuthNoPriv":
		securitylevel = gosnmp.AuthNoPriv
	case "AuthPriv":
		securitylevel = gosnmp.AuthPriv
	}
	return securitylevel
}
func getSNMPAuthProtocol(s string) gosnmp.SnmpV3AuthProtocol {
	var authProtocol gosnmp.SnmpV3AuthProtocol
	switch s {
	case "MD5":
		authProtocol = gosnmp.MD5
	case "SHA":
		authProtocol = gosnmp.SHA
	}
	return authProtocol
}

func getPrivProtocol(s string) gosnmp.SnmpV3PrivProtocol {
	var privProtocol gosnmp.SnmpV3PrivProtocol
	switch s {
	case "DES":
		privProtocol = gosnmp.DES
	case "AES":
		privProtocol = gosnmp.AES
	}
	return privProtocol
}
