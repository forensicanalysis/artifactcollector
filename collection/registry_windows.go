// +build go1.8

// Copyright (c) 2019 Siemens AG
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// Author(s): Jonas Plum

package collection

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

func (c *LiveCollector) createRegistryKey(definitionName, key string) *RegistryKey {
	k, rk := c.createEmptyRegistryKey(definitionName, key)
	defer k.Close()

	values, errs := c.getValues(k)
	for _, err := range errs {
		rk.AddError(err.Error())
	}
	rk.Values = values
	return rk
}

func (c *LiveCollector) createRegistryValue(definitionName, key, valueName string) *RegistryKey {
	k, rk := c.createEmptyRegistryKey(definitionName, key)
	defer k.Close()

	value, err := c.getValue(k, valueName)
	if err != nil {
		rk.AddError(err.Error())
	} else {
		rk.Values = []RegistryValue{value}
	}

	return rk
}

func getRegistryKey(key string) (string, *registry.Key, error) {
	registryMap := map[string]registry.Key{
		"HKEY_CLASSES_ROOT":     registry.CLASSES_ROOT,
		"HKEY_CURRENT_USER":     registry.CURRENT_USER,
		"HKEY_LOCAL_MACHINE":    registry.LOCAL_MACHINE,
		"HKEY_USERS":            registry.USERS,
		"HKEY_CURRENT_CONFIG":   registry.CURRENT_CONFIG,
		"HKEY_PERFORMANCE_DATA": registry.PERFORMANCE_DATA,
	}
	key = strings.Trim(key, "/")
	key = strings.Replace(key, "/", `\`, -1)
	keyparts := strings.SplitN(key, `\`, 2)
	if len(keyparts) != 2 { //nolint:gomnd
		return key, nil, fmt.Errorf("wrong number of keyparts %s", keyparts)
	}
	k, err := registry.OpenKey(registryMap[keyparts[0]], keyparts[1], registry.READ|registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return key, &k, fmt.Errorf("could not open key: %w", err)
	}
	return key, &k, nil
}

func (c *LiveCollector) createEmptyRegistryKey(name string, fskey string) (*registry.Key, *RegistryKey) {
	rk := NewRegistryKey()
	rk.Artifact = name
	rk.Values = []RegistryValue{}
	// get registry key
	cleankey, k, err := getRegistryKey(fskey)
	rk.Key = cleankey
	if err != nil {
		rk.Errors = append(rk.Errors, err.Error())
		return k, rk
	}

	info, err := k.Stat()
	if err != nil {
		rk.Errors = append(rk.Errors, err.Error())
	} else {
		rk.ModifiedTime = info.ModTime().UTC().Format(time.RFC3339Nano)
	}
	return k, rk
}

func (c *LiveCollector) getValues(k *registry.Key) (values []RegistryValue, valueErrors []error) {
	// get registry key stats
	ki, err := k.Stat()
	if err != nil {
		return nil, []error{fmt.Errorf("could not stat: %w", err)}
	}

	if ki.ValueCount > 0 {
		valuenames, err := k.ReadValueNames(int(ki.ValueCount))
		if err != nil {
			return nil, []error{fmt.Errorf("could not read value names: %w", err)}
		}

		for _, valuename := range valuenames {
			value, err := c.getValue(k, valuename)
			if err != nil {
				valueErrors = append(valueErrors, err)
			} else {
				values = append(values, value)
			}
		}
	}

	return values, valueErrors
}

func (c *LiveCollector) getValue(k *registry.Key, valueName string) (value RegistryValue, err error) {
	dataType, _, _, stringData, err := valueData(k, valueName)
	if err != nil {
		return value, fmt.Errorf("could not parse registry data: %w", err)
	}
	if valueName == "" {
		valueName = "(Default)"
	}
	return RegistryValue{Name: valueName, Data: stringData, DataType: dataType}, nil
}

func valueData(rk *registry.Key, name string) (dataType string, bytesData []byte, data interface{}, stringData string, err error) {
	size, valtype, err := rk.GetValue(name, nil)
	if err != nil {
		return "", nil, nil, "", err
	}

	bytesData = make([]byte, size)
	_, _, err = rk.GetValue(name, bytesData)
	if err != nil {
		return "", nil, nil, "", err
	}

	dataType, err = getValueTypeString(valtype)
	if err != nil {
		return "", nil, nil, "", err
	}

	switch valtype {
	case registry.SZ, registry.EXPAND_SZ:
		stringData, _, err = rk.GetStringValue(name)
		data = stringData
	case registry.NONE, registry.BINARY:
		data, _, err = rk.GetBinaryValue(name)
		stringData = fmt.Sprintf("% x", data)
	case registry.QWORD, registry.DWORD:
		data, _, err = rk.GetIntegerValue(name)
		stringData = fmt.Sprintf("%d", data)
	case registry.MULTI_SZ:
		data, _, err = rk.GetStringsValue(name)
		stringData = strings.Join(data.([]string), " ")
	case registry.DWORD_BIG_ENDIAN, registry.LINK, registry.RESOURCE_LIST, registry.FULL_RESOURCE_DESCRIPTOR,
		registry.RESOURCE_REQUIREMENTS_LIST:
		fallthrough
	default:
		data = bytesData
		stringData = fmt.Sprintf("% x", bytesData)
	}
	return dataType, bytesData, data, stringData, err
}

func getValueTypeString(valtype uint32) (string, error) {
	types := map[uint32]string{
		registry.NONE:                       "REG_NONE",
		registry.SZ:                         "REG_SZ",
		registry.EXPAND_SZ:                  "REG_EXPAND_SZ",
		registry.BINARY:                     "REG_BINARY",
		registry.DWORD:                      "REG_DWORD",
		registry.DWORD_BIG_ENDIAN:           "REG_DWORD_BIG_ENDIAN",
		registry.LINK:                       "REG_LINK",
		registry.MULTI_SZ:                   "REG_MULTI_SZ",
		registry.RESOURCE_LIST:              "REG_RESOURCE_LIST",
		registry.FULL_RESOURCE_DESCRIPTOR:   "REG_FULL_RESOURCE_DESCRIPTOR",
		registry.RESOURCE_REQUIREMENTS_LIST: "REG_RESOURCE_REQUIREMENTS_LIST",
		registry.QWORD:                      "REG_QWORD",
	}
	if s, ok := types[valtype]; ok {
		return s, nil
	}
	return "", errors.New("value type not found")
}
