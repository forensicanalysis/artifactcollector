// Copyright (c) 2013 Stack Exchange
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
// This code was adapted from
// https://github.com/StackExchange/wmi/blob/master/swbemservices.go

package collection

import (
	"fmt"
	"log"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

// WMIQuery runs a WMI query and returns the result as a map.
func WMIQuery(q string) (wmiResult []map[string]interface{}, err error) {
	// init COM, oh yeah
	err = ole.CoInitialize(0)
	if err != nil {
		return wmiResult, err
	}
	defer ole.CoUninitialize()

	unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		log.Panic(err)
	}
	defer unknown.Release()

	wmi, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		log.Panic(err)
	}
	defer wmi.Release()

	// service is a SWbemServices
	serviceRaw, err := oleutil.CallMethod(wmi, "ConnectServer")
	if err != nil {
		return wmiResult, err
	}
	service := serviceRaw.ToIDispatch()
	defer service.Release()

	// result is a SWBemObjectSet
	resultRaw, err := oleutil.CallMethod(service, "ExecQuery", q)
	if err != nil {
		return wmiResult, err
	}
	result := resultRaw.ToIDispatch()
	defer result.Release()

	// list of results
	enumProperty, err := oleutil.GetProperty(result, "_NewEnum")
	if err != nil {
		return wmiResult, err
	}
	defer enumProperty.Clear() //nolint:errcheck

	enum, err := enumProperty.ToIUnknown().IEnumVARIANT(ole.IID_IEnumVariant)
	if err != nil {
		return wmiResult, err
	}
	if enum == nil {
		log.Fatal(fmt.Errorf("can't get IEnumVARIANT, enum is nil"))
	}
	defer enum.Release()

	i := 0
	// iterate results
	for itemRaw, length, err := enum.Next(1); length > 0; itemRaw, length, err = enum.Next(1) {
		if err != nil {
			log.Fatal(err)
		}
		wmiResult = append(wmiResult, map[string]interface{}{})

		// item is a SWbemObject, but really a Win32_Process
		item := itemRaw.ToIDispatch()
		defer item.Release()

		// get properties of result
		rawProperties, err := oleutil.GetProperty(item, "Properties_")
		if err != nil {
			return wmiResult, err
		}
		properties := rawProperties.ToIDispatch()
		defer properties.Release()

		err = oleutil.ForEach(properties, func(v *ole.VARIANT) error {
			propertyName, err := oleutil.GetProperty(v.ToIDispatch(), "Name")
			if err != nil {
				return err
			}
			property, err := oleutil.GetProperty(item, propertyName.ToString())
			if err != nil {
				return err
			}
			value := ""
			if property.Value() != nil {
				value = fmt.Sprint(property.Value())
			}
			wmiResult[i][propertyName.ToString()] = value
			return nil
		})
		if err != nil {
			return wmiResult, err
		}

		i++
	}
	return
}
