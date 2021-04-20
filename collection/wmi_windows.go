// Copyright (c) 2013 Stack Exchange
// Copyright (c) 2019 Siemens AG
// Copyright (c) 2021 Jonas Plum
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
	"time"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

// WMIQuery runs a WMI query and returns the result as a map.
func WMIQuery(q string) ([]map[string]interface{}, error) {
	resultsChan := make(chan []map[string]interface{}, 1)
	errChan := make(chan error, 1)
	go wmiRun(resultsChan, errChan, q)

	select {
	case result := <-resultsChan:
		return result, nil
	case err := <-errChan:
		return nil, err
	case <-time.After(10 * time.Second):
		return nil, fmt.Errorf("timeout")
	}
}

func wmiRun(resultsChan chan []map[string]interface{}, errChan chan error, q string) {
	// init COM, oh yeah
	err := ole.CoInitialize(0)
	if err != nil {
		errChan <- err
		return
	}
	defer ole.CoUninitialize()

	unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		errChan <- err
		return
	}
	defer unknown.Release()

	wmi, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		errChan <- err
		return
	}
	defer wmi.Release()

	// service is a SWbemServices
	serviceRaw, err := oleutil.CallMethod(wmi, "ConnectServer")
	if err != nil {
		errChan <- err
		return
	}
	service := serviceRaw.ToIDispatch()
	defer service.Release()

	// result is a SWBemObjectSet
	resultRaw, err := oleutil.CallMethod(service, "ExecQuery", q)
	if err != nil {
		errChan <- err
		return
	}
	result := resultRaw.ToIDispatch()
	defer result.Release()

	// list of results
	enumProperty, err := oleutil.GetProperty(result, "_NewEnum")
	if err != nil {
		errChan <- err
		return
	}
	defer enumProperty.Clear() //nolint:errcheck

	enum, err := enumProperty.ToIUnknown().IEnumVARIANT(ole.IID_IEnumVariant)
	if err != nil {
		errChan <- err
		return
	}
	if enum == nil {
		errChan <- fmt.Errorf("can't get IEnumVARIANT, enum is nil")
		return
	}
	defer enum.Release()

	i := 0
	// iterate results
	var wmiResults []map[string]interface{}
	for elementRaw, length, err := enum.Next(1); length > 0; elementRaw, length, err = enum.Next(1) {
		if err != nil {
			errChan <- err
			return
		}
		wmiResult, err := parseElement(elementRaw)
		if err != nil {
			errChan <- err
			return
		}
		wmiResults = append(wmiResults, wmiResult)

		i++
	}
	resultsChan <- wmiResults
	return
}

func parseElement(elementRaw ole.VARIANT) (map[string]interface{}, error) {
	wmiResult := map[string]interface{}{}

	// element is a SWbemObject, but really a Win32_Process
	element := elementRaw.ToIDispatch()
	defer element.Release()

	// get properties of result
	rawProperties, err := oleutil.GetProperty(element, "Properties_")
	if err != nil {
		return nil, err
	}
	properties := rawProperties.ToIDispatch()
	defer properties.Release()

	err = oleutil.ForEach(properties, func(v *ole.VARIANT) error {
		propertyName, err := oleutil.GetProperty(v.ToIDispatch(), "Name")
		if err != nil {
			return err
		}
		property, err := oleutil.GetProperty(element, propertyName.ToString())
		if err != nil {
			return err
		}
		value := ""
		if property.Value() != nil {
			value = fmt.Sprint(property.Value())
		}
		wmiResult[propertyName.ToString()] = value
		return nil
	})
	return wmiResult, err
}
