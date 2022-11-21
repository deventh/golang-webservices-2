package main

import (
	"errors"
	"fmt"
	"reflect"
)

func i2s(data interface{}, out interface{}) error {
	outValue := reflect.ValueOf(out)
	dataType := reflect.ValueOf(data).Type()

	if dataType.Kind() == reflect.Slice {
		if outValue.Type().Kind() == reflect.Ptr && outValue.Elem().Type().Kind() != reflect.Slice {
			return errors.New(fmt.Sprintf("Types mismatch %s and %s", dataType.Kind(), outValue.Type().Kind()))
		}
		err := mappingSlice(outValue.Elem(), data.([]interface{}))
		if err != nil {
			return err
		}
	} else {
		if outValue.Type().Kind() != reflect.Ptr {
			return errors.New("Pointer is expected")
		}
		err := mapping(data.(map[string]interface{}), outValue)
		if err != nil {
			return err
		}
	}
	return nil
}

func mapping(dataMap map[string]interface{}, outValue reflect.Value) error {
	for name, value := range dataMap {
		outFieldType := outValue
		if outFieldType.Type().Kind() == reflect.Ptr {
			outFieldType = outFieldType.Elem()
		}
		outFieldByName := outFieldType.FieldByName(name)

		kind := reflect.ValueOf(value).Kind()
		switch kind {
		case reflect.String:
			if outFieldByName.Kind() != kind {
				return errors.New(fmt.Sprintf("Types mismatch %s and %s", outFieldByName.Kind(), kind))
			}
			outFieldByName.SetString(value.(string))
		case reflect.Float64:
			// check target field type for float32/64 because of JSON marshalling (always float)
			f := value.(float64)
			switch outFieldByName.Kind() {
			case reflect.Int, reflect.Int64:
				outFieldByName.SetInt(int64(f))
			case reflect.Float32, reflect.Float64:
				outFieldByName.SetFloat(f)
			case reflect.String:
				return errors.New(fmt.Sprintf("Types mismatch %s and %s", outFieldByName.Kind(), kind))
			}
		case reflect.Int:
			if outFieldByName.Kind() != kind {
				return errors.New(fmt.Sprintf("Types mismatch %s and %s", outFieldByName.Kind(), kind))
			}
			outFieldByName.SetInt(value.(int64))
		case reflect.Map:
			if outFieldByName.Kind() != reflect.Struct {
				return errors.New(fmt.Sprintf("Types mismatch %s and %s", outFieldByName.Kind(), kind))
			}
			err := mapping(value.(map[string]interface{}), outFieldByName)
			if err != nil {
				return err
			}
		case reflect.Bool:
			if outFieldByName.Kind() != kind {
				return errors.New(fmt.Sprintf("Types mismatch %s and %s", outFieldByName.Kind(), kind))
			}
			outFieldByName.SetBool(value.(bool))
		case reflect.Slice:
			dataElems := value.([]interface{})
			err := mappingSlice(outFieldByName, dataElems)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func mappingSlice(outValue reflect.Value, dataElems []interface{}) error {
	outValue.Set(reflect.MakeSlice(outValue.Type(), len(dataElems), len(dataElems)))
	for i, _ := range dataElems {
		e := outValue.Type().Elem()
		elementPointer := reflect.New(e)
		err := mapping(dataElems[i].(map[string]interface{}), elementPointer)
		if err != nil {
			return err
		}
		outValue.Index(i).Set(elementPointer.Elem())
	}
	return nil
}
