package store

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
)

// MemoryDB is an in-memory implementation of TableAPI for unit testing.
// It uses reflection to read `dynamo` struct tags and stores items as maps,
// mimicking DynamoDB's attribute storage.
type MemoryDB struct {
	data sync.Map
}

// NewMemoryDB creates a new in-memory TableAPI for testing.
func NewMemoryDB() *MemoryDB {
	return &MemoryDB{}
}

// NewMemoryStore is an alias for NewMemoryDB for backward compatibility.
// Deprecated: Use NewMemoryDB instead.
func NewMemoryStore() *MemoryDB {
	return NewMemoryDB()
}

func (m *MemoryDB) Put(_ context.Context, item interface{}) error {
	itemMap, err := structToMap(item)
	if err != nil {
		return fmt.Errorf("failed to convert item to map: %w", err)
	}

	pk, _ := itemMap["PK"].(string)
	sk, _ := itemMap["SK"].(string)
	if pk == "" {
		return fmt.Errorf("item missing PK field")
	}

	key := fmt.Sprintf("%s#%s", pk, sk)
	m.data.Store(key, itemMap)
	return nil
}

func (m *MemoryDB) PutIfNotExists(ctx context.Context, item interface{}) error {
	itemMap, err := structToMap(item)
	if err != nil {
		return fmt.Errorf("failed to convert item to map: %w", err)
	}

	pk, _ := itemMap["PK"].(string)
	sk, _ := itemMap["SK"].(string)
	if pk == "" {
		return fmt.Errorf("item missing PK field")
	}

	key := fmt.Sprintf("%s#%s", pk, sk)
	if _, loaded := m.data.LoadOrStore(key, itemMap); loaded {
		return ErrConditionFailed
	}

	return nil
}

func (m *MemoryDB) Get(_ context.Context, pk, sk string, out interface{}) error {
	key := fmt.Sprintf("%s#%s", pk, sk)

	value, ok := m.data.Load(key)
	if !ok {
		return ErrNotFound
	}

	itemMap, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("stored value is not a map")
	}

	return mapToStruct(itemMap, out)
}

func (m *MemoryDB) Query(_ context.Context, pk string, skPrefix string, out interface{}) error {
	var results []map[string]interface{}

	m.data.Range(func(key, value interface{}) bool {
		keyStr := key.(string)
		// Key format is "PK#SK", check if it starts with pk+"#"
		prefix := pk + "#"
		if !strings.HasPrefix(keyStr, prefix) {
			return true
		}
		if item, ok := value.(map[string]interface{}); ok {
			if skPrefix != "" {
				sk, _ := item["SK"].(string)
				if !strings.HasPrefix(sk, skPrefix) {
					return true
				}
			}
			results = append(results, item)
		}
		return true
	})

	return unmarshalSlice(results, out)
}

func (m *MemoryDB) QueryGSI(_ context.Context, indexName, gsiPK string, out interface{}) error {
	_ = indexName // MemoryDB ignores index name, scans all items.

	var results []map[string]interface{}

	m.data.Range(func(key, value interface{}) bool {
		if item, ok := value.(map[string]interface{}); ok {
			if pk, pkOk := item["GSI1PK"].(string); pkOk && pk == gsiPK {
				results = append(results, item)
			}
		}
		return true
	})

	return unmarshalSlice(results, out)
}

func (m *MemoryDB) Delete(_ context.Context, pk, sk string) error {
	key := fmt.Sprintf("%s#%s", pk, sk)
	m.data.Delete(key)
	return nil
}

// ScanByPKPrefix scans all items whose PK starts with the given prefix and
// unmarshals them into the slice pointed to by out.
func (m *MemoryDB) ScanByPKPrefix(_ context.Context, prefix string, out interface{}) error {
	var results []map[string]interface{}

	m.data.Range(func(key, value interface{}) bool {
		if item, ok := value.(map[string]interface{}); ok {
			if pk, pkOk := item["PK"].(string); pkOk && strings.HasPrefix(pk, prefix) {
				results = append(results, item)
			}
		}
		return true
	})

	return unmarshalSlice(results, out)
}

// ---------- helper functions ----------

// structToMap converts a struct to a map using dynamo tags and json tags.
func structToMap(item interface{}) (map[string]interface{}, error) {
	data, err := json.Marshal(item)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	// Add fields that have dynamo tags but json:"-" (e.g. PK, SK, GSI keys).
	addDynamoFields(reflect.ValueOf(item), result)

	return result, nil
}

// addDynamoFields walks the struct (including embedded/anonymous fields) and
// adds any field with a dynamo tag to the result map.
func addDynamoFields(v reflect.Value, result map[string]interface{}) {
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return
	}
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldValue := v.Field(i)

		// Recurse into embedded (anonymous) struct fields.
		if field.Anonymous && fieldValue.Kind() == reflect.Struct {
			addDynamoFields(fieldValue, result)
			continue
		}

		dynamoTag := field.Tag.Get("dynamo")
		if dynamoTag == "" {
			continue
		}

		// Extract field name from dynamo tag (before comma).
		tagName := dynamoTag
		if idx := strings.Index(dynamoTag, ","); idx != -1 {
			tagName = dynamoTag[:idx]
		}

		if fieldValue.IsValid() && fieldValue.CanInterface() {
			result[tagName] = fieldValue.Interface()
		}
	}
}

// mapToStruct populates a struct from a map using dynamo tags for field
// mapping, falling back to json tags.
func mapToStruct(m map[string]interface{}, out interface{}) error {
	// Standard json round-trip to fill json-tagged fields.
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("failed to marshal stored item: %w", err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("failed to unmarshal to output: %w", err)
	}

	// Fill fields that have dynamo tags but json:"-".
	v := reflect.ValueOf(out)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}

	fillDynamoFields(v, m)
	return nil
}

// fillDynamoFields walks the struct (including embedded/anonymous fields) and
// sets any field that has json:"-" but a valid dynamo tag, using values
// from the map.
func fillDynamoFields(v reflect.Value, m map[string]interface{}) {
	if v.Kind() != reflect.Struct {
		return
	}
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldVal := v.Field(i)

		// Recurse into embedded (anonymous) struct fields.
		if field.Anonymous && fieldVal.Kind() == reflect.Struct {
			fillDynamoFields(fieldVal, m)
			continue
		}

		jsonTag := field.Tag.Get("json")
		if jsonTag != "-" {
			continue // already handled by json.Unmarshal
		}

		dynamoTag := field.Tag.Get("dynamo")
		if dynamoTag == "" {
			continue
		}
		tagName := dynamoTag
		if idx := strings.Index(dynamoTag, ","); idx != -1 {
			tagName = dynamoTag[:idx]
		}

		val, ok := m[tagName]
		if !ok {
			continue
		}

		if !fieldVal.CanSet() {
			continue
		}

		// Handle string fields (covers cert PEMs, SK, GSI keys, etc.)
		if fieldVal.Kind() == reflect.String {
			if s, ok := val.(string); ok {
				fieldVal.SetString(s)
			}
		}
	}
}

// unmarshalSlice takes a slice of maps and unmarshals each into the slice
// pointed to by out (which must be a pointer to a slice of structs).
func unmarshalSlice(results []map[string]interface{}, out interface{}) error {
	outVal := reflect.ValueOf(out)
	if outVal.Kind() != reflect.Pointer || outVal.Elem().Kind() != reflect.Slice {
		return fmt.Errorf("out must be a pointer to a slice")
	}

	sliceVal := outVal.Elem()
	elemType := sliceVal.Type().Elem()

	for _, item := range results {
		elemPtr := reflect.New(elemType)
		if err := mapToStruct(item, elemPtr.Interface()); err != nil {
			continue
		}
		sliceVal = reflect.Append(sliceVal, elemPtr.Elem())
	}

	outVal.Elem().Set(sliceVal)
	return nil
}
