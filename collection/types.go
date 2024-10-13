package collection

import (
	"log"

	"github.com/google/uuid"
)

// File implements a STIX 2.1 File Object.
type File struct {
	ID         string                 `json:"id"`
	Artifact   string                 `json:"artifact,omitempty"`
	Type       string                 `json:"type"`
	Hashes     map[string]interface{} `json:"hashes,omitempty"`
	Size       float64                `json:"size,omitempty"`
	Name       string                 `json:"name"`
	Ctime      string                 `json:"ctime,omitempty"`
	Mtime      string                 `json:"mtime,omitempty"`
	Atime      string                 `json:"atime,omitempty"`
	Origin     map[string]interface{} `json:"origin,omitempty"`
	ExportPath string                 `json:"export_path,omitempty"`
	Errors     []interface{}          `json:"errors,omitempty"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

// NewFile creates a new STIX 2.1 File Object.
func NewFile() *File {
	return &File{ID: "file--" + uuid.New().String(), Type: "file"}
}

// AddError adds an error string to a File and returns this File.
func (i *File) AddError(err string) *File {
	log.Print(err)
	i.Errors = append(i.Errors, err)

	return i
}

// Directory implements a STIX 2.1 Directory Object.
type Directory struct {
	ID       string        `json:"id"`
	Artifact string        `json:"artifact,omitempty"`
	Type     string        `json:"type"`
	Path     string        `json:"path"`
	Ctime    string        `json:"ctime,omitempty"`
	Mtime    string        `json:"mtime,omitempty"`
	Atime    string        `json:"atime,omitempty"`
	Errors   []interface{} `json:"errors,omitempty"`
}

// NewDirectory creates a new STIX 2.1 Directory Object.
func NewDirectory() *Directory {
	return &Directory{ID: "directory--" + uuid.New().String(), Type: "directory"}
}

// AddError adds an error string to a Directory and returns this Directory.
func (i *Directory) AddError(err string) *Directory {
	log.Print(err)
	i.Errors = append(i.Errors, err)

	return i
}

// RegistryValue implements a STIX 2.1 Windows™ Registry Value Type.
type RegistryValue struct {
	Name     string        `json:"name"`
	Data     string        `json:"data,omitempty"`
	DataType string        `json:"data_type,omitempty"`
	Errors   []interface{} `json:"errors,omitempty"`
}

// NewRegistryValue creates a new STIX 2.1 Windows™ Registry Value Type.
func NewRegistryValue() *RegistryValue {
	return &RegistryValue{}
}

// AddError adds an error string to a RegistryValue and returns this RegistryValue.
func (i *RegistryValue) AddError(err string) *RegistryValue {
	log.Print(err)
	i.Errors = append(i.Errors, err)

	return i
}

// RegistryKey implements a STIX 2.1 Windows™ Registry Key Object.
type RegistryKey struct {
	ID           string          `json:"id"`
	Artifact     string          `json:"artifact,omitempty"`
	Type         string          `json:"type"`
	Key          string          `json:"key"`
	Values       []RegistryValue `json:"values,omitempty"`
	ModifiedTime string          `json:"modified_time,omitempty"`
	Errors       []interface{}   `json:"errors,omitempty"`
}

// NewRegistryKey creates a new STIX 2.1 Windows™ Registry Key Object.
func NewRegistryKey() *RegistryKey {
	return &RegistryKey{ID: "windows-registry-key--" + uuid.New().String(), Type: "windows-registry-key"}
}

// AddError adds an error string to a RegistryKey and returns this RegistryKey.
func (i *RegistryKey) AddError(err string) *RegistryKey {
	log.Print(err)
	i.Errors = append(i.Errors, err)

	return i
}

// Process implements a STIX 2.1 Process Object.
type Process struct {
	ID          string        `json:"id"`
	Artifact    string        `json:"artifact,omitempty"`
	Type        string        `json:"type"`
	Name        string        `json:"name,omitempty"`
	CreatedTime string        `json:"created_time,omitempty"`
	Cwd         string        `json:"cwd,omitempty"`
	CommandLine string        `json:"command_line,omitempty"`
	StdoutPath  string        `json:"stdout_path,omitempty"`
	StderrPath  string        `json:"stderr_path,omitempty"`
	WMI         []interface{} `json:"wmi,omitempty"`
	ReturnCode  float64       `json:"return_code,omitempty"`
	Errors      []interface{} `json:"errors,omitempty"`
}

// NewProcess creates a new STIX 2.1 Process Object.
func NewProcess() *Process {
	return &Process{ID: "process--" + uuid.New().String(), Type: "process"}
}

// AddError adds an error string to a Process and returns this Process.
func (i *Process) AddError(err string) *Process {
	log.Print(err)
	i.Errors = append(i.Errors, err)

	return i
}
