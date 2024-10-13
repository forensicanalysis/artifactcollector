package goartifacts

import (
	"reflect"
	"testing"
)

func Test_toForensicPath(t *testing.T) {
	type args struct {
		name     string
		prefixes []string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{"simple", args{name: `C:\Windows`, prefixes: []string{"C", "D"}}, []string{"C/Windows"}, false},
		{"no partition", args{name: `\Windows`, prefixes: []string{"C", "D"}}, []string{"C/Windows", "D/Windows"}, false},
		{"no partition", args{name: `/Windows`, prefixes: []string{"C", "D"}}, []string{"C/Windows", "D/Windows"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := toForensicPath(tt.args.name, tt.args.prefixes)
			if (err != nil) != tt.wantErr {
				t.Errorf("toForensicPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("toForensicPath() got = %v, want %v", got, tt.want)
			}
		})
	}
}
