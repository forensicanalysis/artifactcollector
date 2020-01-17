package collection

import (
	"reflect"
	"testing"
)

func Test_replaces(t *testing.T) {
	type args struct {
		s    string
		old  string
		news []string
	}
	tests := []struct {
		name   string
		args   args
		wantSs []string
	}{
		{"Replace single", args{"foo", "o", []string{"a"}}, []string{"faa"}},
		{"Replace multi", args{"bar", "a", []string{"aa", "uu"}}, []string{"baar", "buur"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotSs := replaces(tt.args.s, tt.args.old, tt.args.news); !reflect.DeepEqual(gotSs, tt.wantSs) {
				t.Errorf("replaces() = %v, want %v", gotSs, tt.wantSs)
			}
		})
	}
}
