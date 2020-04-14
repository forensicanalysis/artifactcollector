package collection

import (
	"strings"
	"testing"
)

func TestNormalizeFilePath(t *testing.T) {
	x32 := strings.Repeat("x", 32)
	longFileName := strings.Repeat("long_file_name_", 8)

	pathTests := []struct {
		name              string
		srcPath           string
		normalizedSrcPath string
	}{
		{"Windows path", `/C/Users/user/NTUSER.DAT`, `C_Users_user_NTUSER.DAT`},
		{"Linux path", `/home/username/.bash_history`, `home_username_.bash_history`},
		{
			"Long path",
			`/C/Users/user/AppData/Local/Google/Chrome/User Data/Default/Extensions/` + x32 + `/1.11_1/_metadata/folder_` + x32 + `/` + longFileName + `.json`,
			`C_User_user_AppD_Loca_Goog_Chro_User_Defa_Exte_xxxx_1.11__met_fold_long.json`,
		},
	}

	for _, pt := range pathTests {
		t.Run(pt.name, func(t *testing.T) {
			got := normalizeFilePath(pt.srcPath)

			if got != pt.normalizedSrcPath {
				t.Fatalf("need %v, got %v", pt.normalizedSrcPath, got)
			}
		})
	}
}

func Test_last(t *testing.T) {
	type args struct {
		s string
		n int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"long", args{"abcdef", 2}, "ef"},
		{"short", args{"abc", 4}, "abc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := last(tt.args.s, tt.args.n); got != tt.want {
				t.Errorf("last() = %v, want %v", got, tt.want)
			}
		})
	}
}
