package collection

import "testing"

func TestNormalizeFileName(t *testing.T) {
	pathTests := []struct {
		srcPath           string
		normalizedSrcPath string
	}{
		{`/C/Users/user/NTUSER.DAT`, `_C_Users_user_NTUSER.DAT`},
		{`/home/username/.bash_history`, `_home_username_.bash_history`},
		{`/C/Users/user/AppData/Local/Google/Chrome/User Data/Default/Extensions/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/1.11_1/_metadata/folder_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/long_file_name_long_file_name_long_file_name_long_file_name_long_file_name_long_file_name_long_file_name_long_file_name.json`, `ogle_Chrome_User Data_Default_Extensions_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx_1.11_1__metadata_folder_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx_long_file_name_long_file_name_long_file_name_long_file_name_long_file_name_long_file_name_long_file_name_long_file_name.json`},
	}

	for _, pt := range pathTests {
		got := normalizeFileName(pt.srcPath)
		if got != pt.normalizedSrcPath {
			t.Fatalf("need %v, got %v", pt.normalizedSrcPath, got)
		}
	}
}
