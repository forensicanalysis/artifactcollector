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

package run

import (
	"time"

	"github.com/forensicanalysis/forensicstore"
)

type storeLogger struct {
	store *forensicstore.ForensicStore
}

func newStoreLogger(store *forensicstore.ForensicStore) (*storeLogger, error) {
	_, err := store.Query(`CREATE TABLE IF NOT EXISTS logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		msg TEXT NOT NULL,
		insert_time TEXT NOT NULL,
	);`)
	return &storeLogger{store: store}, err
}

func (s *storeLogger) Write(b []byte) (int, error) {
	conn := s.store.Connection()

	stmt, err := conn.Prepare("INSERT INTO `logs` (msg, insert_time) VALUES ($msg, $time)")
	if err != nil {
		return len(b), err
	}

	stmt.SetText("$msg", string(b))
	stmt.SetText("$time", time.Now().UTC().Format(time.RFC3339Nano))

	_, err = stmt.Step()
	if err != nil {
		return len(b), err
	}

	return len(b), stmt.Finalize()
}
