// Copyright The NRI Plugins Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cxl

import (
	"fmt"
	"os"
	"strings"
)

type MissingFile struct{ error }
type UnreadableFile struct{ error }
type MissingLine struct{ error }

type parser struct {
	fileCache        map[string]string
	ignoreErrorTypes map[string]bool
}

type parseable interface {
	parse(p *parser) error
}

type sscanfSpec struct {
	filepath string
	format   string
	dests    []any
}

func (sf *sscanfSpec) parse(p *parser) error {
	var err error
	data, err := p.getFileContent(sf.filepath)
	if err != nil {
		return err
	}
	for line := range strings.SplitSeq(data, "\n") {
		_, err = fmt.Sscanf(line, sf.format, sf.dests...)
		if err == nil {
			return nil
		}
	}
	return MissingLine{fmt.Errorf("failed to parse %s: no line matches format %q", sf.filepath, sf.format)}
}

func parseWithSscanf(filepath, format string, dests ...any) parseable {
	return &sscanfSpec{
		filepath: filepath,
		format:   format,
		dests:    dests,
	}
}

func parseIgnoring(errors ...error) parseable {
	errorTypes := make(map[string]bool)
	for _, err := range errors {
		errType := fmt.Sprintf("%T", err)
		errorTypes[errType] = true
	}
	return &ignoreErrorsSpec{
		errorTypes: errorTypes,
	}
}

type ignoreErrorsSpec struct {
	errorTypes map[string]bool
}

func (ies *ignoreErrorsSpec) parse(p *parser) error {
	p.ignoreErrorTypes = ies.errorTypes
	return nil
}

func (p *parser) getFileContent(filepath string) (string, error) {
	data, ok := p.fileCache[filepath]
	if !ok {
		dataBytes, err := os.ReadFile(filepath)
		if os.IsNotExist(err) {
			return "", MissingFile{fmt.Errorf("file %s does not exist: %w", filepath, err)}
		}
		if err != nil {
			return "", UnreadableFile{fmt.Errorf("failed to read %s: %w", filepath, err)}
		}
		data = strings.TrimSpace(string(dataBytes))
		p.fileCache[filepath] = data
	}
	return data, nil
}

func parse(parseTasks ...parseable) error {
	p := &parser{
		fileCache:        map[string]string{},
		ignoreErrorTypes: map[string]bool{},
	}
	return p.parse(parseTasks...)
}

func (p *parser) parse(parseTasks ...parseable) error {
	for _, pt := range parseTasks {
		if err := pt.parse(p); err != nil {
			if p.isIgnored(err) {
				continue
			}
			return err
		}
	}
	return nil
}

func (p *parser) isIgnored(err error) bool {
	// compare only error types
	errType := fmt.Sprintf("%T", err)
	return p.ignoreErrorTypes[errType]
}
