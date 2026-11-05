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

// gostats prints per-function length and approximate cyclomatic complexity,
// the struct fields that recur across structs, and the mutexes of the non-test
// Go files of the directories given as arguments. With -r it descends into
// subdirectories and ends with a summary over all of them, checked against the
// limits given as flags. With -gate a limit that is exceeded makes it exit 1.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type fn struct {
	name  string
	file  string
	line  int
	lines int
	cyclo int
}

type structInfo struct {
	name   string
	file   string
	fields []string
}

type mutex struct {
	owner string
	file  string
	line  int
}

type stats struct {
	dir     string
	lines   int
	fns     []fn
	structs []structInfo
	mutexes []mutex
}

// accessFields are the field names that describe how a device is accessed.
var accessFields = []string{"Mode", "ReadOnly", "Access", "FsType"}

var (
	recursive  = flag.Bool("r", false, "descend into subdirectories and print a summary")
	gate       = flag.Bool("gate", false, "exit 1 when a limit is exceeded")
	maxLines   = flag.Int("max-lines", 0, "limit of non-test lines (0: none)")
	maxCyclo15 = flag.Int("max-cyclo15", -1, "limit of functions over cyclomatic 15 (-1: none)")
	maxCyclo30 = flag.Int("max-cyclo30", -1, "limit of functions over cyclomatic 30 outside -keep files (-1: none)")
	maxMutexes = flag.Int("max-mutexes", -1, "limit of sync.Mutex and sync.RWMutex fields and variables (-1: none)")
	maxAccess  = flag.Int("max-access-structs", -1, "limit of structs with a Mode, ReadOnly, Access or FsType field (-1: none)")
	keepFiles  = flag.String("keep", "", "comma-separated file names exempt from -max-cyclo30")

	// failed is set when a file or directory cannot be read.
	failed = false
	// keep holds the file names of -keep.
	keep = map[string]bool{}
)

func main() {
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "usage: %s [flags] dir...\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	for _, f := range strings.Split(*keepFiles, ",") {
		if f != "" {
			keep[f] = true
		}
	}

	var all []*stats
	for _, root := range flag.Args() {
		for _, dir := range dirs(root) {
			s := analyse(dir)
			if s == nil {
				continue
			}
			report(s)
			all = append(all, s)
		}
	}

	exceeded := false
	if *recursive {
		exceeded = summary(all)
	}
	if failed {
		os.Exit(1)
	}
	if exceeded && *gate {
		os.Exit(1)
	}
}

// dirs returns root, and with -r every subdirectory of root except testdata and
// hidden ones.
func dirs(root string) []string {
	if !*recursive {
		return []string{root}
	}
	var list []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		name := d.Name()
		if path != root && (name == "testdata" || strings.HasPrefix(name, ".")) {
			return filepath.SkipDir
		}
		list = append(list, path)
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		failed = true
	}
	return list
}

// analyse returns the statistics of the non-test Go files of dir, or nil if it
// has none.
func analyse(dir string) *stats {
	fset := token.NewFileSet()
	files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
	s := &stats{dir: dir}
	parsed := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.ParseComments)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			failed = true
			continue
		}
		parsed++
		s.lines += fset.File(af.Pos()).LineCount()
		base := filepath.Base(f)
		for _, d := range af.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Body == nil {
					continue
				}
				name := d.Name.Name
				if d.Recv != nil && len(d.Recv.List) > 0 {
					name = recvName(d.Recv.List[0].Type) + "." + name
				}
				start := fset.Position(d.Pos()).Line
				end := fset.Position(d.End()).Line
				s.fns = append(s.fns, fn{name, base, start, end - start + 1, cyclomatic(d.Body)})
			case *ast.GenDecl:
				s.addGenDecl(fset, base, d)
			}
		}
	}
	if parsed == 0 {
		return nil
	}
	return s
}

// addGenDecl records the structs and the mutexes declared by d.
func (s *stats) addGenDecl(fset *token.FileSet, base string, d *ast.GenDecl) {
	for _, spec := range d.Specs {
		switch sp := spec.(type) {
		case *ast.ValueSpec:
			if isMutex(sp.Type) {
				for _, n := range sp.Names {
					s.mutexes = append(s.mutexes, mutex{n.Name, base, fset.Position(n.Pos()).Line})
				}
			}
		case *ast.TypeSpec:
			st, ok := sp.Type.(*ast.StructType)
			if !ok {
				continue
			}
			si := structInfo{name: sp.Name.Name, file: base}
			for _, fl := range st.Fields.List {
				for _, n := range fl.Names {
					si.fields = append(si.fields, n.Name)
				}
				if len(fl.Names) == 0 {
					si.fields = append(si.fields, "(embedded)"+types(fl.Type))
				}
				if isMutex(fl.Type) {
					s.mutexes = append(s.mutexes, mutex{sp.Name.Name, base, fset.Position(fl.Pos()).Line})
				}
			}
			s.structs = append(s.structs, si)
		}
	}
}

// cyclomatic returns 1 plus the number of branch points in body.
func cyclomatic(body *ast.BlockStmt) int {
	c := 1
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.CaseClause, *ast.CommClause:
			c++
		case *ast.BinaryExpr:
			if n.Op == token.LAND || n.Op == token.LOR {
				c++
			}
		}
		return true
	})
	return c
}

// report prints the statistics of one directory.
func report(s *stats) {
	fmt.Printf("==== %s: %d non-test lines, %d functions, %d structs, %d mutexes\n",
		s.dir, s.lines, len(s.fns), len(s.structs), len(s.mutexes))
	over80, over150, cyclo15, cyclo30 := 0, 0, 0, 0
	for _, f := range s.fns {
		if f.lines > 80 {
			over80++
		}
		if f.lines > 150 {
			over150++
		}
		if f.cyclo > 15 {
			cyclo15++
		}
		if f.cyclo > 30 {
			cyclo30++
		}
	}
	fmt.Printf("functions >80 lines: %d, >150 lines: %d; cyclomatic >15: %d, >30: %d\n", over80, over150, cyclo15, cyclo30)

	fns := append([]fn(nil), s.fns...)
	sort.SliceStable(fns, func(i, j int) bool { return fns[i].lines > fns[j].lines })
	fmt.Println("-- longest 25 functions (lines, cyclo, file:line, name)")
	for i, f := range fns {
		if i >= 25 {
			break
		}
		fmt.Printf("%5d %4d %s:%d %s\n", f.lines, f.cyclo, f.file, f.line, f.name)
	}
	sort.SliceStable(fns, func(i, j int) bool { return fns[i].cyclo > fns[j].cyclo })
	fmt.Println("-- most complex 15 functions (cyclo, lines, file:line, name)")
	for i, f := range fns {
		if i >= 15 {
			break
		}
		fmt.Printf("%5d %4d %s:%d %s\n", f.cyclo, f.lines, f.file, f.line, f.name)
	}

	count := map[string]int{}
	where := map[string][]string{}
	for _, st := range s.structs {
		seen := map[string]bool{}
		for _, f := range st.fields {
			if seen[f] {
				continue
			}
			seen[f] = true
			count[f]++
			where[f] = append(where[f], st.name)
		}
	}
	type fc struct {
		f string
		n int
	}
	var fcs []fc
	for f, n := range count {
		if n >= 3 {
			fcs = append(fcs, fc{f, n})
		}
	}
	sort.Slice(fcs, func(i, j int) bool {
		if fcs[i].n != fcs[j].n {
			return fcs[i].n > fcs[j].n
		}
		return fcs[i].f < fcs[j].f
	})
	fmt.Println("-- field names appearing in >=3 structs (count, name: structs)")
	for _, x := range fcs {
		fmt.Printf("%3d %-14s %s\n", x.n, x.f, strings.Join(where[x.f], ","))
	}

	structs := append([]structInfo(nil), s.structs...)
	sort.SliceStable(structs, func(i, j int) bool { return len(structs[i].fields) > len(structs[j].fields) })
	fmt.Println("-- structs with >= 10 fields (fields, name, file)")
	for _, st := range structs {
		if len(st.fields) >= 10 {
			fmt.Printf("%3d %-24s %s\n", len(st.fields), st.name, st.file)
		}
	}
	fmt.Println()
}

// summary prints the totals over all directories against the limits and
// returns whether a limit is exceeded.
func summary(all []*stats) bool {
	lines, cyclo15, cyclo30, cyclo30Kept := 0, 0, 0, 0
	var mutexes []string
	var access []string
	var over30 []string
	for _, s := range all {
		lines += s.lines
		for _, f := range s.fns {
			if f.cyclo > 15 {
				cyclo15++
			}
			if f.cyclo > 30 {
				if keep[f.file] {
					cyclo30Kept++
					continue
				}
				cyclo30++
				over30 = append(over30, fmt.Sprintf("%s/%s:%d %s (%d)", s.dir, f.file, f.line, f.name, f.cyclo))
			}
		}
		for _, m := range s.mutexes {
			mutexes = append(mutexes, fmt.Sprintf("%s/%s:%d %s", s.dir, m.file, m.line, m.owner))
		}
		for _, st := range s.structs {
			if hasAccessField(st) {
				access = append(access, st.name)
			}
		}
	}

	exceeded := false
	check := func(what string, value, limit, none int) {
		verdict := "no limit"
		if limit != none {
			verdict = fmt.Sprintf("limit %d: ok", limit)
			if value > limit {
				verdict = fmt.Sprintf("limit %d: EXCEEDED", limit)
				exceeded = true
			}
		}
		fmt.Printf("%-58s %6d  (%s)\n", what, value, verdict)
	}

	fmt.Printf("==== summary of %d directories\n", len(all))
	check("non-test lines", lines, *maxLines, 0)
	check("functions over cyclomatic 15", cyclo15, *maxCyclo15, -1)
	check(fmt.Sprintf("functions over cyclomatic 30 (%d more in -keep files)", cyclo30Kept), cyclo30, *maxCyclo30, -1)
	for _, f := range over30 {
		fmt.Printf("    %s\n", f)
	}
	check("mutexes", len(mutexes), *maxMutexes, -1)
	for _, m := range mutexes {
		fmt.Printf("    %s\n", m)
	}
	check("structs with "+strings.Join(accessFields, "/")+" fields", len(access), *maxAccess, -1)
	if len(access) > 0 {
		fmt.Printf("    %s\n", strings.Join(access, ","))
	}
	return exceeded
}

// hasAccessField returns whether st has one of the accessFields.
func hasAccessField(st structInfo) bool {
	for _, f := range st.fields {
		for _, a := range accessFields {
			if f == a {
				return true
			}
		}
	}
	return false
}

// isMutex returns whether e is sync.Mutex or sync.RWMutex, or a pointer to one.
func isMutex(e ast.Expr) bool {
	if st, ok := e.(*ast.StarExpr); ok {
		e = st.X
	}
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "sync" {
		return false
	}
	return sel.Sel.Name == "Mutex" || sel.Sel.Name == "RWMutex"
}

// recvName returns the type name of a method receiver expression.
func recvName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return recvName(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		return recvName(t.X)
	case *ast.IndexListExpr:
		return recvName(t.X)
	}
	return "?"
}

// types returns a short printable form of a type expression.
func types(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return "*" + types(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return types(t.X) + "." + t.Sel.Name
	}
	return "?"
}
