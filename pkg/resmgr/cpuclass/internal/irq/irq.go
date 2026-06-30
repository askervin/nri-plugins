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

// Package irq provides the IRQ affinity mask writer used by the
// cpuclass handler. It masks CPUs from all IRQs by clearing the
// corresponding bits in the smp_affinity files of all interrupts.
package irq

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	logger "github.com/containers/nri-plugins/pkg/log"
)

var log = logger.NewLogger("cpuclass")

// hooks lets tests intercept the IRQ mask operations without
// touching real sysfs. Production use leaves all hooks nil; the
// writer then talks to the platform via /proc/irq sysfs.
type hooks struct {
	// readAffinity reads the current affinity mask for an IRQ
	readAffinity func(irq int) (string, error)
	// writeAffinity writes the affinity mask for an IRQ
	writeAffinity func(irq int, mask string) error
}

// Writer enforces per-class IRQ CPU masks by clearing bits for
// target CPUs in all interrupt's smp_affinity files.
type Writer struct {
	lastWritten map[string]string
	hooks       hooks
}

// NewWriter returns a Writer wired to the given hooks. Pass a
// zero-valued hooks to use real sysfs.
func NewWriter() *Writer {
	return &Writer{
		lastWritten: map[string]string{},
	}
}

// EnforceIRQMask masks the given CPUs from all IRQs by clearing
// their bits in the smp_affinity mask. If disable is true, CPUs
// are masked (their bits cleared). If disable is false, CPUs are
// unmasked (restored to default). Returns the first error
// encountered.
func (w *Writer) EnforceIRQMask(className string, disable bool, cpus []int) error {
	if len(cpus) == 0 {
		return nil
	}

	irqs, err := enumerateIRQs()
	if err != nil {
		return fmt.Errorf("failed to enumerate IRQs: %w", err)
	}

	var firstErr error
	for _, irq := range irqs {
		mask, err := w.readAffinityOrRead(irq)
		if err != nil {
			log.Debugf("irq: failed to read affinity for IRQ %d: %v", irq, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		newMask, err := applyCPUmask(mask, cpus, disable)
		if err != nil {
			log.Debugf("irq: failed to apply mask for IRQ %d: %v", irq, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		key := fmt.Sprintf("irq%d", irq)
		if newMask == w.lastWritten[key] {
			log.Debugf("irq: skip writing same mask for IRQ %d", irq)
			continue
		}

		if err := w.writeAffinityOrWrite(irq, newMask); err != nil {
			log.Debugf("irq: failed to write affinity for IRQ %d: %v", irq, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		w.lastWritten[key] = newMask
		log.Debugf("irq: class %q on cpus %v: IRQ %d mask updated to %s (disable=%v)", className, cpus, irq, newMask, disable)
	}

	return firstErr
}

// Reset clears the cached last-written values, forcing a full
// write on next EnforceIRQMask call.
func (w *Writer) Reset() {
	w.lastWritten = map[string]string{}
}

// readAffinityOrRead reads the current affinity mask for an IRQ,
// using hooks if set, otherwise reading from /proc/irq.
func (w *Writer) readAffinityOrRead(irq int) (string, error) {
	if w.hooks.readAffinity != nil {
		return w.hooks.readAffinity(irq)
	}
	return readAffinity(irq)
}

// writeAffinityOrWrite writes the affinity mask for an IRQ,
// using hooks if set, otherwise writing to /proc/irq.
func (w *Writer) writeAffinityOrWrite(irq int, mask string) error {
	if w.hooks.writeAffinity != nil {
		return w.hooks.writeAffinity(irq, mask)
	}
	return writeAffinity(irq, mask)
}

// enumerateIRQs returns a list of all IRQ numbers by parsing
// /proc/interrupts.
func enumerateIRQs() ([]int, error) {
	file, err := os.Open("/proc/interrupts")
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc/interrupts: %w", err)
	}
	defer file.Close()

	var irqs []int
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// First field is IRQ number followed by colon
		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}

		irqStr := strings.TrimSpace(parts[0])
		irq, err := strconv.Atoi(irqStr)
		if err != nil {
			continue
		}

		irqs = append(irqs, irq)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan /proc/interrupts: %w", err)
	}

	return irqs, nil
}

// readAffinity reads the current affinity mask for an IRQ from
// /proc/irq/<irq>/smp_affinity.
func readAffinity(irq int) (string, error) {
	path := filepath.Join("/proc/irq", strconv.Itoa(irq), "smp_affinity")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read %s: %w", path, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// writeAffinity writes the affinity mask for an IRQ to
// /proc/irq/<irq>/smp_affinity.
func writeAffinity(irq int, mask string) error {
	path := filepath.Join("/proc/irq", strconv.Itoa(irq), "smp_affinity")
	if err := os.WriteFile(path, []byte(mask), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	return nil
}

// applyCPUmask modifies the given mask to clear or set bits for
// the specified CPUs. If disable is true, CPU bits are cleared.
// If disable is false, CPU bits are set (restored to default).
func applyCPUmask(mask string, cpus []int, disable bool) (string, error) {
	// Parse the existing mask (hexadecimal format)
	baseMask, err := parseMask(mask)
	if err != nil {
		return "", fmt.Errorf("failed to parse mask %q: %w", mask, err)
	}

	// Create CPU mask
	cpusMask := make([]byte, len(baseMask))
	for _, cpu := range cpus {
		if cpu < 0 || cpu >= len(baseMask)*8 {
			continue
		}
		byteIdx := cpu / 8
		bitIdx := cpu % 8
		if disable {
			// Clear the bit for this CPU
			cpusMask[byteIdx] &= ^(1 << bitIdx)
		} else {
			// Set the bit for this CPU
			cpusMask[byteIdx] |= 1 << bitIdx
		}
	}

	// Apply the mask
	result := make([]byte, len(baseMask))
	if disable {
		// Clear CPU bits from the mask
		for i := range result {
			result[i] = baseMask[i] & cpusMask[i]
		}
	} else {
		// Set CPU bits in the mask
		for i := range result {
			result[i] = baseMask[i] | ^cpusMask[i]
		}
	}

	return formatMask(result), nil
}

// parseMask parses a hexadecimal affinity mask string into a byte
// slice.
func parseMask(mask string) ([]byte, error) {
	// Remove 0x prefix if present
	mask = strings.TrimPrefix(mask, "0x")
	mask = strings.TrimPrefix(mask, "0X")

	// Pad to even length
	if len(mask)%2 == 1 {
		mask = "0" + mask
	}

	bytes, err := hexDecode(mask)
	if err != nil {
		return nil, err
	}

	// Reverse to match CPU bit order (little-endian)
	for i, j := 0, len(bytes)-1; i < j; i, j = i+1, j-1 {
		bytes[i], bytes[j] = bytes[j], bytes[i]
	}

	return bytes, nil
}

// formatMask converts a byte slice to a hexadecimal string.
func formatMask(bytes []byte) string {
	// Reverse to match CPU bit order
	for i, j := 0, len(bytes)-1; i < j; i, j = i+1, j-1 {
		bytes[i], bytes[j] = bytes[j], bytes[i]
	}

	hex := hexEncode(bytes)
	// Remove leading zeros
	hex = strings.TrimLeft(hex, "0")
	if hex == "" {
		hex = "0"
	}
	return "0x" + hex
}

// hexDecode decodes a hex string to bytes.
func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		s = "0" + s
	}
	bytes := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		var val byte
		for j := 0; j < 2; j++ {
			c := s[i+j]
			switch {
			case c >= '0' && c <= '9':
				val = (val << 4) | (c - '0')
			case c >= 'a' && c <= 'f':
				val = (val << 4) | (c - 'a' + 10)
			case c >= 'A' && c <= 'F':
				val = (val << 4) | (c - 'A' + 10)
			default:
				return nil, fmt.Errorf("invalid hex character: %c", c)
			}
		}
		bytes[i/2] = val
	}
	return bytes, nil
}

// hexEncode encodes bytes to a hex string.
func hexEncode(bytes []byte) string {
	hex := "0123456789abcdef"
	result := make([]byte, 0, len(bytes)*2)
	for _, b := range bytes {
		result = append(result, hex[b>>4], hex[b&0xF])
	}
	return string(result)
}

// Hooks exposes the hooks for testing.
type Hooks struct {
	// ReadAffinity reads the current affinity mask for an IRQ
	ReadAffinity func(irq int) (string, error)
	// WriteAffinity writes the affinity mask for an IRQ
	WriteAffinity func(irq int, mask string) error
}

// SetHooks sets the hooks for testing.
func (w *Writer) SetHooks(h Hooks) {
	w.hooks.readAffinity = h.ReadAffinity
	w.hooks.writeAffinity = h.WriteAffinity
}
