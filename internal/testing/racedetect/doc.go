// Package racedetect reports whether the binary was built with the Go race
// detector enabled.
//
// Tests use it to skip or widen wall-clock assertions. Race instrumentation
// adds several times the normal execution cost, so a latency bound calibrated
// without it measures the instrumentation rather than the code under test and
// fails on a loaded machine such as a shared CI runner. See GOTCHAS.md §1.2.
package racedetect
