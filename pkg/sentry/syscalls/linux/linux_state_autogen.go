// automatically generated by stateify.

package linux

import (
	"gvisor.dev/gvisor/pkg/state"
)

func (x *futexWaitRestartBlock) StateTypeName() string {
	return "pkg/sentry/syscalls/linux.futexWaitRestartBlock"
}

func (x *futexWaitRestartBlock) StateFields() []string {
	return []string{
		"duration",
		"addr",
		"private",
		"val",
		"mask",
	}
}

func (x *futexWaitRestartBlock) beforeSave() {}

func (x *futexWaitRestartBlock) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.duration)
	m.Save(1, &x.addr)
	m.Save(2, &x.private)
	m.Save(3, &x.val)
	m.Save(4, &x.mask)
}

func (x *futexWaitRestartBlock) afterLoad() {}

func (x *futexWaitRestartBlock) StateLoad(m state.Source) {
	m.Load(0, &x.duration)
	m.Load(1, &x.addr)
	m.Load(2, &x.private)
	m.Load(3, &x.val)
	m.Load(4, &x.mask)
}

func (x *pollRestartBlock) StateTypeName() string {
	return "pkg/sentry/syscalls/linux.pollRestartBlock"
}

func (x *pollRestartBlock) StateFields() []string {
	return []string{
		"pfdAddr",
		"nfds",
		"timeout",
	}
}

func (x *pollRestartBlock) beforeSave() {}

func (x *pollRestartBlock) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.pfdAddr)
	m.Save(1, &x.nfds)
	m.Save(2, &x.timeout)
}

func (x *pollRestartBlock) afterLoad() {}

func (x *pollRestartBlock) StateLoad(m state.Source) {
	m.Load(0, &x.pfdAddr)
	m.Load(1, &x.nfds)
	m.Load(2, &x.timeout)
}

func (x *clockNanosleepRestartBlock) StateTypeName() string {
	return "pkg/sentry/syscalls/linux.clockNanosleepRestartBlock"
}

func (x *clockNanosleepRestartBlock) StateFields() []string {
	return []string{
		"c",
		"duration",
		"rem",
	}
}

func (x *clockNanosleepRestartBlock) beforeSave() {}

func (x *clockNanosleepRestartBlock) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.c)
	m.Save(1, &x.duration)
	m.Save(2, &x.rem)
}

func (x *clockNanosleepRestartBlock) afterLoad() {}

func (x *clockNanosleepRestartBlock) StateLoad(m state.Source) {
	m.Load(0, &x.c)
	m.Load(1, &x.duration)
	m.Load(2, &x.rem)
}

func init() {
	state.Register((*futexWaitRestartBlock)(nil))
	state.Register((*pollRestartBlock)(nil))
	state.Register((*clockNanosleepRestartBlock)(nil))
}
