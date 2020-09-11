// automatically generated by stateify.

package signalfd

import (
	"gvisor.dev/gvisor/pkg/state"
)

func (x *SignalOperations) StateTypeName() string {
	return "pkg/sentry/kernel/signalfd.SignalOperations"
}

func (x *SignalOperations) StateFields() []string {
	return []string{
		"target",
		"mask",
	}
}

func (x *SignalOperations) beforeSave() {}

func (x *SignalOperations) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.target)
	m.Save(1, &x.mask)
}

func (x *SignalOperations) afterLoad() {}

func (x *SignalOperations) StateLoad(m state.Source) {
	m.Load(0, &x.target)
	m.Load(1, &x.mask)
}

func init() {
	state.Register((*SignalOperations)(nil))
}
