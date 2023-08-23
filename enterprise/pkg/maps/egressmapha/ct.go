// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressmapha

import (
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/types"

	ciliumebpf "github.com/cilium/ebpf"
)

const (
	CtMapName    = "cilium_egress_gw_ha_ct_v4"
	MaxCtEntries = 1 << 18
)

// EgressCtKey4 is the key of an egress CT map.
type EgressCtKey4 struct {
	tuple.TupleKey4
}

// EgressCtVal is the value of an egress CT map.
type EgressCtVal4 struct {
	Gateway types.IPv4
}

type CtMap interface {
	Lookup(*EgressCtKey4, *EgressCtVal4) error
	Update(*EgressCtKey4, *EgressCtVal4, ciliumebpf.MapUpdateFlags) error
	Delete(k *EgressCtKey4) error
	IterateWithCallback(cb EgressCtIterateCallback) error
}

// ctMap is the internal representation of an egress CT map.
type ctMap struct {
	*ebpf.Map
}

func createCtMapFromDaemonConfig(in struct {
	cell.In

	Lifecycle hive.Lifecycle
	*option.DaemonConfig
}) (out struct {
	cell.Out

	bpf.MapOut[CtMap]
	defines.NodeOut
}) {
	out.NodeDefines = map[string]string{
		"EGRESS_GW_HA_CT_MAP":      CtMapName,
		"EGRESS_GW_HA_CT_MAP_SIZE": fmt.Sprint(MaxCtEntries),
	}

	if !in.EgressGatewayHAEnabled() {
		return
	}

	out.MapOut = bpf.NewMapOut(CtMap(createCtMap(in.Lifecycle, ebpf.PinByName)))
	return
}

// CreatePrivateCtMap creates an unpinned CT map.
//
// Useful for testing.
func CreatePrivateCtMap(lc hive.Lifecycle) CtMap {
	return createCtMap(lc, ebpf.PinNone)
}

func createCtMap(lc hive.Lifecycle, pinning ebpf.PinType) *ctMap {
	m := ebpf.NewMap(&ebpf.MapSpec{
		Name:       CtMapName,
		Type:       ciliumebpf.LRUHash,
		KeySize:    uint32(unsafe.Sizeof(EgressCtKey4{})),
		ValueSize:  uint32(unsafe.Sizeof(EgressCtVal4{})),
		MaxEntries: uint32(MaxCtEntries),
		Pinning:    pinning,
	})

	lc.Append(hive.Hook{
		OnStart: func(hive.HookContext) error {
			return m.OpenOrCreate()
		},
		OnStop: func(hive.HookContext) error {
			return m.Close()
		},
	})

	return &ctMap{m}
}

func OpenPinnedCtMap() (CtMap, error) {
	m, err := ebpf.LoadRegisterMap(CtMapName)
	if err != nil {
		return nil, err
	}

	return &ctMap{m}, nil
}

// RemoveEntry removes an entry from the CT map.
func (m *ctMap) Delete(k *EgressCtKey4) error {
	return m.Map.Delete(k)
}

func (m *ctMap) Lookup(k *EgressCtKey4, v *EgressCtVal4) error {
	return m.Map.Lookup(k, v)
}

func (m *ctMap) Update(k *EgressCtKey4, v *EgressCtVal4, flags ciliumebpf.MapUpdateFlags) error {
	return m.Map.Update(k, v, flags)
}

// EgressCtIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of an egress CT map.
type EgressCtIterateCallback func(*EgressCtKey4, *EgressCtVal4)

// IterateWithCallback iterates through all the keys/values of an egress CT map,
// passing each key/value pair to the cb callback.
func (m *ctMap) IterateWithCallback(cb EgressCtIterateCallback) error {
	return m.Map.IterateWithCallback(&EgressCtKey4{}, &EgressCtVal4{},
		func(k, v interface{}) {
			key := k.(*EgressCtKey4)
			value := v.(*EgressCtVal4)

			cb(key, value)
		})
}
