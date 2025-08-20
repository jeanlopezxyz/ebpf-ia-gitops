package main

import (
	"fmt"
	
	"github.com/cilium/ebpf"
)

// This file provides stub implementations when eBPF is not available
// It will be overridden by generated files when bpf2go succeeds

type networkObjects struct {
	NetworkMonitor   *ebpf.Program
	Events          *ebpf.Map
	PortUniqueCount *ebpf.Map
}

func (o *networkObjects) Close() error {
	if o.NetworkMonitor != nil {
		o.NetworkMonitor.Close()
	}
	if o.Events != nil {
		o.Events.Close()
	}
	if o.PortUniqueCount != nil {
		o.PortUniqueCount.Close()
	}
	return nil
}

func loadNetworkObjects(obj *networkObjects, opts *ebpf.CollectionOptions) error {
	return fmt.Errorf("eBPF not available - bpf2go generation failed or kernel doesn't support eBPF")
}