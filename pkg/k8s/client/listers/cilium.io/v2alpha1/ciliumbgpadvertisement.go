// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by lister-gen. DO NOT EDIT.

package v2alpha1

import (
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// CiliumBGPAdvertisementLister helps list CiliumBGPAdvertisements.
// All objects returned here must be treated as read-only.
type CiliumBGPAdvertisementLister interface {
	// List lists all CiliumBGPAdvertisements in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v2alpha1.CiliumBGPAdvertisement, err error)
	// Get retrieves the CiliumBGPAdvertisement from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v2alpha1.CiliumBGPAdvertisement, error)
	CiliumBGPAdvertisementListerExpansion
}

// ciliumBGPAdvertisementLister implements the CiliumBGPAdvertisementLister interface.
type ciliumBGPAdvertisementLister struct {
	indexer cache.Indexer
}

// NewCiliumBGPAdvertisementLister returns a new CiliumBGPAdvertisementLister.
func NewCiliumBGPAdvertisementLister(indexer cache.Indexer) CiliumBGPAdvertisementLister {
	return &ciliumBGPAdvertisementLister{indexer: indexer}
}

// List lists all CiliumBGPAdvertisements in the indexer.
func (s *ciliumBGPAdvertisementLister) List(selector labels.Selector) (ret []*v2alpha1.CiliumBGPAdvertisement, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v2alpha1.CiliumBGPAdvertisement))
	})
	return ret, err
}

// Get retrieves the CiliumBGPAdvertisement from the index for a given name.
func (s *ciliumBGPAdvertisementLister) Get(name string) (*v2alpha1.CiliumBGPAdvertisement, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v2alpha1.Resource("ciliumbgpadvertisement"), name)
	}
	return obj.(*v2alpha1.CiliumBGPAdvertisement), nil
}
