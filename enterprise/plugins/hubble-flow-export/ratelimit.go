// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package export

import (
	"sync/atomic"
	"time"

	nodeTypes "github.com/cilium/cilium/pkg/node/types"

	"golang.org/x/time/rate"
)

type rateLimiter struct {
	*rate.Limiter
	done           chan struct{}
	stopped        chan struct{}
	reportInterval time.Duration
	dropped        uint64 // accessed atomically
	nodeName       string
}

// getLimit converts an numEvents and interval to rate.Limit which is a floating point value
// representing number of events per second.
func getLimit(numEvents int, interval time.Duration) rate.Limit {
	if numEvents == 0 {
		return 0
	}
	return rate.Every(interval / time.Duration(numEvents))
}

// newRateLimiter returns a rate limiter that allows numEvents per interval.
func newRateLimiter(interval time.Duration, numEvents int, s *export) *rateLimiter {
	if numEvents < 0 {
		return nil
	}
	r := &rateLimiter{
		Limiter:        rate.NewLimiter(getLimit(numEvents, interval), numEvents),
		done:           make(chan struct{}),
		stopped:        make(chan struct{}),
		reportInterval: interval, // TODO(tk): use a separate interval for reporting?
		dropped:        0,
		nodeName:       nodeTypes.GetName(), // TODO(tk): use nodeTypes.GetAbsoluteNodeName() once we switch to Cilium 1.10.
	}
	if s.nodeName != "" {
		// Override node_name with the value specified in --export-node-name flag.
		r.nodeName = s.nodeName
	}
	go r.reportRateLimitInfo(s)
	return r
}

func (r *rateLimiter) stop() {
	if r == nil {
		return
	}
	close(r.done)
	<-r.stopped
}

type RateLimitInfo struct {
	NumberOfDroppedEvents uint64 `json:"number_of_dropped_events"`
}

type RateLimitInfoEvent struct {
	RateLimitInfo *RateLimitInfo `json:"rate_limit_info"`
	NodeName      string         `json:"node_name"`
	Time          time.Time      `json:"time"`
}

func (r *rateLimiter) reportRateLimitInfo(s *export) {
	ticker := time.NewTicker(r.reportInterval)
	for {
		select {
		case <-ticker.C:
			dropped := atomic.SwapUint64(&r.dropped, 0)
			if dropped > 0 {
				err := s.encoder.Encode(&RateLimitInfoEvent{
					RateLimitInfo: &RateLimitInfo{NumberOfDroppedEvents: dropped},
					NodeName:      r.nodeName,
					Time:          time.Now(),
				})
				if err != nil {
					s.logger.WithError(err).
						WithField("dropped", dropped).
						Warn("Failed to encode rate_limit_info event")
				}
			}
		case <-r.done:
			close(r.stopped)
			return
		}
	}
}
