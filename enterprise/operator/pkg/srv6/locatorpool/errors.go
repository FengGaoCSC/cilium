//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package locatorpool

import "fmt"

var (
	// ErrLocatorPoolExhausted is returned when the pool capacity is exceeded
	ErrLocatorPoolExhausted = fmt.Errorf("pool exhausted")

	// ErrLocatorAllocation is returned when the allocation fails
	ErrLocatorAllocation = fmt.Errorf("locator allocation failed")

	// ErrInvalidPrefix is returned when the prefix is not valid
	ErrInvalidPrefix = fmt.Errorf("invalid prefix")

	// ErrInvalidLocator is returned when the given locator does not match the pool
	ErrInvalidLocator = fmt.Errorf("invalid locator")

	// ErrInvalidPrefixAndSIDStruct is returned when the prefix and SID structure are not valid
	ErrInvalidPrefixAndSIDStruct = fmt.Errorf("invalid prefix and SID structure combination")

	// ErrInvalidBehaviorType is returned when the behavior type is not valid
	ErrInvalidBehaviorType = fmt.Errorf("invalid behavior type")

	// ErrInvalidSID is returned when the SID is not valid
	ErrInvalidSID = fmt.Errorf("invalid SID")

	// ErrOverlappingPrefix is returned when the prefix is overlapping with another prefix
	ErrOverlappingPrefix = fmt.Errorf("prefix overlapping with existing pool")

	// ErrPrefixNotByteAligned is returned when the prefix is not byte aligned
	ErrPrefixNotByteAligned = fmt.Errorf("not byte aligned")
)
